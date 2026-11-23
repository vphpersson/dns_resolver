package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func keyFor(name string) Key {
	return Key{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
}

func answerMsg(name string, ttl uint32) *dns.Msg {
	m := msgWithRcode(name, dns.RcodeSuccess)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   []byte{93, 184, 216, 34},
	}}
	return m
}

func msgWithRcode(name string, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Rcode = rcode
	return m
}

// A transient failure rcode must never be cached: doing so turns a momentary
// upstream/transport hiccup into a sticky outage for the name. This is the
// regression that wedged www.google.com on a cached SERVFAIL.
func TestSet_DoesNotCacheFailureRcodes(t *testing.T) {
	t.Parallel()

	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotImplemented} {
		c := New()
		key := keyFor("www.google.com.")
		if c.Set(key, msgWithRcode("www.google.com.", rcode), nil) {
			t.Fatalf("Set cached an rcode %d (%s) response; want it rejected", rcode, dns.RcodeToString[rcode])
		}
		if _, ok, _ := c.Get(key); ok {
			t.Fatalf("rcode %d (%s) response was retrievable from cache", rcode, dns.RcodeToString[rcode])
		}
	}
}

func TestSet_CachesPositiveAnswer(t *testing.T) {
	t.Parallel()

	c := New()
	key := keyFor("example.com.")

	m := msgWithRcode("example.com.", dns.RcodeSuccess)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{93, 184, 216, 34},
	}}

	if !c.Set(key, m, nil) {
		t.Fatal("Set rejected a NOERROR answer; want it cached")
	}
	_, ok, remaining := c.Get(key)
	if !ok {
		t.Fatal("NOERROR answer not retrievable from cache")
	}
	if remaining <= 0 || remaining > 60*time.Second {
		t.Fatalf("remaining TTL = %s; want (0, 60s]", remaining)
	}
}

func soa(zone string, ttl uint32, minimum uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:    dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:     "ns." + zone,
		Mbox:   "hostmaster." + zone,
		Minttl: minimum,
	}
}

// A negative answer is cached for as long as its SOA allows, and one without an
// SOA is not cached at all: it used to take the 24h cap, so an upstream's
// empty answer to a query it did not recurse for stuck for a day.
func TestSet_NegativeAnswers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		message    func() *dns.Msg
		wantCached bool
		wantMaxTtl time.Duration
	}{
		{
			name:    "nxdomain without soa",
			message: func() *dns.Msg { return msgWithRcode("nope.example.", dns.RcodeNameError) },
		},
		{
			name:    "nodata without soa",
			message: func() *dns.Msg { return msgWithRcode("nope.example.", dns.RcodeSuccess) },
		},
		{
			name: "nxdomain with soa",
			message: func() *dns.Msg {
				m := msgWithRcode("nope.example.", dns.RcodeNameError)
				m.Ns = []dns.RR{soa("example.", 300, 60)}
				return m
			},
			wantCached: true,
			wantMaxTtl: 60 * time.Second,
		},
		{
			name: "nodata with soa",
			message: func() *dns.Msg {
				m := msgWithRcode("nope.example.", dns.RcodeSuccess)
				m.Ns = []dns.RR{soa("example.", 120, 3600)}
				return m
			},
			wantCached: true,
			wantMaxTtl: 120 * time.Second,
		},
		{
			name:       "answer with an unbounded ttl",
			message:    func() *dns.Msg { return answerMsg("forever.example.", ^uint32(0)) },
			wantCached: true,
			wantMaxTtl: maxCacheTtl,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			c := New()
			key := keyFor("nope.example.")

			if got := c.Set(key, testCase.message(), nil); got != testCase.wantCached {
				t.Fatalf("Set = %t; want %t", got, testCase.wantCached)
			}
			_, ok, remaining := c.Get(key)
			if ok != testCase.wantCached {
				t.Fatalf("Get found = %t; want %t", ok, testCase.wantCached)
			}
			if ok && (remaining <= 0 || remaining > testCase.wantMaxTtl) {
				t.Fatalf("remaining TTL = %s; want (0, %s]", remaining, testCase.wantMaxTtl)
			}
		})
	}
}

func TestFlush(t *testing.T) {
	t.Parallel()

	c := New()
	c.Set(keyFor("a.example."), answerMsg("a.example.", 60), nil)
	c.Set(keyFor("b.example."), answerMsg("b.example.", 60), nil)

	if got := c.Flush(); got != 2 {
		t.Fatalf("Flush() = %d; want 2", got)
	}
	if s := c.Stats(); s.Entries != 0 {
		t.Fatalf("entries after flush = %d; want 0", s.Entries)
	}
}

// DeleteName must remove every variant of one name (here A + AAAA) without
// touching other names — the targeted "unpoison" control.
func TestDeleteName(t *testing.T) {
	t.Parallel()

	c := New()
	a := answerMsg("www.google.com.", 60)
	aaaa := answerMsg("www.google.com.", 60)
	c.Set(Key{Name: "www.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, a, nil)
	c.Set(Key{Name: "www.google.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}, aaaa, nil)
	c.Set(keyFor("google.com."), answerMsg("google.com.", 60), nil)

	// Callers may pass the bare (non-FQDN) name; it must still match.
	if got := c.DeleteName("www.google.com"); got != 2 {
		t.Fatalf("DeleteName = %d; want 2", got)
	}
	if _, ok, _ := c.Get(keyFor("google.com.")); !ok {
		t.Fatal("DeleteName removed an unrelated name")
	}
	if s := c.Stats(); s.Entries != 1 {
		t.Fatalf("entries after DeleteName = %d; want 1", s.Entries)
	}
}

func TestStats_HitsAndMisses(t *testing.T) {
	t.Parallel()

	c := New()
	c.Set(keyFor("a.example."), answerMsg("a.example.", 60), nil)

	c.Get(keyFor("a.example.")) // hit
	c.Get(keyFor("a.example.")) // hit
	c.Get(keyFor("absent."))    // miss

	s := c.Stats()
	if s.Hits != 2 || s.Misses != 1 {
		t.Fatalf("hits=%d misses=%d; want hits=2 misses=1", s.Hits, s.Misses)
	}
	if s.Insertions != 1 {
		t.Fatalf("insertions=%d; want 1", s.Insertions)
	}
}

func TestStats_RejectionCounted(t *testing.T) {
	t.Parallel()

	c := New()
	if c.Set(keyFor("x."), msgWithRcode("x.", dns.RcodeServerFailure), nil) {
		t.Fatal("SERVFAIL should not be cached")
	}
	if s := c.Stats(); s.Rejections != 1 {
		t.Fatalf("rejections=%d; want 1", s.Rejections)
	}
}
