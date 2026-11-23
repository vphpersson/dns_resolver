package cache

import (
	"fmt"
	"strings"
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
			// The root zone's SOA: a random name under a missing TLD would
			// otherwise be kept for a day.
			name: "nxdomain with a day-long soa",
			message: func() *dns.Msg {
				m := msgWithRcode("nope.", dns.RcodeNameError)
				m.Ns = []dns.RR{soa(".", 86400, 86400)}
				return m
			},
			wantCached: true,
			wantMaxTtl: maxNegativeTtl,
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

func txtMsg(name string, size int) *dns.Msg {
	m := msgWithRcode(name, dns.RcodeSuccess)
	m.Question[0].Qtype = dns.TypeTXT
	var strs []string
	for remaining := size; remaining > 0; remaining -= 255 {
		strs = append(strs, strings.Repeat("x", min(remaining, 255)))
	}
	m.Answer = []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: strs,
	}}
	return m
}

func names(count int) []string {
	out := make([]string, count)
	for i := range out {
		out[i] = fmt.Sprintf("n%d.example.", i)
	}
	return out
}

// The cache holds a bounded number of answers and bytes, evicting the least
// recently used. It used to grow without bound, the janitor removing only what
// had expired: random names under a missing TLD lived for a day each, and
// large TXT answers pinned memory.
func TestSet_Bounded(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		// options make the cache; insert fills it; wantPresent and
		// wantAbsent are looked up afterwards.
		options     []Option
		insert      func(c *Cache)
		wantPresent []string
		wantAbsent  []string
		check       func(t *testing.T, c *Cache)
	}{
		{
			name:    "entry bound",
			options: []Option{WithMaxEntries(3)},
			insert: func(c *Cache) {
				for _, name := range names(5) {
					c.Set(keyFor(name), answerMsg(name, 60), nil)
				}
			},
			wantPresent: []string{"n2.example.", "n3.example.", "n4.example."},
			wantAbsent:  []string{"n0.example.", "n1.example."},
		},
		{
			name:    "least recently used goes first",
			options: []Option{WithMaxEntries(3)},
			insert: func(c *Cache) {
				for _, name := range names(3) {
					c.Set(keyFor(name), answerMsg(name, 60), nil)
				}
				c.Get(keyFor("n0.example."))
				c.Set(keyFor("n3.example."), answerMsg("n3.example.", 60), nil)
			},
			wantPresent: []string{"n0.example.", "n2.example.", "n3.example."},
			wantAbsent:  []string{"n1.example."},
		},
		{
			name:    "byte bound",
			options: []Option{WithMaxBytes(10_000)},
			insert: func(c *Cache) {
				for _, name := range names(10) {
					c.Set(keyFor(name), txtMsg(name, 3000), nil)
				}
			},
			wantPresent: []string{"n9.example."},
			wantAbsent:  []string{"n0.example."},
			check: func(t *testing.T, c *Cache) {
				t.Helper()
				if stats := c.Stats(); stats.Bytes > 10_000 || stats.Entries == 0 {
					t.Fatalf("stats = %+v; want at most 10000 bytes and some entries", stats)
				}
			},
		},
		{
			name:    "answer larger than the cache",
			options: []Option{WithMaxBytes(2_000)},
			insert: func(c *Cache) {
				c.Set(keyFor("small.example."), answerMsg("small.example.", 60), nil)
				c.Set(keyFor("huge.example."), txtMsg("huge.example.", 5000), nil)
			},
			wantPresent: []string{"small.example."},
			wantAbsent:  []string{"huge.example."},
		},
		{
			name:    "replacing an entry",
			options: []Option{WithMaxEntries(2)},
			insert: func(c *Cache) {
				for range 5 {
					c.Set(keyFor("same.example."), answerMsg("same.example.", 60), nil)
				}
				c.Set(keyFor("other.example."), answerMsg("other.example.", 60), nil)
			},
			wantPresent: []string{"same.example.", "other.example."},
			check: func(t *testing.T, c *Cache) {
				t.Helper()
				one := New()
				one.Set(keyFor("same.example."), answerMsg("same.example.", 60), nil)
				one.Set(keyFor("other.example."), answerMsg("other.example.", 60), nil)
				if got, want := c.Stats().Bytes, one.Stats().Bytes; got != want {
					t.Fatalf("bytes = %d after replacing an entry; want %d", got, want)
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			c := New(testCase.options...)
			testCase.insert(c)

			for _, name := range testCase.wantPresent {
				if _, ok, _ := c.Get(keyFor(name)); !ok {
					t.Errorf("%s was evicted; want it kept", name)
				}
			}
			for _, name := range testCase.wantAbsent {
				if _, ok, _ := c.Get(keyFor(name)); ok {
					t.Errorf("%s is cached; want it evicted or rejected", name)
				}
			}
			if testCase.check != nil {
				testCase.check(t, c)
			}
		})
	}
}

// Snapshot lists a bounded number of entries, most recently used first, and
// can be narrowed to one name. It used to build the whole cache's listing
// under the lock.
func TestSnapshot(t *testing.T) {
	t.Parallel()

	c := New()
	for _, name := range names(20) {
		c.Set(keyFor(name), answerMsg(name, 60), nil)
	}
	c.Set(Key{Name: "n3.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}, answerMsg("n3.example.", 60), nil)

	testCases := []struct {
		name      string
		qname     string
		limit     int
		wantNames []string
	}{
		{name: "limit", limit: 3, wantNames: []string{"n3.example.", "n19.example.", "n18.example."}},
		{name: "default limit", wantNames: nil},
		{name: "one name", qname: "N3.example", limit: 10, wantNames: []string{"n3.example.", "n3.example."}},
		{name: "absent name", qname: "absent.example.", limit: 10, wantNames: []string{}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			infos := c.Snapshot(testCase.qname, testCase.limit)
			if testCase.wantNames == nil {
				if len(infos) != 21 {
					t.Fatalf("listed %d entries; want all 21 under the default limit", len(infos))
				}
				return
			}
			got := make([]string, 0, len(infos))
			for _, info := range infos {
				got = append(got, info.Name)
			}
			if strings.Join(got, ",") != strings.Join(testCase.wantNames, ",") {
				t.Fatalf("listed %v; want %v", got, testCase.wantNames)
			}
		})
	}
}
