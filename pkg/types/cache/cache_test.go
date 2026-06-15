package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func keyFor(name string) Key {
	return Key{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
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

// An NXDOMAIN/NODATA with no SOA yields the uint32-max sentinel TTL from
// EffectiveMessageTtl; the cache must cap it rather than pin the name for ~136
// years.
func TestSet_CapsUnboundedTtl(t *testing.T) {
	c := New()
	key := keyFor("nope.example.")

	if !c.Set(key, msgWithRcode("nope.example.", dns.RcodeNameError), nil) {
		t.Fatal("Set rejected an NXDOMAIN response; want it cached (capped)")
	}
	_, ok, remaining := c.Get(key)
	if !ok {
		t.Fatal("NXDOMAIN response not retrievable from cache")
	}
	if remaining > maxCacheTtl {
		t.Fatalf("remaining TTL = %s; want <= %s", remaining, maxCacheTtl)
	}
}
