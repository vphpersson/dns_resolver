package resolver

import (
	"dns_resolver/pkg/types/resolver_config"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// With every forward slot taken, a request that needs the upstream is refused
// at once instead of queueing another goroutine behind the pool, while what
// the cache holds is still answered. Nothing bounded the requests waiting on
// the upstream before: each UDP packet got a goroutine that waited as long as
// the pool made it.
//
//nolint:tparallel // The subtests share the one held slot, so they run in turn.
func TestServeDNS_InFlightLimit(t *testing.T) {
	t.Parallel()

	upstream := startUpstream(t, func(query *dns.Msg) *dns.Msg {
		if query.Question[0].Name == "slow.example." {
			return nil
		}
		return answerWith("192.0.2.1")(query)
	})
	resolver := newTestResolver(
		t,
		upstream,
		resolver_config.WithMaxInFlight(1),
		resolver_config.WithRequestTimeout(2*time.Second),
	)

	if reply := ask(resolver, "udp", newQuery("cached.example.", dns.TypeA)); reply == nil || reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("priming the cache: rcode = %s", rcodeOf(reply))
	}

	slow := make(chan *dns.Msg, 1)
	go func() { slow <- ask(resolver, "udp", newQuery("slow.example.", dns.TypeA)) }()
	waitFor(t, "the slow query to reach the upstream", func() bool { return upstream.receivedFor("slow.example.") > 0 })

	testCases := []struct {
		name      string
		qname     string
		wantRcode int
	}{
		{name: "uncached name refused", qname: "other.example.", wantRcode: dns.RcodeServerFailure},
		{name: "cached name answered", qname: "cached.example.", wantRcode: dns.RcodeSuccess},
	}

	//nolint:paralleltest // The cases share the one held slot, so they run in turn.
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			start := time.Now()
			reply := ask(resolver, "udp", newQuery(testCase.qname, dns.TypeA))
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("reply took %s; want it at once", elapsed)
			}
			if reply == nil || reply.Rcode != testCase.wantRcode {
				t.Fatalf("rcode = %s; want %s", rcodeOf(reply), dns.RcodeToString[testCase.wantRcode])
			}
		})
	}

	if sent := upstream.receivedFor("other.example."); sent != 0 {
		t.Fatalf("the refused query reached the upstream %d times", sent)
	}
	if rejected := resolver.Metrics().OverloadRejected; rejected != 1 {
		t.Fatalf("overload_rejected = %d; want 1", rejected)
	}

	<-slow
	if reply := ask(resolver, "udp", newQuery("other.example.", dns.TypeA)); reply == nil || reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("after the slot was freed: rcode = %s; want NOERROR", rcodeOf(reply))
	}
}
