package resolver

import (
	"dns_resolver/pkg/types/resolver_config"
	"net/netip"
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

// One client may hold only so many forwards at once, so a client keeping the
// upstream busy cannot make every other client's cache misses fail. The bound
// was global and first come, first served.
//
//nolint:tparallel // The subtests share the one client's held slot, so they run in turn.
func TestServeDNS_InFlightLimitPerClient(t *testing.T) {
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
		resolver_config.WithMaxInFlight(8),
		resolver_config.WithMaxInFlightPerClient(1),
		resolver_config.WithRequestTimeout(2*time.Second),
	)

	const busyClient = "192.0.2.10:5000"

	slow := make(chan *dns.Msg, 1)
	go func() { slow <- askFrom(resolver, "udp", busyClient, newQuery("slow.example.", dns.TypeA)) }()
	waitFor(t, "the slow query to reach the upstream", func() bool { return upstream.receivedFor("slow.example.") > 0 })

	testCases := []struct {
		name      string
		remote    string
		qname     string
		wantRcode int
	}{
		{name: "busy client refused", remote: "192.0.2.10:5001", qname: "busy.example.", wantRcode: dns.RcodeServerFailure},
		{name: "other client answered", remote: "192.0.2.11:5000", qname: "other.example.", wantRcode: dns.RcodeSuccess},
	}

	//nolint:paralleltest // The cases share the busy client's held slot, so they run in turn.
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			start := time.Now()
			reply := askFrom(resolver, "udp", testCase.remote, newQuery(testCase.qname, dns.TypeA))
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("reply took %s; want it at once", elapsed)
			}
			if reply == nil || reply.Rcode != testCase.wantRcode {
				t.Fatalf("rcode = %s; want %s", rcodeOf(reply), dns.RcodeToString[testCase.wantRcode])
			}
		})
	}

	if sent := upstream.receivedFor("busy.example."); sent != 0 {
		t.Fatalf("the refused query reached the upstream %d times", sent)
	}
	if metrics := resolver.Metrics(); metrics.ClientOverloadRejected != 1 || metrics.OverloadRejected != 0 {
		t.Fatalf("client_overload_rejected=%d overload_rejected=%d; want 1 and 0", metrics.ClientOverloadRejected, metrics.OverloadRejected)
	}

	<-slow
	if reply := askFrom(resolver, "udp", busyClient, newQuery("busy.example.", dns.TypeA)); reply == nil || reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("after the client's slot was freed: rcode = %s; want NOERROR", rcodeOf(reply))
	}
}

func TestClientSlots(t *testing.T) {
	t.Parallel()

	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")

	type step struct {
		release bool
		client  netip.Addr
		want    bool
	}

	testCases := []struct {
		name  string
		limit int
		steps []step
	}{
		{
			name:  "up to the limit",
			limit: 2,
			steps: []step{{client: a, want: true}, {client: a, want: true}, {client: a, want: false}},
		},
		{
			name:  "clients apart",
			limit: 1,
			steps: []step{{client: a, want: true}, {client: b, want: true}, {client: a, want: false}},
		},
		{
			name:  "release frees a slot",
			limit: 1,
			steps: []step{{client: a, want: true}, {client: a, want: false}, {release: true, client: a}, {client: a, want: true}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			slots := newClientSlots(testCase.limit)
			for i, step := range testCase.steps {
				if step.release {
					slots.release(step.client)
					continue
				}
				if got := slots.acquire(step.client); got != step.want {
					t.Fatalf("step %d: acquire(%v) = %t; want %t", i, step.client, got, step.want)
				}
			}
		})
	}

	// Releasing every slot forgets the client, so the map holds only the
	// clients with forwards in flight.
	slots := newClientSlots(2)
	slots.acquire(a)
	slots.release(a)
	if len(slots.counts) != 0 {
		t.Fatalf("slots track %d clients after all were released", len(slots.counts))
	}

	var unbounded *clientSlots
	if !unbounded.acquire(a) {
		t.Fatal("a nil clientSlots refused a forward")
	}
	unbounded.release(a)
}
