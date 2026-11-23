package resolver

import (
	"dns_resolver/pkg/types/resolver_config"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// An answer other than NOERROR is the upstream's reply, not a fault of the
// connection it came over. Closing the connection for it cost every NXDOMAIN a
// new TCP and TLS handshake.
func TestServeDNS_RcodeKeepsConnection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		rcode int
	}{
		{name: "nxdomain", rcode: dns.RcodeNameError},
		{name: "servfail", rcode: dns.RcodeServerFailure},
		{name: "refused", rcode: dns.RcodeRefused},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, answerRcode(testCase.rcode))
			resolver := newTestResolver(t, upstream)

			for i := range 5 {
				reply := ask(resolver, "udp", newQuery(fmt.Sprintf("name%d.example.", i), dns.TypeA))
				if reply == nil || reply.Rcode != testCase.rcode {
					t.Fatalf("query %d: rcode = %s; want %s", i, rcodeOf(reply), dns.RcodeToString[testCase.rcode])
				}
			}

			if accepted := upstream.accepted.Load(); accepted != 1 {
				t.Fatalf("upstream accepted %d connections for 5 sequential queries; want 1", accepted)
			}
		})
	}
}

// A message the exchange failed on is not an answer. The resolver used to hand
// back whatever the last attempt read, so a reply carrying another query's ID,
// or answering another name, was served and cached as the answer.
func TestServeDNS_FailedExchangeAnswersNothing(t *testing.T) {
	t.Parallel()

	const poison = "198.51.100.66"

	testCases := []struct {
		name   string
		answer answerFunc
	}{
		{
			name: "mismatched id",
			answer: func(query *dns.Msg) *dns.Msg {
				response := answerWith(poison)(query)
				response.Id = query.Id ^ 0xffff
				return response
			},
		},
		{
			name: "other question",
			answer: func(query *dns.Msg) *dns.Msg {
				other := query.Copy()
				other.Question[0].Name = "poison.example."
				response := answerWith(poison)(other)
				response.Id = query.Id
				return response
			},
		},
		{
			name: "other type",
			answer: func(query *dns.Msg) *dns.Msg {
				response := answerWith(poison)(query)
				response.Question[0].Qtype = dns.TypeAAAA
				return response
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, testCase.answer)
			resolver := newTestResolver(t, upstream)

			reply := ask(resolver, "udp", newQuery("victim.example.", dns.TypeA))
			if reply == nil || reply.Rcode != dns.RcodeServerFailure {
				t.Fatalf("rcode = %s; want SERVFAIL", rcodeOf(reply))
			}
			if len(reply.Answer) != 0 {
				t.Fatalf("reply carries %d answers from a failed exchange: %v", len(reply.Answer), reply.Answer)
			}
			if entries := resolver.Cache.Snapshot("", 0); len(entries) != 0 {
				t.Fatalf("cache holds %d entries after a failed exchange: %+v", len(entries), entries)
			}
		})
	}
}

// startStalledUpstream accepts TCP connections and never speaks, so a TLS
// handshake with it lasts until the client gives up.
func startStalledUpstream(t *testing.T) *testUpstream {
	t.Helper()

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	upstream := &testUpstream{address: listener.Addr().String()}
	go func() {
		var connections []net.Conn
		defer func() {
			for _, connection := range connections {
				_ = connection.Close()
			}
		}()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			upstream.accepted.Add(1)
			connections = append(connections, connection)
		}
	}()

	return upstream
}

// One request must not hold an upstream connection for longer than its own
// deadline. Every timed-out exchange used to be retried up to
// MaxNumConnections+1 times with no deadline over them, so a name the upstream
// was slow on held a slot for minutes.
func TestServeDNS_RequestDeadline(t *testing.T) {
	t.Parallel()

	const (
		requestTimeout = 500 * time.Millisecond
		// The slack allows for a slow test machine; the failure this guards
		// against took seconds per attempt.
		maxElapsed = requestTimeout + time.Second
	)

	testCases := []struct {
		name     string
		upstream func(t *testing.T) *testUpstream
	}{
		{
			name: "silent upstream",
			upstream: func(t *testing.T) *testUpstream {
				t.Helper()
				return startUpstream(t, func(*dns.Msg) *dns.Msg { return nil })
			},
		},
		{
			name:     "stalled handshake",
			upstream: startStalledUpstream,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := testCase.upstream(t)
			resolver := newTestResolver(
				t,
				upstream,
				resolver_config.WithMaxConnections(8),
				resolver_config.WithRequestTimeout(requestTimeout),
			)

			start := time.Now()
			reply := ask(resolver, "udp", newQuery("slow.example.", dns.TypeA))
			elapsed := time.Since(start)

			if reply == nil || reply.Rcode != dns.RcodeServerFailure {
				t.Fatalf("rcode = %s; want SERVFAIL", rcodeOf(reply))
			}
			if elapsed > maxElapsed {
				t.Fatalf("request took %s; want at most %s", elapsed.Round(time.Millisecond), maxElapsed)
			}
			if sent := upstream.receivedFor("slow.example."); sent > maxExchangeAttempts {
				t.Fatalf("upstream was sent the query %d times; want at most %d", sent, maxExchangeAttempts)
			}
		})
	}
}

// Attempts are bounded even when each fails fast, so a name whose answers all
// fail costs a few connections rather than one per pool slot.
func TestServeDNS_BoundedAttempts(t *testing.T) {
	t.Parallel()

	upstream := startUpstream(t, func(query *dns.Msg) *dns.Msg {
		response := answerWith("192.0.2.1")(query)
		response.Id = query.Id ^ 0xffff
		return response
	})
	resolver := newTestResolver(t, upstream, resolver_config.WithMaxConnections(16))

	if reply := ask(resolver, "udp", newQuery("failing.example.", dns.TypeA)); reply == nil || reply.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s; want SERVFAIL", rcodeOf(reply))
	}
	if sent := upstream.receivedFor("failing.example."); sent != maxExchangeAttempts {
		t.Fatalf("upstream was sent the query %d times; want %d", sent, maxExchangeAttempts)
	}
}

// When the upstream closes the connections idle in the pool, a request must
// still be answered. The attempts took the most recently used idle connection
// each time, so with three or more dead ones idle every attempt failed and the
// request was answered SERVFAIL without a dial.
func TestServeDNS_DeadPooledConnections(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		idle int
	}{
		{name: "one idle", idle: 1},
		{name: "as many idle as attempts", idle: maxExchangeAttempts},
		{name: "more idle than attempts", idle: 2 * maxExchangeAttempts},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// The priming queries are held until all of them have arrived, so
			// each takes a connection of its own.
			var arrived atomic.Int64
			release := make(chan struct{})
			upstream := startUpstream(t, func(query *dns.Msg) *dns.Msg {
				if strings.HasPrefix(query.Question[0].Name, "prime") {
					arrived.Add(1)
					select {
					case <-release:
					case <-time.After(5 * time.Second):
					}
				}
				return answerWith("192.0.2.1")(query)
			})
			resolver := newTestResolver(t, upstream, resolver_config.WithMaxConnections(2*maxExchangeAttempts+2))

			var group sync.WaitGroup
			for i := range testCase.idle {
				group.Go(func() { ask(resolver, "udp", newQuery(fmt.Sprintf("prime%d.example.", i), dns.TypeA)) })
			}
			waitFor(t, "the priming queries to reach the upstream", func() bool { return arrived.Load() == int64(testCase.idle) })
			close(release)
			group.Wait()
			if idle := resolver.DotConfig.ConnectionPool.Len(); idle != testCase.idle {
				t.Fatalf("pool holds %d idle connections; the test needs %d", idle, testCase.idle)
			}

			upstream.closeConnections()
			dialled := upstream.accepted.Load()

			reply := ask(resolver, "udp", newQuery("after.example.", dns.TypeA))
			if reply == nil || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
				t.Fatalf("rcode = %s; want NOERROR with the answer", rcodeOf(reply))
			}
			if upstream.accepted.Load() == dialled {
				t.Fatal("the request was answered without a new connection")
			}
		})
	}
}
