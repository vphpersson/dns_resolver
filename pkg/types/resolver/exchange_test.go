package resolver

import (
	"fmt"
	"testing"

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
			if entries := resolver.Cache.Snapshot(); len(entries) != 0 {
				t.Fatalf("cache holds %d entries after a failed exchange: %+v", len(entries), entries)
			}
		})
	}
}
