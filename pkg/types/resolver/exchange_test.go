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
