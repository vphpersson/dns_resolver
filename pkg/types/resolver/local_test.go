package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

// Special-use names and the reverse of private addresses are answered without
// asking the upstream. A home.arpa name missing from the hosts file, a private
// address's PTR and a bare host name all used to go to the forwarder.
func TestServeDNS_LocalNames(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		qname         string
		qtype         uint16
		wantRcode     int
		wantForwarded bool
	}{
		{name: "home.arpa name not in the hosts file", qname: "printer.home.arpa.", qtype: dns.TypeA, wantRcode: dns.RcodeNameError},
		{name: "home.arpa name in the hosts file", qname: "nas.home.arpa.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess},
		{name: "home.arpa delegation", qname: "home.arpa.", qtype: dns.TypeDS, wantRcode: dns.RcodeSuccess, wantForwarded: true},
		{name: "private reverse", qname: "10.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, wantRcode: dns.RcodeNameError},
		{name: "bare host name", qname: "printer.", qtype: dns.TypeA, wantRcode: dns.RcodeNameError},
		{name: "top-level domain", qname: "se.", qtype: dns.TypeNS, wantRcode: dns.RcodeSuccess, wantForwarded: true},
		{name: "public reverse", qname: "8.8.8.8.in-addr.arpa.", qtype: dns.TypePTR, wantRcode: dns.RcodeSuccess, wantForwarded: true},
		{name: "public name", qname: "www.example.com.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantForwarded: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, answerWith("192.0.2.1"))
			resolver := newTestResolver(t, upstream)
			hosts := &testHosts{}
			hosts.add("nas.home.arpa.", "192.168.1.20")
			resolver.Hosts = hosts

			reply := ask(resolver, "udp", newQuery(testCase.qname, testCase.qtype))
			if reply == nil || reply.Rcode != testCase.wantRcode {
				t.Fatalf("rcode = %s; want %s", rcodeOf(reply), dns.RcodeToString[testCase.wantRcode])
			}
			if forwarded := upstream.receivedFor(testCase.qname) > 0; forwarded != testCase.wantForwarded {
				t.Fatalf("forwarded = %t; want %t", forwarded, testCase.wantForwarded)
			}
		})
	}
}
