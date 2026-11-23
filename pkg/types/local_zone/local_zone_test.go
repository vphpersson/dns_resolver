package local_zone

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMatch(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		qname    string
		qtype    uint16
		wantZone string
		wantOk   bool
	}{
		{name: "home.arpa host", qname: "printer.home.arpa.", qtype: dns.TypeA, wantZone: "home.arpa.", wantOk: true},
		{name: "home.arpa any case, no dot", qname: "Printer.HOME.arpa", qtype: dns.TypeAAAA, wantZone: "home.arpa.", wantOk: true},
		{name: "home.arpa apex", qname: "home.arpa.", qtype: dns.TypeSOA, wantZone: "home.arpa.", wantOk: true},
		{name: "home.arpa apex ds", qname: "home.arpa.", qtype: dns.TypeDS},
		{name: "ds below the apex", qname: "sub.home.arpa.", qtype: dns.TypeDS, wantZone: "home.arpa.", wantOk: true},
		{name: "resolver.arpa", qname: "_dns.resolver.arpa.", qtype: dns.TypeSVCB, wantZone: "resolver.arpa.", wantOk: true},
		{name: "mdns name", qname: "tv.local.", qtype: dns.TypeA, wantZone: "local.", wantOk: true},
		{name: "onion", qname: "abcdef.onion.", qtype: dns.TypeA, wantZone: "onion.", wantOk: true},
		{name: "rfc 1918 10/8", qname: "4.3.2.10.in-addr.arpa.", qtype: dns.TypePTR, wantZone: "10.in-addr.arpa.", wantOk: true},
		{name: "rfc 1918 172.16/12 low", qname: "1.0.16.172.in-addr.arpa.", qtype: dns.TypePTR, wantZone: "16.172.in-addr.arpa.", wantOk: true},
		{name: "rfc 1918 172.16/12 high", qname: "1.0.31.172.in-addr.arpa.", qtype: dns.TypePTR, wantZone: "31.172.in-addr.arpa.", wantOk: true},
		{name: "172.32 is public", qname: "1.0.32.172.in-addr.arpa.", qtype: dns.TypePTR},
		{name: "rfc 1918 192.168/16", qname: "10.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, wantZone: "168.192.in-addr.arpa.", wantOk: true},
		{name: "shared address space", qname: "1.0.100.100.in-addr.arpa.", qtype: dns.TypePTR, wantZone: "100.100.in-addr.arpa.", wantOk: true},
		{name: "100.128 is public", qname: "1.0.128.100.in-addr.arpa.", qtype: dns.TypePTR},
		{name: "link local v4", qname: "1.1.254.169.in-addr.arpa.", qtype: dns.TypePTR, wantZone: "254.169.in-addr.arpa.", wantOk: true},
		{name: "unique local v6", qname: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.", qtype: dns.TypePTR, wantZone: "d.f.ip6.arpa.", wantOk: true},
		{name: "link local v6", qname: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.", qtype: dns.TypePTR, wantZone: "8.e.f.ip6.arpa.", wantOk: true},
		{name: "public reverse", qname: "8.8.8.8.in-addr.arpa.", qtype: dns.TypePTR},
		{name: "public v6 reverse", qname: "1.0.0.2.ip6.arpa.", qtype: dns.TypePTR},
		{name: "single label host", qname: "printer.", qtype: dns.TypeA, wantOk: true},
		{name: "single label https", qname: "printer.", qtype: dns.TypeHTTPS, wantOk: true},
		{name: "top-level domain ns", qname: "se.", qtype: dns.TypeNS},
		{name: "top-level domain ds", qname: "com.", qtype: dns.TypeDS},
		{name: "root", qname: ".", qtype: dns.TypeNS},
		{name: "public name", qname: "www.example.com.", qtype: dns.TypeA},
		{name: "localhost", qname: "localhost.", qtype: dns.TypeA, wantZone: "localhost.", wantOk: true},
		{name: "below localhost", qname: "app.dev.localhost.", qtype: dns.TypeAAAA, wantZone: "localhost.", wantOk: true},
		{name: "localhost other type", qname: "localhost.", qtype: dns.TypeMX, wantZone: "localhost.", wantOk: true},
		{name: "localhost ds", qname: "localhost.", qtype: dns.TypeDS, wantZone: "localhost.", wantOk: true},
		{name: "a name ending in localhost", qname: "notlocalhost.", qtype: dns.TypeNS},
		{name: "a public name ending like a zone", qname: "notlocal.", qtype: dns.TypeNS},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			zone, ok := Match(testCase.qname, testCase.qtype)
			if ok != testCase.wantOk || zone != testCase.wantZone {
				t.Fatalf("Match(%q, %s) = %q, %t; want %q, %t", testCase.qname, dns.TypeToString[testCase.qtype], zone, ok, testCase.wantZone, testCase.wantOk)
			}
		})
	}
}

func TestResponse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		qname     string
		zone      string
		wantRcode int
		wantSoa   bool
	}{
		{name: "below the zone", qname: "printer.home.arpa.", zone: "home.arpa.", wantRcode: dns.RcodeNameError, wantSoa: true},
		{name: "zone apex", qname: "home.arpa.", zone: "home.arpa.", wantRcode: dns.RcodeSuccess, wantSoa: true},
		{name: "single label", qname: "printer.", wantRcode: dns.RcodeNameError},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request := new(dns.Msg)
			request.SetQuestion(testCase.qname, dns.TypeA)
			response := Response(request, testCase.zone)

			if response.Rcode != testCase.wantRcode || response.Id != request.Id || len(response.Answer) != 0 {
				t.Fatalf("response rcode=%s id=%d answers=%d; want %s, %d, 0", dns.RcodeToString[response.Rcode], response.Id, len(response.Answer), dns.RcodeToString[testCase.wantRcode], request.Id)
			}
			if gotSoa := len(response.Ns) == 1; gotSoa != testCase.wantSoa {
				t.Fatalf("response has an SOA = %t; want %t", gotSoa, testCase.wantSoa)
			}
			if testCase.wantSoa && response.Ns[0].Header().Name != testCase.zone {
				t.Fatalf("SOA owner = %q; want %q", response.Ns[0].Header().Name, testCase.zone)
			}
		})
	}
}

// localhost and every name below it are loopback (RFC 6761 section 6.3).
func TestResponse_Localhost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		qname      string
		qtype      uint16
		wantAnswer string
	}{
		{name: "a", qname: "localhost.", qtype: dns.TypeA, wantAnswer: "127.0.0.1"},
		{name: "aaaa", qname: "localhost.", qtype: dns.TypeAAAA, wantAnswer: "::1"},
		{name: "below, asker's case", qname: "App.LocalHost.", qtype: dns.TypeA, wantAnswer: "127.0.0.1"},
		{name: "other type", qname: "localhost.", qtype: dns.TypeTXT},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request := new(dns.Msg)
			request.SetQuestion(testCase.qname, testCase.qtype)
			zone, ok := Match(testCase.qname, testCase.qtype)
			if !ok {
				t.Fatalf("Match(%q) did not match", testCase.qname)
			}
			response := Response(request, zone)
			if response.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s; want NOERROR", dns.RcodeToString[response.Rcode])
			}

			if testCase.wantAnswer == "" {
				if len(response.Answer) != 0 || len(response.Ns) != 1 {
					t.Fatalf("answers=%d authority=%d; want NODATA with an SOA", len(response.Answer), len(response.Ns))
				}
				return
			}
			if len(response.Answer) != 1 {
				t.Fatalf("answers = %v; want one", response.Answer)
			}
			record := response.Answer[0]
			var got string
			switch typedRecord := record.(type) {
			case *dns.A:
				got = typedRecord.A.String()
			case *dns.AAAA:
				got = typedRecord.AAAA.String()
			}
			if got != testCase.wantAnswer || record.Header().Name != testCase.qname || record.Header().Rrtype != testCase.qtype {
				t.Fatalf("answer = %v; want %s %s %s", record, testCase.qname, dns.TypeToString[testCase.qtype], testCase.wantAnswer)
			}
		})
	}
}
