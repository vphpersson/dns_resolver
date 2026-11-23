// Package local_zone knows the names a resolver answers itself rather than
// sending upstream: special-use names, which have no meaning in the global
// DNS, and the reverse zones of private and reserved address space. A query
// for one says something about the local network -- a host's name, a LAN
// address -- and the upstream could only answer it NXDOMAIN.
package local_zone

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// localhostZone and every name below it are loopback (RFC 6761 section 6.3).
const localhostZone = "localhost."

// specialUseZones are the special-use domains a caching resolver answers
// itself.
var specialUseZones = []string{
	localhostZone,    // RFC 6761
	"home.arpa.",     // RFC 8375
	"resolver.arpa.", // RFC 9462: about this resolver, not the upstream
	"local.",         // RFC 6762: multicast DNS only
	"onion.",         // RFC 7686
	"invalid.",       // RFC 6761
	"test.",          // RFC 6761
}

// reverseZones are the locally served reverse zones of RFC 6303 and RFC 7793.
func reverseZones() []string {
	zones := []string{
		// RFC 1918
		"10.in-addr.arpa.",
		"168.192.in-addr.arpa.",
		// RFC 6303 section 4.2: this network, loopback, link local and the
		// documentation networks.
		"0.in-addr.arpa.",
		"127.in-addr.arpa.",
		"254.169.in-addr.arpa.",
		"2.0.192.in-addr.arpa.",
		"100.51.198.in-addr.arpa.",
		"113.0.203.in-addr.arpa.",
		"255.255.255.255.in-addr.arpa.",
		// RFC 6303 sections 4.3 to 4.6: ::, ::1, unique local, link local
		// and documentation addresses.
		strings.Repeat("0.", 32) + "ip6.arpa.",
		"1." + strings.Repeat("0.", 31) + "ip6.arpa.",
		"d.f.ip6.arpa.",
		"8.e.f.ip6.arpa.",
		"9.e.f.ip6.arpa.",
		"a.e.f.ip6.arpa.",
		"b.e.f.ip6.arpa.",
		"8.b.d.0.1.0.0.2.ip6.arpa.",
	}
	// RFC 1918: 172.16.0.0/12.
	for octet := 16; octet <= 31; octet++ {
		zones = append(zones, fmt.Sprintf("%d.172.in-addr.arpa.", octet))
	}
	// RFC 6598 shared address space, 100.64.0.0/10, per RFC 7793.
	for octet := 64; octet <= 127; octet++ {
		zones = append(zones, fmt.Sprintf("%d.100.in-addr.arpa.", octet))
	}
	return zones
}

var zones = func() map[string]struct{} {
	set := make(map[string]struct{})
	for _, zone := range append(specialUseZones, reverseZones()...) {
		set[zone] = struct{}{}
	}
	return set
}()

// singleLabelTypes are the types a host is looked up by. A single-label name
// asked for one of them is a host's bare name, which has no answer in the
// global DNS; asked for other types, it is a top-level domain, whose NS, DS
// and DNSKEY records a validating client needs.
var singleLabelTypes = map[uint16]struct{}{
	dns.TypeA:     {},
	dns.TypeAAAA:  {},
	dns.TypeANY:   {},
	dns.TypeHTTPS: {},
	dns.TypeSVCB:  {},
}

// Match reports whether a query for name and qtype is answered locally, and
// the zone it falls in, which is empty for a single-label name. A DS query at
// a zone's apex is not answered locally: the DS record lives in the parent,
// whose proof that the zone is unsigned is what lets a validating client
// accept the zone's local answers. localhost is the exception, as no query
// for it is to reach an authoritative server (RFC 6761 section 6.3).
func Match(name string, qtype uint16) (string, bool) {
	name = strings.ToLower(dns.Fqdn(name))

	for candidate := name; candidate != "."; {
		if _, found := zones[candidate]; found {
			if qtype == dns.TypeDS && candidate == name && candidate != localhostZone {
				return "", false
			}
			return candidate, true
		}
		index := strings.IndexByte(candidate, '.')
		candidate = candidate[index+1:]
		if candidate == "" {
			break
		}
	}

	if dns.CountLabel(name) == 1 {
		if _, found := singleLabelTypes[qtype]; found {
			return "", true
		}
	}

	return "", false
}

// soaTtl is the TTL and negative-caching time of a local answer. It is short,
// so a name added to the hosts file is found soon by clients that cached its
// absence.
const soaTtl = 60

// Response answers request locally, its question being one Match accepted
// with zone. A name below the zone does not exist; the zone's own apex exists
// and holds nothing. Every name at or below localhost exists, holding the
// loopback addresses and nothing else. The SOA in the authority section of a
// negative answer is what lets a client cache it (RFC 2308); a single-label
// name, which has no zone, gets none.
func Response(request *dns.Msg, zone string) *dns.Msg {
	response := new(dns.Msg)
	response.SetRcode(request, dns.RcodeNameError)
	response.Authoritative = true
	response.RecursionAvailable = true

	if zone == "" {
		return response
	}

	var question dns.Question
	if len(request.Question) > 0 {
		question = request.Question[0]
	}

	switch {
	case zone == localhostZone:
		response.Rcode = dns.RcodeSuccess
		if record := loopbackRecord(question); record != nil {
			response.Answer = []dns.RR{record}
			return response
		}
	case strings.EqualFold(dns.Fqdn(question.Name), zone):
		response.Rcode = dns.RcodeSuccess
	}

	response.Ns = []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTtl},
		Ns:      "localhost.",
		Mbox:    "nobody.invalid.",
		Serial:  1,
		Refresh: 3600,
		Retry:   1200,
		Expire:  604800,
		Minttl:  soaTtl,
	}}
	return response
}

// loopbackRecord is the answer to question for a localhost name, or nil for a
// type that has none.
func loopbackRecord(question dns.Question) dns.RR {
	header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: soaTtl}
	switch question.Qtype {
	case dns.TypeA:
		return &dns.A{Hdr: header, A: net.IPv4(127, 0, 0, 1).To4()}
	case dns.TypeAAAA:
		return &dns.AAAA{Hdr: header, AAAA: net.IPv6loopback}
	default:
		return nil
	}
}
