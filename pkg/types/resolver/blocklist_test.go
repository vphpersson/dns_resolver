package resolver

import (
	"strings"
	"sync"
	"testing"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/miekg/dns"
)

// testBlocklist blocks the names added to it and every name below them.
type testBlocklist struct {
	mu    sync.Mutex
	names map[string]struct{}
}

func (b *testBlocklist) add(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.names == nil {
		b.names = map[string]struct{}{}
	}
	b.names[strings.ToLower(dns.Fqdn(name))] = struct{}{}
}

func (b *testBlocklist) IsBlocked(qname string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	name := strings.ToLower(dns.Fqdn(qname))
	for {
		if _, ok := b.names[name]; ok {
			return true
		}
		index := strings.IndexByte(name, '.')
		if index < 0 || index == len(name)-1 {
			return false
		}
		name = name[index+1:]
	}
}

func (b *testBlocklist) GetRule() *schema.Rule { return &schema.Rule{Name: "test"} }

// testHosts answers A queries for the names added to it.
type testHosts struct {
	mu    sync.Mutex
	names map[string]string
}

func (h *testHosts) add(name string, address string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.names == nil {
		h.names = map[string]string{}
	}
	h.names[strings.ToLower(name)] = address
}

func (h *testHosts) Resolve(request *dns.Msg) *dns.Msg {
	h.mu.Lock()
	address, ok := h.names[strings.ToLower(request.Question[0].Name)]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	return answerWith(address)(request)
}

func isBlockedReply(reply *dns.Msg) bool {
	if reply == nil || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 || len(reply.Ns) != 1 {
		return false
	}
	soa, ok := reply.Ns[0].(*dns.SOA)
	return ok && soa.Ns == "ns.block.local."
}

// answerCname answers every A query with a CNAME to target and target's
// address, as a first-party name fronting a tracker does.
func answerCname(target string) answerFunc {
	return func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		name := query.Question[0].Name
		response.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: target},
			&dns.A{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{198, 51, 100, 7}},
		}
		return response
	}
}

// A blocklist or hosts entry applies to a name as soon as it is loaded, and a
// blocklist applies to the names an answer leads to as well as to the one
// asked. The cache used to be consulted first and never flushed on a reload,
// so a name listed after it was cached resolved until its answer expired, and
// only the question's name was ever checked.
func TestServeDNS_BlocklistAndHostsOverCache(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		answer answerFunc
		// listBefore is listed before the first query, listAfter between
		// the first and the second.
		listBefore string
		listAfter  string
		hostsAfter string
		wantFirst  func(*dns.Msg) bool
		wantSecond func(*dns.Msg) bool
	}{
		{
			name:       "listed after it was cached",
			answer:     answerWith("192.0.2.1"),
			listAfter:  "victim.example.",
			wantFirst:  func(m *dns.Msg) bool { return len(m.Answer) == 1 },
			wantSecond: isBlockedReply,
		},
		{
			name:       "hosts entry after it was cached",
			answer:     answerWith("192.0.2.1"),
			hostsAfter: "192.168.1.10",
			wantFirst:  func(m *dns.Msg) bool { return len(m.Answer) == 1 && m.Answer[0].(*dns.A).A.String() == "192.0.2.1" },
			wantSecond: func(m *dns.Msg) bool {
				return len(m.Answer) == 1 && m.Answer[0].(*dns.A).A.String() == "192.168.1.10"
			},
		},
		{
			name:       "cname target listed",
			answer:     answerCname("tracker.bad.example."),
			listBefore: "bad.example.",
			wantFirst:  isBlockedReply,
			wantSecond: isBlockedReply,
		},
		{
			name:       "cname target listed after it was cached",
			answer:     answerCname("tracker.bad.example."),
			listAfter:  "tracker.bad.example.",
			wantFirst:  func(m *dns.Msg) bool { return len(m.Answer) == 2 },
			wantSecond: isBlockedReply,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, testCase.answer)
			resolver := newTestResolver(t, upstream)
			blocklist := &testBlocklist{}
			resolver.SetBlocklist("test", blocklist)
			hosts := &testHosts{}
			resolver.Hosts = hosts

			if testCase.listBefore != "" {
				blocklist.add(testCase.listBefore)
			}

			first := ask(resolver, "udp", newQuery("victim.example.", dns.TypeA))
			if first == nil || !testCase.wantFirst(first) {
				t.Fatalf("first reply = %v; not what was wanted", first)
			}

			if testCase.listAfter != "" {
				blocklist.add(testCase.listAfter)
			}
			if testCase.hostsAfter != "" {
				hosts.add("victim.example.", testCase.hostsAfter)
			}

			second := ask(resolver, "udp", newQuery("victim.example.", dns.TypeA))
			if second == nil || !testCase.wantSecond(second) {
				t.Fatalf("second reply = %v; not what was wanted", second)
			}
		})
	}
}
