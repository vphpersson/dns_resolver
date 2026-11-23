package resolver

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func withEdns(options ...dns.EDNS0) func(*dns.Msg) {
	return func(m *dns.Msg) {
		m.SetEdns0(4096, false)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, options...)
	}
}

func lastQuery(t *testing.T, upstream *testUpstream) *dns.Msg {
	t.Helper()
	queries := upstream.received()
	if len(queries) == 0 {
		t.Fatal("the upstream received no query")
	}
	return queries[len(queries)-1]
}

// The upstream is sent a query of the resolver's own making, holding only what
// the cache key holds. The client's message used to go up as it was: its
// header bits, its EDNS options and its other sections, while the answer was
// cached for every client by name, type, class and DO alone.
func TestServeDNS_UpstreamQueryIsOwn(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		qname  string
		mutate func(*dns.Msg)
		wantDO bool
		wantCD bool
	}{
		{
			name:   "recursion not desired",
			qname:  "rd.example.",
			mutate: func(m *dns.Msg) { m.RecursionDesired = false },
		},
		{
			name:  "client subnet",
			qname: "subnet.example.",
			mutate: withEdns(&dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        1,
				SourceNetmask: 24,
				Address:       net.ParseIP("192.0.2.0").To4(),
			}),
		},
		{
			name:   "cookie",
			qname:  "cookie.example.",
			mutate: withEdns(&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"}),
		},
		{
			name:  "additional record",
			qname: "extra.example.",
			mutate: func(m *dns.Msg) {
				m.Extra = append(m.Extra, &dns.TXT{
					Hdr: dns.RR_Header{Name: "extra.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{"from the client"},
				})
			},
		},
		{
			name:  "mixed case",
			qname: "MiXeD.Example.",
		},
		{
			name:   "dnssec ok",
			qname:  "do.example.",
			mutate: func(m *dns.Msg) { m.SetEdns0(1232, true) },
			wantDO: true,
		},
		{
			name:   "checking disabled",
			qname:  "cd.example.",
			mutate: func(m *dns.Msg) { m.CheckingDisabled = true },
			wantCD: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, answerWith("192.0.2.1"))
			resolver := newTestResolver(t, upstream)

			request := newQuery(testCase.qname, dns.TypeA)
			if testCase.mutate != nil {
				testCase.mutate(request)
			}
			reply := ask(resolver, "udp", request)
			if reply == nil || reply.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s; want NOERROR", rcodeOf(reply))
			}
			if reply.RecursionDesired != request.RecursionDesired {
				t.Fatalf("reply RD = %t; want the asker's %t", reply.RecursionDesired, request.RecursionDesired)
			}

			query := lastQuery(t, upstream)
			if query.Opcode != dns.OpcodeQuery || !query.RecursionDesired {
				t.Fatalf("upstream query opcode=%s rd=%t; want QUERY with RD", dns.OpcodeToString[query.Opcode], query.RecursionDesired)
			}
			if query.CheckingDisabled != testCase.wantCD {
				t.Fatalf("upstream query CD = %t; want %t", query.CheckingDisabled, testCase.wantCD)
			}
			if len(query.Question) != 1 || query.Question[0].Name != strings.ToLower(testCase.qname) {
				t.Fatalf("upstream question = %v; want one for %q", query.Question, strings.ToLower(testCase.qname))
			}
			if len(query.Answer) != 0 || len(query.Ns) != 0 || len(query.Extra) != 1 {
				t.Fatalf("upstream query sections an=%d ns=%d ar=%d; want 0, 0 and the OPT alone", len(query.Answer), len(query.Ns), len(query.Extra))
			}
			opt := query.IsEdns0()
			if opt == nil {
				t.Fatal("upstream query has no OPT record")
			}
			if len(opt.Option) != 0 {
				t.Fatalf("upstream query carries EDNS options %v; want none", opt.Option)
			}
			if opt.Do() != testCase.wantDO {
				t.Fatalf("upstream query DO = %t; want %t", opt.Do(), testCase.wantDO)
			}
		})
	}
}

// What one client asks must not change what another is answered.
func TestServeDNS_AnswerSharedAcrossClients(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		answer      answerFunc
		first       *dns.Msg
		second      *dns.Msg
		checkSecond func(t *testing.T, reply *dns.Msg)
	}{
		{
			// An upstream asked without RD answers from its cache, so an empty
			// NOERROR -- which was cached for a day as NODATA for everyone.
			name: "recursion not desired",
			answer: func(query *dns.Msg) *dns.Msg {
				if !query.RecursionDesired {
					response := new(dns.Msg)
					response.SetReply(query)
					return response
				}
				return answerWith("192.0.2.1")(query)
			},
			first: func() *dns.Msg {
				m := newQuery("victim.example.", dns.TypeA)
				m.RecursionDesired = false
				return m
			}(),
			second: newQuery("victim.example.", dns.TypeA),
			checkSecond: func(t *testing.T, reply *dns.Msg) {
				t.Helper()
				if len(reply.Answer) != 1 {
					t.Fatalf("second asker got %d answers; want 1", len(reply.Answer))
				}
			},
		},
		{
			// A validating upstream fails a bogus answer unless CD is set. The
			// CD=1 answer was cached under the same key and so served to
			// clients that wanted it validated.
			name: "checking disabled",
			answer: func(query *dns.Msg) *dns.Msg {
				if !query.CheckingDisabled {
					response := new(dns.Msg)
					response.SetRcode(query, dns.RcodeServerFailure)
					return response
				}
				return answerWith("192.0.2.66")(query)
			},
			first: func() *dns.Msg {
				m := newQuery("bogus.example.", dns.TypeA)
				m.CheckingDisabled = true
				return m
			}(),
			second: newQuery("bogus.example.", dns.TypeA),
			checkSecond: func(t *testing.T, reply *dns.Msg) {
				t.Helper()
				if reply.Rcode != dns.RcodeServerFailure || len(reply.Answer) != 0 {
					t.Fatalf("CD=0 asker got rcode %s with %d answers; want the validated SERVFAIL", rcodeOf(reply), len(reply.Answer))
				}
			},
		},
		{
			// The cached reply carried the first asker's question, so a client
			// checking its 0x20 casing saw a reply to another question.
			name:   "question casing",
			answer: answerWith("192.0.2.1"),
			first:  newQuery("VICTIM.example.", dns.TypeA),
			second: newQuery("victim.EXAMPLE.", dns.TypeA),
			checkSecond: func(t *testing.T, reply *dns.Msg) {
				t.Helper()
				if len(reply.Question) != 1 || reply.Question[0].Name != "victim.EXAMPLE." {
					t.Fatalf("second asker's reply question = %v; want its own victim.EXAMPLE.", reply.Question)
				}
				if len(reply.Answer) != 1 || reply.Answer[0].Header().Name != "victim.EXAMPLE." {
					t.Fatalf("second asker's answer = %v; want it owned by victim.EXAMPLE.", reply.Answer)
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, testCase.answer)
			resolver := newTestResolver(t, upstream)

			if reply := ask(resolver, "udp", testCase.first); reply == nil {
				t.Fatal("first asker got no reply")
			}
			reply := ask(resolver, "udp", testCase.second)
			if reply == nil {
				t.Fatal("second asker got no reply")
			}
			if reply.Id != testCase.second.Id {
				t.Fatalf("reply ID = %d; want the asker's %d", reply.Id, testCase.second.Id)
			}
			testCase.checkSecond(t, reply)
		})
	}
}

// Only a standard query is answered; anything else used to be forwarded, and
// its reply cached as the answer to an ordinary query for the name.
func TestServeDNS_RefusesOtherOpcodes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		opcode int
	}{
		{name: "notify", opcode: dns.OpcodeNotify},
		{name: "update", opcode: dns.OpcodeUpdate},
		{name: "status", opcode: dns.OpcodeStatus},
		{name: "iquery", opcode: dns.OpcodeIQuery},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, answerWith("192.0.2.1"))
			resolver := newTestResolver(t, upstream)

			request := newQuery("zone.example.", dns.TypeSOA)
			request.Opcode = testCase.opcode
			reply := ask(resolver, "udp", request)
			if reply == nil || reply.Rcode != dns.RcodeNotImplemented {
				t.Fatalf("rcode = %s; want NOTIMP", rcodeOf(reply))
			}
			if sent := len(upstream.received()); sent != 0 {
				t.Fatalf("upstream was sent %d queries; want none", sent)
			}
		})
	}
}

// The reply's OPT record is the resolver's, given to an asker that sent one.
// The upstream's own was passed on, options and all, to every client of the
// cached answer, including ones that sent no OPT and must receive none.
func TestServeDNS_ReplyEdns(t *testing.T) {
	t.Parallel()

	answer := func(query *dns.Msg) *dns.Msg {
		response := answerWith("192.0.2.1")(query)
		response.AuthenticatedData = true
		response.SetEdns0(4096, false)
		opt := response.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708a1a2a3a4a5a6a7a8"})
		return response
	}

	testCases := []struct {
		name    string
		mutate  func(*dns.Msg)
		wantOpt bool
		wantDO  bool
		wantAD  bool
	}{
		{name: "no edns"},
		{name: "edns", mutate: withEdns(), wantOpt: true},
		{name: "dnssec ok", mutate: func(m *dns.Msg) { m.SetEdns0(1232, true) }, wantOpt: true, wantDO: true, wantAD: true},
		{name: "authenticated data", mutate: func(m *dns.Msg) { m.AuthenticatedData = true }, wantAD: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, answer)
			resolver := newTestResolver(t, upstream)

			// The answer is cached by whoever asks first; what each asker
			// gets must not depend on that.
			for _, attempt := range []string{"miss", "hit"} {
				request := newQuery("edns.example.", dns.TypeA)
				if testCase.mutate != nil {
					testCase.mutate(request)
				}
				reply := ask(resolver, "udp", request)
				if reply == nil || reply.Rcode != dns.RcodeSuccess {
					t.Fatalf("%s: rcode = %s; want NOERROR", attempt, rcodeOf(reply))
				}

				opt := reply.IsEdns0()
				if (opt != nil) != testCase.wantOpt {
					t.Fatalf("%s: reply has OPT = %t; want %t", attempt, opt != nil, testCase.wantOpt)
				}
				if opt != nil {
					if len(opt.Option) != 0 {
						t.Fatalf("%s: reply OPT carries the upstream's options %v", attempt, opt.Option)
					}
					if opt.Do() != testCase.wantDO {
						t.Fatalf("%s: reply DO = %t; want %t", attempt, opt.Do(), testCase.wantDO)
					}
				}
				if reply.AuthenticatedData != testCase.wantAD {
					t.Fatalf("%s: reply AD = %t; want %t", attempt, reply.AuthenticatedData, testCase.wantAD)
				}
			}
		})
	}
}

// A UDP reply is held to 1232 bytes (RFC 9715) whatever size the client
// advertised, so a large answer goes over TCP rather than as a fragmented
// datagram. The advertised size, up to 65535, used to be taken as given.
func TestServeDNS_UdpReplySize(t *testing.T) {
	t.Parallel()

	const records = 120

	answer := func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		for i := range records {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(198, 51, 100, byte(i)).To4(),
			})
		}
		return response
	}

	testCases := []struct {
		name          string
		network       string
		udpSize       uint16
		wantMaxLength int
		wantTruncated bool
	}{
		{name: "udp without edns", network: "udp", wantMaxLength: dns.MinMsgSize, wantTruncated: true},
		{name: "udp advertising 4096", network: "udp", udpSize: 4096, wantMaxLength: 1232, wantTruncated: true},
		{name: "udp advertising 65535", network: "udp", udpSize: 65535, wantMaxLength: 1232, wantTruncated: true},
		{name: "udp advertising 100", network: "udp", udpSize: 100, wantMaxLength: dns.MinMsgSize, wantTruncated: true},
		{name: "tcp", network: "tcp", udpSize: 1232, wantMaxLength: dns.MaxMsgSize},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, answer)
			resolver := newTestResolver(t, upstream)

			request := newQuery("big.example.", dns.TypeA)
			if testCase.udpSize != 0 {
				request.SetEdns0(testCase.udpSize, false)
			}
			reply, length := askWire(resolver, testCase.network, request)
			if reply == nil {
				t.Fatal("no reply")
			}

			if length > testCase.wantMaxLength {
				t.Fatalf("reply is %d bytes; want at most %d", length, testCase.wantMaxLength)
			}
			if reply.Truncated != testCase.wantTruncated {
				t.Fatalf("reply TC = %t; want %t", reply.Truncated, testCase.wantTruncated)
			}
			if !testCase.wantTruncated && len(reply.Answer) != records {
				t.Fatalf("reply carries %d answers; want all %d", len(reply.Answer), records)
			}
			if opt := reply.IsEdns0(); opt != nil && opt.UDPSize() > 1232 {
				t.Fatalf("reply advertises a UDP size of %d; want at most 1232", opt.UDPSize())
			}
		})
	}
}

// A large answer the upstream sent compressed must still fit when it is sent
// on over TCP. The reply was packed without name compression, so an answer
// that fitted the 64 KiB limit as the upstream sent it could not be packed
// again, and the client got nothing.
func TestServeDNS_LargeTcpReply(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		records int
	}{
		{name: "fits uncompressed", records: 1000},
		{name: "fits only compressed", records: 3000},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			upstream := startUpstream(t, func(query *dns.Msg) *dns.Msg {
				response := new(dns.Msg)
				response.SetReply(query)
				response.Compress = true
				for i := range testCase.records {
					response.Answer = append(response.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.IPv4(10, byte(i>>8), byte(i), 1).To4(),
					})
				}
				return response
			})
			resolver := newTestResolver(t, upstream)

			reply := ask(resolver, "tcp", newQuery("many.example.", dns.TypeA))
			if reply == nil {
				t.Fatal("no reply")
			}
			if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != testCase.records {
				t.Fatalf("rcode = %s with %d answers; want NOERROR with %d", rcodeOf(reply), len(reply.Answer), testCase.records)
			}
		})
	}
}
