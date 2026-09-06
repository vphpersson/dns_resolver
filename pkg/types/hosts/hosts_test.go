package hosts

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const testHostsFile = `
# Static table lookup for hostnames.
127.0.0.1       localhost
::1             localhost
192.168.1.1     glory glory.home.arpa dns.home.arpa
10.5.2.2        clamps clamps.home.arpa   # trailing comment
2001:db8::1     v6only v6only.home.arpa
not-an-address  bogus
198.51.100.1
`

func parseTestEntries(t *testing.T) *Entries {
	t.Helper()
	entries, err := ParseReader(strings.NewReader(testHostsFile))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	return entries
}

func TestParseReader(t *testing.T) {
	t.Parallel()

	entries := parseTestEntries(t)

	testCases := []struct {
		name    string
		lookup  string
		wantV4  []string
		wantV6  []string
		wantHas bool
	}{
		{
			name:    "v4 name with aliases",
			lookup:  "glory.home.arpa",
			wantV4:  []string{"192.168.1.1"},
			wantHas: true,
		},
		{
			name:    "bare name is an alias of the same entry",
			lookup:  "glory",
			wantV4:  []string{"192.168.1.1"},
			wantHas: true,
		},
		{
			name:    "lookup is case insensitive",
			lookup:  "GLORY.Home.Arpa",
			wantV4:  []string{"192.168.1.1"},
			wantHas: true,
		},
		{
			name:    "a trailing dot is stripped",
			lookup:  "clamps.home.arpa.",
			wantV4:  []string{"10.5.2.2"},
			wantHas: true,
		},
		{
			name:    "a name after a comment marker is not parsed",
			lookup:  "trailing",
			wantHas: false,
		},
		{
			name:    "both families on one name",
			lookup:  "localhost",
			wantV4:  []string{"127.0.0.1"},
			wantV6:  []string{"::1"},
			wantHas: true,
		},
		{
			name:    "v6 only",
			lookup:  "v6only",
			wantV6:  []string{"2001:db8::1"},
			wantHas: true,
		},
		{
			name:    "a line whose address does not parse is skipped",
			lookup:  "bogus",
			wantHas: false,
		},
		{
			name:    "a name absent from the file",
			lookup:  "nowhere.home.arpa",
			wantHas: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := entries.Has(testCase.lookup); got != testCase.wantHas {
				t.Errorf("%s: Has = %v, want %v", testCase.name, got, testCase.wantHas)
			}
			assertIPs(t, testCase.name+" (A)", entries.LookupA(testCase.lookup), testCase.wantV4)
			assertIPs(t, testCase.name+" (AAAA)", entries.LookupAAAA(testCase.lookup), testCase.wantV6)
		})
	}
}

func assertIPs(t *testing.T, name string, got []net.IP, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %d addresses (%v), want %d (%v)", name, len(got), got, len(want), want)
		return
	}
	for i, w := range want {
		if !got[i].Equal(net.ParseIP(w)) {
			t.Errorf("%s: address %d = %v, want %v", name, i, got[i], w)
		}
	}
}

// TestResolveNoDataForKnownName is the regression that motivated Has: a name
// present in the file with only an A record must answer NOERROR with an empty
// answer section when asked for AAAA, never fall through to the forwarder.
// Falling through produced NXDOMAIN for names that exist only locally, and
// glibc -- which asks for A and AAAA together -- then failed the whole lookup,
// so getent could not resolve a name that a direct A query returned fine.
func TestResolveNoDataForKnownName(t *testing.T) {
	t.Parallel()

	hosts := &Hosts{path: "test", ttl: DefaultTtl}
	hosts.entries.Store(parseTestEntries(t))

	testCases := []struct {
		name       string
		query      string
		qtype      uint16
		qclass     uint16
		wantNil    bool
		wantAnswer string
	}{
		{
			name:       "A for a v4 name",
			query:      "glory.home.arpa.",
			qtype:      dns.TypeA,
			wantAnswer: "192.168.1.1",
		},
		{
			name:    "AAAA for a v4-only name is NODATA, not a fall-through",
			query:   "glory.home.arpa.",
			qtype:   dns.TypeAAAA,
			wantNil: false,
		},
		{
			name:    "A for a v6-only name is NODATA",
			query:   "v6only.home.arpa.",
			qtype:   dns.TypeA,
			wantNil: false,
		},
		{
			name:       "AAAA for a v6 name",
			query:      "v6only.home.arpa.",
			qtype:      dns.TypeAAAA,
			wantAnswer: "2001:db8::1",
		},
		{
			name:    "another type on a known name is NODATA",
			query:   "glory.home.arpa.",
			qtype:   dns.TypeMX,
			wantNil: false,
		},
		{
			name:    "an unknown name falls through",
			query:   "nowhere.home.arpa.",
			qtype:   dns.TypeA,
			wantNil: true,
		},
		{
			name:    "a class other than IN falls through",
			query:   "glory.home.arpa.",
			qtype:   dns.TypeA,
			qclass:  dns.ClassCHAOS,
			wantNil: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			qclass := testCase.qclass
			if qclass == 0 {
				qclass = dns.ClassINET
			}
			request := new(dns.Msg)
			request.Question = []dns.Question{
				{Name: testCase.query, Qtype: testCase.qtype, Qclass: qclass},
			}

			response := hosts.Resolve(request)

			if testCase.wantNil {
				if response != nil {
					t.Fatalf("%s: got a response, want nil so the caller forwards", testCase.name)
				}
				return
			}
			if response == nil {
				t.Fatalf("%s: got nil, want an authoritative response", testCase.name)
			}
			if response.Rcode != dns.RcodeSuccess {
				t.Errorf("%s: rcode = %s, want NOERROR", testCase.name, dns.RcodeToString[response.Rcode])
			}
			if !response.Authoritative {
				t.Errorf("%s: response is not authoritative", testCase.name)
			}

			if testCase.wantAnswer == "" {
				if len(response.Answer) != 0 {
					t.Errorf("%s: got %d answers, want NODATA", testCase.name, len(response.Answer))
				}
				return
			}
			if len(response.Answer) != 1 {
				t.Fatalf("%s: got %d answers, want 1", testCase.name, len(response.Answer))
			}
			var got net.IP
			switch record := response.Answer[0].(type) {
			case *dns.A:
				got = record.A
			case *dns.AAAA:
				got = record.AAAA
			default:
				t.Fatalf("%s: unexpected record type %T", testCase.name, record)
			}
			if !got.Equal(net.ParseIP(testCase.wantAnswer)) {
				t.Errorf("%s: answer = %v, want %v", testCase.name, got, testCase.wantAnswer)
			}
		})
	}
}

func TestResolveNilReceiverAndEmptyQuestion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		hosts   *Hosts
		request *dns.Msg
	}{
		{name: "nil receiver", hosts: nil, request: new(dns.Msg)},
		{name: "nil request", hosts: &Hosts{}, request: nil},
		{name: "no question", hosts: &Hosts{}, request: new(dns.Msg)},
		{
			name:  "entries never loaded",
			hosts: &Hosts{},
			request: &dns.Msg{Question: []dns.Question{
				{Name: "glory.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.hosts.Resolve(testCase.request); got != nil {
				t.Errorf("%s: got %v, want nil", testCase.name, got)
			}
		})
	}
}

// TestLoopbackNames covers the check behind the reload warning. The case that
// matters is the stock "127.0.1.1 <hostname>" line: harmless on a workstation,
// but this hosts file is served to the whole network, so it tells every client
// that the router is themselves.
func TestLoopbackNames(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		hosts string
		want  []string
	}{
		{
			name:  "the stock local hostname line is reported",
			hosts: "127.0.1.1 glory\n192.168.1.1 dns.home.arpa\n",
			want:  []string{"glory"},
		},
		{
			name:  "localhost itself is exempt",
			hosts: "127.0.0.1 localhost\n::1 localhost\n",
			want:  nil,
		},
		{
			name:  "the localhost special-use names are exempt",
			hosts: "127.0.0.1 localhost localhost.localdomain foo.localhost\n",
			want:  nil,
		},
		{
			name:  "an IPv6 loopback is reported too",
			hosts: "::1 glory\n",
			want:  []string{"glory"},
		},
		{
			name:  "every alias on the line is reported, sorted",
			hosts: "127.0.1.1 zeta alpha\n",
			want:  []string{"alpha", "zeta"},
		},
		{
			name:  "a name reported once even with both families",
			hosts: "127.0.1.1 glory\n::1 glory\n",
			want:  []string{"glory"},
		},
		{
			name:  "routable addresses are not reported",
			hosts: "192.168.1.1 glory\n10.5.2.2 clamps\n",
			want:  nil,
		},
		{
			name:  "a name with both a loopback and a routable address is still reported",
			hosts: "127.0.1.1 glory\n192.168.1.1 glory\n",
			want:  []string{"glory"},
		},
		{
			name:  "an empty file reports nothing",
			hosts: "",
			want:  nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			entries, err := ParseReader(strings.NewReader(testCase.hosts))
			if err != nil {
				t.Fatalf("%s: ParseReader: %v", testCase.name, err)
			}
			got := entries.LoopbackNames()
			if len(got) != len(testCase.want) {
				t.Fatalf("%s: got %v, want %v", testCase.name, got, testCase.want)
			}
			for i := range got {
				if got[i] != testCase.want[i] {
					t.Errorf("%s: got %v, want %v", testCase.name, got, testCase.want)
					break
				}
			}
		})
	}
}

func TestEntriesNilReceiver(t *testing.T) {
	t.Parallel()

	var entries *Entries
	if entries.LookupA("glory") != nil {
		t.Error("LookupA on a nil Entries should return nil")
	}
	if entries.LookupAAAA("glory") != nil {
		t.Error("LookupAAAA on a nil Entries should return nil")
	}
	if entries.Has("glory") {
		t.Error("Has on a nil Entries should return false")
	}
	if entries.LoopbackNames() != nil {
		t.Error("LoopbackNames on a nil Entries should return nil")
	}
}
