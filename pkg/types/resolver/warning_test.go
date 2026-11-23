package resolver

import (
	"dns_resolver/pkg/types/resolver_config"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type logEvent struct {
	Event struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	} `json:"event"`
	Client struct {
		Ip string `json:"ip"`
	} `json:"client"`
	Dns struct {
		Question struct {
			Name string `json:"name"`
		} `json:"question"`
	} `json:"dns"`
	RateLimit struct {
		Suppressed int `json:"suppressed"`
	} `json:"rate_limit"`
}

// warnings returns the logged events whose reason contains reason.
func warnings(t *testing.T, sink *lockedBuffer, reason string) []logEvent {
	t.Helper()
	var events []logEvent
	for _, line := range sink.lines() {
		if line == "" {
			continue
		}
		var event logEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode log line: %v: %s", err, line)
		}
		if strings.Contains(event.Event.Reason, reason) {
			events = append(events, event)
		}
	}
	return events
}

// A rejected request is warned of with who asked and what, and one client's
// rejections at most once per interval, with a count of those held back. The
// overload and opcode warnings carried neither the client nor the question,
// and a flood of rejections was a flood of warnings.
//
//nolint:paralleltest // It swaps the default logger.
func TestServeDNS_RejectionWarnings(t *testing.T) {
	sink := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(productionLogger(sink))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const overloadReason = "The limit on requests waiting on the upstream was reached."
	const opcodeReason = "The request's opcode is not supported."

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
		resolver_config.WithRequestTimeout(3*time.Second),
	)
	clock := &fakeClock{now: time.Unix(1_000_000, 0)}
	resolver.rejectionWarnings.now = clock.Now

	slow := make(chan *dns.Msg, 1)
	go func() { slow <- askFrom(resolver, "udp", "192.0.2.50:1000", newQuery("slow.example.", dns.TypeA)) }()
	waitFor(t, "the slow query to reach the upstream", func() bool { return upstream.receivedFor("slow.example.") > 0 })

	notify := newQuery("zone.example.", dns.TypeSOA)
	notify.Opcode = dns.OpcodeNotify

	testCases := []struct {
		name    string
		advance time.Duration
		remote  string
		request *dns.Msg
		times   int
		reason  string
		// wantEvents is how many warnings with reason there are after the
		// step, all told; the last of them is checked against the rest.
		wantEvents     int
		wantClient     string
		wantQuestion   string
		wantSuppressed int
	}{
		{
			name:         "overload names the client and question",
			remote:       "192.0.2.7:4000",
			request:      newQuery("first.example.", dns.TypeA),
			times:        1,
			reason:       overloadReason,
			wantEvents:   1,
			wantClient:   "192.0.2.7",
			wantQuestion: "first.example",
		},
		{
			name:         "repeats within the interval are held back",
			remote:       "192.0.2.7:4001",
			request:      newQuery("again.example.", dns.TypeA),
			times:        4,
			reason:       overloadReason,
			wantEvents:   1,
			wantClient:   "192.0.2.7",
			wantQuestion: "first.example",
		},
		{
			name:         "another client is warned of on its own",
			remote:       "192.0.2.8:4000",
			request:      newQuery("other.example.", dns.TypeA),
			times:        1,
			reason:       overloadReason,
			wantEvents:   2,
			wantClient:   "192.0.2.8",
			wantQuestion: "other.example",
		},
		{
			name:           "after the interval the held back are counted",
			advance:        defaultWarningInterval,
			remote:         "192.0.2.7:4002",
			request:        newQuery("later.example.", dns.TypeA),
			times:          1,
			reason:         overloadReason,
			wantEvents:     3,
			wantClient:     "192.0.2.7",
			wantQuestion:   "later.example",
			wantSuppressed: 4,
		},
		{
			name:         "unsupported opcode names the client and question",
			remote:       "192.0.2.9:4000",
			request:      notify,
			times:        3,
			reason:       opcodeReason,
			wantEvents:   1,
			wantClient:   "192.0.2.9",
			wantQuestion: "zone.example",
		},
	}

	// The cases build on the warnings of those before them, so they run in
	// turn.
	//nolint:paralleltest // See above.
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			clock.now = clock.now.Add(testCase.advance)
			for range testCase.times {
				if reply := askFrom(resolver, "udp", testCase.remote, testCase.request); reply == nil {
					t.Fatal("no reply")
				}
			}

			events := warnings(t, sink, testCase.reason)
			if len(events) != testCase.wantEvents {
				t.Fatalf("%d warnings logged; want %d", len(events), testCase.wantEvents)
			}
			last := events[len(events)-1]
			if last.Client.Ip != testCase.wantClient || last.Dns.Question.Name != testCase.wantQuestion {
				t.Fatalf("warning names client %q and question %q; want %q and %q", last.Client.Ip, last.Dns.Question.Name, testCase.wantClient, testCase.wantQuestion)
			}
			if last.RateLimit.Suppressed != testCase.wantSuppressed {
				t.Fatalf("warning counts %d held back; want %d", last.RateLimit.Suppressed, testCase.wantSuppressed)
			}
		})
	}

	<-slow
}
