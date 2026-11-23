package resolver

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func TestWarningLimiter(t *testing.T) {
	t.Parallel()

	const interval = 10 * time.Second

	type step struct {
		advance        time.Duration
		key            string
		wantAllowed    bool
		wantSuppressed int
	}

	testCases := []struct {
		name  string
		steps []step
	}{
		{
			name: "first warning passes",
			steps: []step{
				{key: "a", wantAllowed: true},
			},
		},
		{
			name: "repeats held back, then counted",
			steps: []step{
				{key: "a", wantAllowed: true},
				{advance: time.Second, key: "a"},
				{advance: time.Second, key: "a"},
				{advance: time.Second, key: "a"},
				{advance: interval, key: "a", wantAllowed: true, wantSuppressed: 3},
				{key: "a"},
			},
		},
		{
			name: "keys are apart",
			steps: []step{
				{key: "a", wantAllowed: true},
				{key: "b", wantAllowed: true},
				{key: "a"},
				{key: "b"},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			clock := &fakeClock{now: time.Unix(1_000_000, 0)}
			limiter := newWarningLimiter(interval)
			limiter.now = clock.Now

			for i, step := range testCase.steps {
				clock.now = clock.now.Add(step.advance)
				allowed, suppressed := limiter.allow(step.key)
				if allowed != step.wantAllowed || suppressed != step.wantSuppressed {
					t.Fatalf("step %d: allow(%q) = %t, %d; want %t, %d", i, step.key, allowed, suppressed, step.wantAllowed, step.wantSuppressed)
				}
			}
		})
	}
}

// Past maxWarningKeys, untracked keys share one, so a client spoofing many
// addresses cannot grow the limiter without bound.
func TestWarningLimiter_Bounded(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: time.Unix(1_000_000, 0)}
	limiter := newWarningLimiter(time.Minute)
	limiter.now = clock.Now

	for i := range maxWarningKeys {
		if allowed, _ := limiter.allow(fmt.Sprintf("client%d", i)); !allowed {
			t.Fatalf("client%d's first warning was held back", i)
		}
	}
	if allowed, _ := limiter.allow("one more"); !allowed {
		t.Fatal("the first key past the bound was held back; it should share the overflow key's first warning")
	}
	if allowed, _ := limiter.allow("and another"); allowed {
		t.Fatal("a second key past the bound got its own warning")
	}
	if entries := len(limiter.entries); entries > maxWarningKeys+1 {
		t.Fatalf("limiter tracks %d keys; want at most %d", entries, maxWarningKeys+1)
	}

	// Once the tracked keys are stale, a new key is tracked on its own.
	clock.now = clock.now.Add(time.Minute)
	if allowed, _ := limiter.allow("later"); !allowed {
		t.Fatal("a new key after the others went stale was held back")
	}
	if entries := len(limiter.entries); entries != 1 {
		t.Fatalf("limiter tracks %d keys after pruning; want 1", entries)
	}
}

func TestClientAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		addr net.Addr
		want netip.Addr
	}{
		{name: "udp v4", addr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 5353}, want: netip.MustParseAddr("192.168.1.10")},
		{name: "tcp v6", addr: &net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 53}, want: netip.MustParseAddr("fd00::1")},
		{name: "v4-mapped", addr: &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1}, want: netip.MustParseAddr("192.0.2.1")},
		{name: "nil", addr: nil, want: netip.Addr{}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := clientAddress(testCase.addr); got != testCase.want {
				t.Fatalf("clientAddress(%v) = %v; want %v", testCase.addr, got, testCase.want)
			}
		})
	}
}
