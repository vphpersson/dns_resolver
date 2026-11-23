package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseDuration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		value     string
		allowZero bool
		want      time.Duration
		// wantErr is the error expected; fails marks a failure of any kind.
		wantErr error
		fails   bool
	}{
		{name: "positive", value: "4s", want: 4 * time.Second},
		{name: "zero allowed", value: "0", allowZero: true, want: 0},
		{name: "zero refused", value: "0s", wantErr: errNonPositiveDuration},
		{name: "negative", value: "-1s", allowZero: true, wantErr: errNegativeDuration},
		{name: "malformed", value: "soon", allowZero: true, fails: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseDuration(testCase.value, testCase.allowZero)
			if testCase.fails {
				if err == nil {
					t.Fatalf("parseDuration(%q) succeeded; want an error", testCase.value)
				}
				return
			}
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("parseDuration(%q) error = %v; want %v", testCase.value, err, testCase.wantErr)
			}
			if got != testCase.want {
				t.Fatalf("parseDuration(%q) = %s; want %s", testCase.value, got, testCase.want)
			}
		})
	}
}

// exchangeOn sends a query on connection and waits up to timeout for the reply.
func exchangeOn(connection net.Conn, timeout time.Duration) error {
	query := new(dns.Msg)
	query.SetQuestion("example.", dns.TypeA)
	dnsConnection := &dns.Conn{Conn: connection}
	if err := dnsConnection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := dnsConnection.WriteMsg(query); err != nil {
		return err
	}
	_, err := dnsConnection.ReadMsg()
	return err
}

// The TCP listener serves a bounded number of connections at once; one over
// the bound waits for a free slot. Each connection used to be accepted
// whatever the count, holding a goroutine and a descriptor for as long as its
// client kept it open.
func TestNewDnsServer_TcpConnectionLimit(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		maxTcpConnections int
		wantSecondServed  bool
	}{
		{name: "at the limit", maxTcpConnections: 1, wantSecondServed: false},
		{name: "below the limit", maxTcpConnections: 2, wantSecondServed: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
				reply := new(dns.Msg)
				reply.SetReply(request)
				_ = writer.WriteMsg(reply)
			})
			server, err := newDnsServer(t.Context(), "127.0.0.1:0", "tcp", handler, testCase.maxTcpConnections)
			if err != nil {
				t.Fatalf("new dns server: %v", err)
			}
			started := make(chan struct{})
			server.NotifyStartedFunc = func() { close(started) }
			go func() { _ = serve(server) }()
			<-started
			t.Cleanup(func() { _ = server.Shutdown() })

			address := server.Listener.Addr().String()

			var dialer net.Dialer
			first, err := dialer.DialContext(t.Context(), "tcp", address)
			if err != nil {
				t.Fatalf("dial first: %v", err)
			}
			defer first.Close()
			if err := exchangeOn(first, 2*time.Second); err != nil {
				t.Fatalf("first connection not served: %v", err)
			}

			second, err := dialer.DialContext(t.Context(), "tcp", address)
			if err != nil {
				t.Fatalf("dial second: %v", err)
			}
			defer second.Close()

			err = exchangeOn(second, 300*time.Millisecond)
			if served := err == nil; served != testCase.wantSecondServed {
				t.Fatalf("second connection served while the first was open = %t (%v); want %t", served, err, testCase.wantSecondServed)
			}
			if testCase.wantSecondServed {
				return
			}

			// Closing the first frees its slot, and the waiting connection is
			// then served.
			_ = first.Close()
			dnsSecond := &dns.Conn{Conn: second}
			if err := dnsSecond.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			if _, err := dnsSecond.ReadMsg(); err != nil {
				t.Fatalf("second connection not served after the first closed: %v", err)
			}
		})
	}
}

// answerAll answers every query with an empty reply.
func answerAll() dns.Handler {
	return dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		_ = writer.WriteMsg(reply)
	})
}

// freeAddress returns a loopback address whose port was free for both UDP and
// TCP a moment ago, as serveDns binds both: a port free for UDP alone may be
// held on TCP, by a client connection of a test running alongside.
func freeAddress(t *testing.T) string {
	t.Helper()

	var listenConfig net.ListenConfig
	for range 20 {
		listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		listenerAddr := listener.Addr()
		if listenerAddr == nil {
			t.Fatal("listener has no address")
		}
		address := listenerAddr.String()

		packetConn, err := listenConfig.ListenPacket(t.Context(), "udp", address)
		_ = listener.Close()
		if err != nil {
			continue
		}
		_ = packetConn.Close()
		return address
	}

	t.Fatal("found no port free for both udp and tcp")
	return ""
}

// localAddress returns the address packetConn is bound to.
func localAddress(t *testing.T, packetConn net.PacketConn) string {
	t.Helper()

	localAddr := packetConn.LocalAddr()
	if localAddr == nil {
		t.Fatal("packet conn has no local address")
	}
	return localAddr.String()
}

// waitForServeDns waits for serveDns to return, failing the test if it has not
// within the time given.
func waitForServeDns(t *testing.T, done <-chan error, within time.Duration) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(within):
		t.Fatalf("serveDns had not returned after %s", within)
		return nil
	}
}

// A server that fails ends every other one, so the process exits and is
// started again. The others used to go on serving, with a context that had
// ended, so that every query forwarded upstream was answered with SERVFAIL and
// nothing restarted the process.
func TestServeDns_FailureEndsEveryServer(t *testing.T) {
	t.Parallel()

	var listenConfig net.ListenConfig
	busy, err := listenConfig.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	defer busy.Close()

	addresses := []string{freeAddress(t), localAddress(t, busy)}
	done := make(chan error, 1)
	go func() { done <- serveDns(t.Context(), addresses, answerAll(), 4) }()

	err = waitForServeDns(t, done, 5*time.Second)
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("error %v, want %v", err, syscall.EADDRINUSE)
	}
}

// When the context ends, the servers stop, those already serving as well as
// those not started yet, and that is no failure.
func TestServeDns_ContextEndStopsServers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		serveFirst bool
	}{
		{name: "before the servers start"},
		{name: "while the servers answer", serveFirst: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			address := freeAddress(t)
			done := make(chan error, 1)
			if !testCase.serveFirst {
				cancel()
			}
			go func() { done <- serveDns(ctx, []string{address}, answerAll(), 4) }()

			if testCase.serveFirst {
				query := new(dns.Msg)
				query.SetQuestion("example.", dns.TypeA)
				client := &dns.Client{Net: "udp", Timeout: 200 * time.Millisecond}
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, _, err := client.Exchange(query, address); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("the server never answered")
					}
				}
				cancel()
			}

			if err := waitForServeDns(t, done, 5*time.Second); err != nil {
				t.Fatalf("error %v, want none", err)
			}
		})
	}
}

// Ending the servers ends the TCP connections they had accepted too. Closing
// only the listening socket left an open connection served until its client
// went: an idle one held the exit for the idle timeout, and one that kept
// querying for as long as it did.
func TestServeDns_OpenTcpConnectionDoesNotHoldTheExit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	address := freeAddress(t)
	done := make(chan error, 1)
	go func() { done <- serveDns(ctx, []string{address}, answerAll(), 4) }()

	var dialer net.Dialer
	var connection net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		var err error
		connection, err = dialer.DialContext(t.Context(), "tcp", address)
		if err == nil {
			err = exchangeOn(connection, 500*time.Millisecond)
			if err == nil {
				break
			}
			_ = connection.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("the tcp server never answered: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer connection.Close()

	cancel()
	if err := waitForServeDns(t, done, dnsTcpIdleTimeout/4); err != nil {
		t.Fatalf("error %v, want none", err)
	}
}

func TestCollectInterfaceAddresses(t *testing.T) {
	t.Parallel()

	interfaces, err := collectInterfaceAddresses()
	if err != nil {
		t.Fatalf("collect interface addresses: %v", err)
	}

	loopback := netip.MustParseAddr("127.0.0.1")
	for _, networkInterface := range interfaces {
		if slices.Contains(networkInterface.addresses, loopback) {
			if networkInterface.name == "" || networkInterface.index == 0 {
				t.Errorf("loopback interface without a name or index: %+v", networkInterface)
			}
			return
		}
	}
	t.Errorf("no interface has %s: %+v", loopback, interfaces)
}

func TestUnassignedAddresses(t *testing.T) {
	t.Parallel()

	interfaces := []*interfaceAddresses{
		{name: "lo", index: 1, addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}},
		{name: "eth0", index: 2, addresses: []netip.Addr{netip.MustParseAddr("192.168.2.1"), netip.MustParseAddr("fe80::1")}},
		{name: "eth1", index: 3},
	}

	testCases := []struct {
		name          string
		listenAddress string
		wantReported  bool
	}{
		{name: "an address an interface has", listenAddress: "192.168.2.1:53"},
		{name: "loopback", listenAddress: "127.0.0.1:53"},
		{name: "ipv6 loopback", listenAddress: "[::1]:53"},
		{name: "an ipv4-mapped address an interface has", listenAddress: "[::ffff:192.168.2.1]:53"},
		{name: "a link-local address on the interface its zone names", listenAddress: "[fe80::1%eth0]:53"},
		{name: "a link-local address on the interface its zone numbers", listenAddress: "[fe80::1%2]:53"},
		{name: "a link-local address on another interface than its zone names", listenAddress: "[fe80::1%eth1]:53", wantReported: true},
		{name: "a link-local address on another interface than its zone numbers", listenAddress: "[fe80::1%3]:53", wantReported: true},
		{name: "an address no interface has", listenAddress: "192.168.3.1:53", wantReported: true},
		{name: "another address in an interface's subnet", listenAddress: "192.168.2.7:53", wantReported: true},
		{name: "an ipv6 address no interface has", listenAddress: "[2001:db8::53]:53", wantReported: true},
		{name: "the ipv4 wildcard", listenAddress: "0.0.0.0:53"},
		{name: "the ipv6 wildcard", listenAddress: "[::]:53"},
		{name: "no host", listenAddress: ":53"},
		{name: "a name rather than an address", listenAddress: "localhost:53"},
		{name: "no port", listenAddress: "192.168.3.1"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			reported := len(unassignedAddresses([]string{testCase.listenAddress}, interfaces)) == 1
			if reported != testCase.wantReported {
				t.Errorf("reported %t, want %t", reported, testCase.wantReported)
			}
		})
	}
}

// Every listener is opened with free binding, so an address whose interface is
// not up yet binds rather than failing the start.
func TestNewDnsServer_FreeBind(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skip("free binding is Linux's")
	}

	// A documentation address (RFC 5737), which no interface here has.
	const address = "192.0.2.53:0"

	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			t.Parallel()

			// Without free binding the address must be refused here, or the case
			// shows nothing.
			err := plainBind(t.Context(), network, address)
			if err == nil {
				t.Skipf("%s is bound without free binding here", address)
			}
			if !errors.Is(err, syscall.EADDRNOTAVAIL) {
				t.Skipf("%s cannot be bound here for another reason: %v", address, err)
			}

			if _, err := newDnsServer(t.Context(), address, network, answerAll(), 1); err != nil {
				t.Fatalf("new dns server: %v", err)
			}
		})
	}
}

// plainBind binds address without free binding and closes it again.
func plainBind(ctx context.Context, network string, address string) error {
	var listenConfig net.ListenConfig
	if network == "udp" {
		packetConn, err := listenConfig.ListenPacket(ctx, network, address)
		if err != nil {
			return err
		}
		return packetConn.Close()
	}

	listener, err := listenConfig.Listen(ctx, network, address)
	if err != nil {
		return err
	}
	return listener.Close()
}
