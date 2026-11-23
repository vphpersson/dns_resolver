package main

import (
	"errors"
	"net"
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
			server, err := newDnsServer("127.0.0.1:0", "tcp", handler, testCase.maxTcpConnections)
			if err != nil {
				t.Fatalf("new dns server: %v", err)
			}
			started := make(chan struct{})
			server.NotifyStartedFunc = func() { close(started) }
			go func() { _ = serve(server) }()
			<-started
			t.Cleanup(func() { _ = server.Shutdown() })

			address := server.Listener.Addr().String()

			first, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatalf("dial first: %v", err)
			}
			defer first.Close()
			if err := exchangeOn(first, 2*time.Second); err != nil {
				t.Fatalf("first connection not served: %v", err)
			}

			second, err := net.Dial("tcp", address)
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
