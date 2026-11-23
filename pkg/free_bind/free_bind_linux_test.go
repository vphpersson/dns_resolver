//go:build linux

package free_bind

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestControl(t *testing.T) {
	t.Parallel()

	// Documentation addresses (RFC 5737, RFC 3849), which no interface here has.
	testCases := []struct {
		name    string
		network string
		address string
	}{
		{name: "udp on an ipv4 address no interface has", network: "udp", address: "192.0.2.53:0"},
		{name: "tcp on an ipv4 address no interface has", network: "tcp", address: "192.0.2.53:0"},
		{name: "udp on an ipv6 address no interface has", network: "udp", address: "[2001:db8::53]:0"},
		{name: "tcp on an ipv6 address no interface has", network: "tcp", address: "[2001:db8::53]:0"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// Without free binding the address must be refused here, or the case
			// shows nothing.
			err := bind(&net.ListenConfig{}, testCase.network, testCase.address)
			if err == nil {
				t.Skipf("%s is bound without free binding here", testCase.address)
			}
			if !errors.Is(err, syscall.EADDRNOTAVAIL) {
				t.Skipf("%s cannot be bound here for another reason: %v", testCase.address, err)
			}

			if err := bind(&net.ListenConfig{Control: Control}, testCase.network, testCase.address); err != nil {
				t.Fatalf("bind with free binding: %v", err)
			}
		})
	}
}

// bind binds address with listenConfig and closes it again.
func bind(listenConfig *net.ListenConfig, network string, address string) error {
	if network == "udp" {
		packetConn, err := listenConfig.ListenPacket(context.Background(), network, address)
		if err != nil {
			return err
		}
		return packetConn.Close()
	}

	listener, err := listenConfig.Listen(context.Background(), network, address)
	if err != nil {
		return err
	}
	return listener.Close()
}
