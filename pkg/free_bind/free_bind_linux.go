//go:build linux

// Package free_bind lets a listener bind to an address no interface has yet.
package free_bind

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Control is a net.ListenConfig Control that sets IP_FREEBIND (IPV6_FREEBIND
// for an IPv6 socket), so that a listener for an interface that comes up later
// binds now and receives once the interface does, rather than failing.
func Control(network string, _ string, rawConn syscall.RawConn) error {
	level, option := unix.IPPROTO_IP, unix.IP_FREEBIND
	if strings.HasSuffix(network, "6") {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_FREEBIND
	}

	var setErr error
	if err := rawConn.Control(func(descriptor uintptr) {
		setErr = unix.SetsockoptInt(int(descriptor), level, option, 1)
	}); err != nil {
		return fmt.Errorf("raw conn control: %w", err)
	}
	if setErr != nil {
		return fmt.Errorf("unix setsockopt int (free bind, %s): %w", network, setErr)
	}

	return nil
}
