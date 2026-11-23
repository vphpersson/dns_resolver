//go:build !linux

// Package free_bind lets a listener bind to an address no interface has yet.
package free_bind

import "syscall"

// Control does nothing where there is no IP_FREEBIND: a listener for an address
// no interface has yet fails to bind there.
func Control(string, string, syscall.RawConn) error {
	return nil
}
