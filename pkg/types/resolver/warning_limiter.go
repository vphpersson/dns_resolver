package resolver

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// defaultWarningInterval is how often one client's rejections are
	// warned of.
	defaultWarningInterval = 10 * time.Second
	// maxWarningKeys bounds the clients a warningLimiter keeps track of;
	// beyond it, the ones not yet tracked share one key.
	maxWarningKeys = 1024
	overflowKey    = "*"
)

// warningLimiter lets one warning per key through per interval and counts the
// ones it holds back, so that a flood of rejected requests does not become a
// flood of log lines as well.
type warningLimiter struct {
	mutex    sync.Mutex
	interval time.Duration
	now      func() time.Time
	entries  map[string]*warningEntry
}

type warningEntry struct {
	last       time.Time
	suppressed int
}

func newWarningLimiter(interval time.Duration) *warningLimiter {
	return &warningLimiter{interval: interval, now: time.Now, entries: make(map[string]*warningEntry)}
}

// allow reports whether a warning for key may be written now and, if so, how
// many for the key were held back since the last one written.
func (l *warningLimiter) allow(key string) (bool, int) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	now := l.now()

	entry, ok := l.entries[key]
	if !ok && len(l.entries) >= maxWarningKeys {
		l.prune(now)
		if len(l.entries) >= maxWarningKeys {
			key = overflowKey
			entry, ok = l.entries[key]
		}
	}
	if !ok {
		l.entries[key] = &warningEntry{last: now}
		return true, 0
	}

	if now.Sub(entry.last) < l.interval {
		entry.suppressed++
		return false, 0
	}
	suppressed := entry.suppressed
	entry.last = now
	entry.suppressed = 0
	return true, suppressed
}

// prune forgets the keys last warned of an interval or more ago. The caller
// holds the mutex.
func (l *warningLimiter) prune(now time.Time) {
	for key, entry := range l.entries {
		if now.Sub(entry.last) >= l.interval {
			delete(l.entries, key)
		}
	}
}

// clientAddress is the IP address a request came from, or the zero Addr when
// it cannot be told.
func clientAddress(remoteAddr net.Addr) netip.Addr {
	if remoteAddr == nil {
		return netip.Addr{}
	}
	if addrPort, err := netip.ParseAddrPort(remoteAddr.String()); err == nil {
		return addrPort.Addr().Unmap()
	}
	if addr, err := netip.ParseAddr(remoteAddr.String()); err == nil {
		return addr.Unmap()
	}
	return netip.Addr{}
}
