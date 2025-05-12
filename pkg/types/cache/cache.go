package cache

import (
	"context"
	"github.com/miekg/dns"
	"sync"
	"time"
)

const max32 = ^uint32(0)

type Entry struct {
	Msg        *dns.Msg
	Expiration time.Time
}

type Cache struct {
	sync.RWMutex
	ctx     context.Context
	entries map[string]*Entry
}

// New initialises the map and starts an optional sweeper.
func New(ctx context.Context) *Cache {
	return &Cache{ctx: ctx, entries: make(map[string]*Entry)}
}

// Get returns a *copy* whose TTLs are already aged down.
func (c *Cache) Get(key string) (*dns.Msg, bool) {
	c.RLock()
	entry, ok := c.entries[key]
	c.RUnlock()
	if !ok {
		return nil, false
	}

	remain := time.Until(entry.Expiration)
	if remain <= 0 {
		c.Lock()
		defer c.Unlock()
		delete(c.entries, key)

		return nil, false
	}

	out := entry.Msg.Copy()
	applyRemainingTTL(out, uint32(remain.Seconds()))
	return out, true
}

// Set stores a deep copy and records when it must expire.
func (c *Cache) Set(key string, msg *dns.Msg) {
	if msg.Truncated {
		return
	}

	ttl := effectiveTTL(msg)
	if ttl == 0 {
		return
	}

	c.Lock()
	defer c.Unlock()
	// TODO: Don't use `time.Now()`? Obtain from somewhere else?
	c.entries[key] = &Entry{Msg: msg.Copy(), Expiration: time.Now().Add(ttl)}
}

func (c *Cache) StartJanitor(every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			select {
			case <-c.ctx.Done():
				return
			default:
				now := time.Now()
				c.Lock()
				for k, e := range c.entries {
					if now.After(e.Expiration) {
						delete(c.entries, k)
					}
				}
				c.Unlock()
			}
		}
	}
}

// --------------------------------------------------------------
// Helper functions

// effectiveTTL returns the minimum TTL across Answer, Ns & Extra.
// Includes RFC 2308 negative-cache logic.
func effectiveTTL(m *dns.Msg) time.Duration {
	minValue := max32
	sweep := func(resourceRecords []dns.RR) {
		for _, resourceRecord := range resourceRecords {
			switch resourceRecord.(type) {
			case *dns.OPT, *dns.TSIG, *dns.SIG:
				continue
			default:
				ttl := resourceRecord.Header().Ttl
				if ttl < minValue {
					minValue = ttl
				}
			}
		}
	}
	sweep(m.Answer)
	sweep(m.Ns)
	sweep(m.Extra)

	// NXDOMAIN / NODATA – use SOA.MINIMUM if smaller
	if m.Rcode == dns.RcodeNameError || len(m.Answer) == 0 {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < minValue {
				minValue = soa.Minttl
			}
		}
	}

	return time.Duration(minValue) * time.Second
}

// applyRemainingTTL rewrites every RR TTL to the remaining seconds.
func applyRemainingTTL(m *dns.Msg, secs uint32) {
	update := func(rrs []dns.RR) {
		for _, rr := range rrs {
			rr.Header().Ttl = secs
		}
	}
	update(m.Answer)
	update(m.Ns)
	update(m.Extra)
}
