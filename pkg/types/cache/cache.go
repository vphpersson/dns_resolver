package cache

import (
	"context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	"github.com/miekg/dns"
	"sync"
	"time"
)

type Key struct {
	Name   string
	Qtype  uint16
	Qclass uint16
	DO     bool
}

type Entry struct {
	Msg        *dns.Msg
	Expiration time.Time
}

type Cache struct {
	sync.RWMutex
	entries map[Key]*Entry
}

func New() *Cache {
	return &Cache{entries: make(map[Key]*Entry)}
}

func (c *Cache) Get(key Key) (*dns.Msg, bool, time.Duration) {
	c.RLock()
	entry, ok := c.entries[key]
	c.RUnlock()
	if !ok {
		return nil, false, 0
	}

	remainingTtl := time.Until(entry.Expiration)
	if remainingTtl <= 0 {
		c.Lock()
		// Only delete if the entry in the map is still the expired one we
		// observed; otherwise a concurrent Set may have replaced it.
		if cur := c.entries[key]; cur == entry {
			delete(c.entries, key)
		}
		c.Unlock()

		return nil, false, 0
	}

	return entry.Msg, true, remainingTtl
}

func (c *Cache) Set(key Key, message *dns.Msg, expirationReference *time.Time) bool {
	if message == nil {
		return false
	}

	if expirationReference == nil {
		t := time.Now()
		expirationReference = &t
	}

	if message.Truncated {
		return false
	}

	ttl := dns_utils.EffectiveMessageTtl(message)
	if ttl == 0 {
		return false
	}

	c.Lock()
	defer c.Unlock()
	c.entries[key] = &Entry{Msg: message, Expiration: expirationReference.Add(ttl)}

	return true
}

// sweep removes expired entries. The scan phase uses an RLock so concurrent
// readers are not blocked; the delete phase takes a write lock only if any
// expired keys were found.
func (c *Cache) sweep() {
	now := time.Now()

	var expired []Key
	c.RLock()
	for k, e := range c.entries {
		if now.After(e.Expiration) {
			expired = append(expired, k)
		}
	}
	c.RUnlock()

	if len(expired) == 0 {
		return
	}

	c.Lock()
	for _, k := range expired {
		// Re-check under the write lock: a concurrent Set may have replaced
		// the entry with a fresh one between the two phases.
		if e, ok := c.entries[k]; ok && now.After(e.Expiration) {
			delete(c.entries, k)
		}
	}
	c.Unlock()
}

func (c *Cache) StartJanitor(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			select {
			case <-ctx.Done():
				return
			default:
				c.sweep()
			}
		}
	}
}
