package cache

import (
	"context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	"github.com/miekg/dns"
	"sync"
	"time"
)

type Entry struct {
	Msg        *dns.Msg
	Expiration time.Time
}

type Cache struct {
	sync.RWMutex
	ctx     context.Context
	entries map[string]*Entry
}

func New(ctx context.Context) *Cache {
	return &Cache{ctx: ctx, entries: make(map[string]*Entry)}
}

func (c *Cache) Get(key string) (*dns.Msg, bool, time.Duration) {
	c.RLock()
	entry, ok := c.entries[key]
	c.RUnlock()
	if !ok {
		return nil, false, 0
	}

	remainingTtl := time.Until(entry.Expiration)
	if remainingTtl <= 0 {
		c.Lock()
		defer c.Unlock()
		delete(c.entries, key)

		return nil, false, 0
	}

	return entry.Msg, true, remainingTtl
}

func (c *Cache) Set(key string, message *dns.Msg, expirationReference *time.Time) bool {
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
