package cache

import (
	"context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	"github.com/miekg/dns"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxCacheTtl bounds how long any single entry may live. It defends against an
// unbounded effective TTL: EffectiveMessageTtl falls back to the uint32 max
// (~136 years) when no record or SOA supplies a TTL, so without a cap a single
// odd response could pin a name effectively forever. 24h matches Unbound's
// cache-max-ttl default.
const maxCacheTtl = 24 * time.Hour

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

	hits       atomic.Uint64
	misses     atomic.Uint64
	evictions  atomic.Uint64
	insertions atomic.Uint64
	rejections atomic.Uint64
}

// Stats is a point-in-time snapshot of cache counters, suitable for the
// diagnostic /metrics endpoint. The counters are monotonic for the process
// lifetime; Entries is the live size.
type Stats struct {
	Entries    int    `json:"entries"`
	Hits       uint64 `json:"hits"`
	Misses     uint64 `json:"misses"`
	Evictions  uint64 `json:"evictions"`
	Insertions uint64 `json:"insertions"`
	Rejections uint64 `json:"rejections"`
}

// EntryInfo summarises a single cached entry for the diagnostic /cache
// listing. The full message is intentionally not exposed.
type EntryInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Class      string `json:"class"`
	DO         bool   `json:"do"`
	Rcode      string `json:"rcode"`
	Answers    int    `json:"answers"`
	RemainingS int    `json:"remaining_s"`
}

func New() *Cache {
	return &Cache{entries: make(map[Key]*Entry)}
}

func (c *Cache) Get(key Key) (*dns.Msg, bool, time.Duration) {
	c.RLock()
	entry, ok := c.entries[key]
	c.RUnlock()
	if !ok {
		c.misses.Add(1)
		return nil, false, 0
	}

	remainingTtl := time.Until(entry.Expiration)
	if remainingTtl <= 0 {
		c.Lock()
		// Only delete if the entry in the map is still the expired one we
		// observed; otherwise a concurrent Set may have replaced it.
		if cur := c.entries[key]; cur == entry {
			delete(c.entries, key)
			c.evictions.Add(1)
		}
		c.Unlock()

		c.misses.Add(1)
		return nil, false, 0
	}

	c.hits.Add(1)
	return entry.Msg, true, remainingTtl
}

func (c *Cache) Set(key Key, message *dns.Msg, expirationReference *time.Time) bool {
	if message == nil {
		return false
	}

	// Only cache authoritative results. NOERROR (positive answers and NODATA)
	// and NXDOMAIN are statements about the name and are safe to cache; their
	// TTL is bounded by the record TTLs or the negative-caching SOA MINIMUM.
	// SERVFAIL/REFUSED/etc. are transient failures, not answers: caching one
	// turns a momentary upstream or transport hiccup into a sticky, self-
	// perpetuating outage for the name (and, lacking any record or SOA to
	// derive a TTL from, it would otherwise be pinned for the ~136-year uint32
	// sentinel TTL). Re-query instead.
	switch message.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		c.rejections.Add(1)
		return false
	}

	if expirationReference == nil {
		t := time.Now()
		expirationReference = &t
	}

	if message.Truncated {
		c.rejections.Add(1)
		return false
	}

	ttl := dns_utils.EffectiveMessageTtl(message)
	if ttl <= 0 {
		c.rejections.Add(1)
		return false
	}
	if ttl > maxCacheTtl {
		ttl = maxCacheTtl
	}

	c.Lock()
	defer c.Unlock()
	c.entries[key] = &Entry{Msg: message, Expiration: expirationReference.Add(ttl)}

	c.insertions.Add(1)
	return true
}

// Stats returns a snapshot of the cache counters and current size.
func (c *Cache) Stats() Stats {
	c.RLock()
	entries := len(c.entries)
	c.RUnlock()

	return Stats{
		Entries:    entries,
		Hits:       c.hits.Load(),
		Misses:     c.misses.Load(),
		Evictions:  c.evictions.Load(),
		Insertions: c.insertions.Load(),
		Rejections: c.rejections.Load(),
	}
}

// Snapshot returns a summary of every live (non-expired) entry, most useful for
// answering "is this name cached, and as what?" from the diagnostic endpoint.
func (c *Cache) Snapshot() []EntryInfo {
	now := time.Now()

	c.RLock()
	defer c.RUnlock()

	infos := make([]EntryInfo, 0, len(c.entries))
	for key, entry := range c.entries {
		remaining := entry.Expiration.Sub(now)
		if remaining <= 0 {
			continue
		}

		var rcode string
		var answers int
		if entry.Msg != nil {
			rcode = dns.RcodeToString[entry.Msg.Rcode]
			answers = len(entry.Msg.Answer)
		}

		infos = append(infos, EntryInfo{
			Name:       key.Name,
			Type:       dns.TypeToString[key.Qtype],
			Class:      dns.ClassToString[key.Qclass],
			DO:         key.DO,
			Rcode:      rcode,
			Answers:    answers,
			RemainingS: int(remaining.Seconds()),
		})
	}
	return infos
}

// Flush removes every entry and returns the number removed.
func (c *Cache) Flush() int {
	c.Lock()
	defer c.Unlock()

	removed := len(c.entries)
	c.entries = make(map[Key]*Entry)
	return removed
}

// DeleteName removes every entry for the given name — across all qtypes,
// classes and DO variants — and returns the number removed. The name is matched
// the way keys are stored (lower-cased and fully qualified), so callers may pass
// either "www.google.com" or "www.google.com.". This is the targeted "unpoison
// one name" control without flushing the whole cache.
func (c *Cache) DeleteName(name string) int {
	target := strings.ToLower(dns.Fqdn(name))

	c.Lock()
	defer c.Unlock()

	var removed int
	for key := range c.entries {
		if key.Name == target {
			delete(c.entries, key)
			removed++
		}
	}
	return removed
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
			c.evictions.Add(1)
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
