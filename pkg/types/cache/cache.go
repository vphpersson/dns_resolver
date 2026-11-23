package cache

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	"github.com/miekg/dns"
)

// maxCacheTtl bounds how long any single entry may live. It defends against an
// unbounded effective TTL: EffectiveMessageTtl falls back to the uint32 max
// (~136 years) when no record or SOA supplies a TTL, so without a cap a single
// odd response could pin a name effectively forever. 24h matches Unbound's
// cache-max-ttl default.
const maxCacheTtl = 24 * time.Hour

// maxNegativeTtl bounds how long an NXDOMAIN or NODATA answer may live, as
// Unbound's cache-max-negative-ttl does. The root zone's SOA would otherwise
// keep every random name under a missing TLD for a day.
const maxNegativeTtl = time.Hour

const (
	// DefaultMaxEntries bounds the number of cached answers.
	DefaultMaxEntries = 50_000
	// DefaultMaxBytes bounds the approximate memory the cached answers take.
	DefaultMaxBytes = 64 << 20
	// DefaultSnapshotLimit is how many entries Snapshot lists when not told.
	DefaultSnapshotLimit = 1000
)

// Approximate costs of an entry beyond its wire length, so that MaxBytes
// tracks memory rather than the wire size alone: a message unpacks into one
// allocation per record, and an entry costs a map slot and a list element.
const (
	recordOverhead = 64
	entryOverhead  = 128
)

type Key struct {
	Name   string
	Qtype  uint16
	Qclass uint16
	DO     bool
	CD     bool
}

type Entry struct {
	Key        Key
	Msg        *dns.Msg
	Expiration time.Time
	size       int
}

// Cache holds answers by Key, evicting the least recently used when it holds
// more than MaxEntries of them or more than MaxBytes of approximate memory.
type Cache struct {
	mutex sync.Mutex
	// entries indexes order, whose elements hold *Entry, the most recently
	// used at the front.
	entries map[Key]*list.Element
	order   *list.List
	bytes   int

	maxEntries int
	maxBytes   int

	hits       atomic.Uint64
	misses     atomic.Uint64
	evictions  atomic.Uint64
	insertions atomic.Uint64
	rejections atomic.Uint64
}

// Stats is a point-in-time snapshot of cache counters, suitable for the
// diagnostic /metrics endpoint. The counters are monotonic for the process
// lifetime; Entries and Bytes are the live size.
type Stats struct {
	Entries    int    `json:"entries"`
	Bytes      int    `json:"bytes"`
	MaxEntries int    `json:"max_entries"`
	MaxBytes   int    `json:"max_bytes"`
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
	CD         bool   `json:"cd"`
	Rcode      string `json:"rcode"`
	Answers    int    `json:"answers"`
	RemainingS int    `json:"remaining_s"`
}

// Option tunes a Cache made by New.
type Option func(*Cache)

// WithMaxEntries bounds the number of cached answers; <= 0 keeps the default.
func WithMaxEntries(maxEntries int) Option {
	return func(c *Cache) {
		if maxEntries > 0 {
			c.maxEntries = maxEntries
		}
	}
}

// WithMaxBytes bounds the approximate memory of the cached answers; <= 0
// keeps the default.
func WithMaxBytes(maxBytes int) Option {
	return func(c *Cache) {
		if maxBytes > 0 {
			c.maxBytes = maxBytes
		}
	}
}

func New(options ...Option) *Cache {
	c := &Cache{
		entries:    make(map[Key]*list.Element),
		order:      list.New(),
		maxEntries: DefaultMaxEntries,
		maxBytes:   DefaultMaxBytes,
	}
	for _, option := range options {
		if option != nil {
			option(c)
		}
	}
	return c
}

// entrySize estimates the memory an entry for message takes.
func entrySize(key Key, message *dns.Msg) int {
	records := len(message.Answer) + len(message.Ns) + len(message.Extra)
	return message.Len() + records*recordOverhead + len(key.Name) + entryOverhead
}

// removeElement drops element from the cache. The caller holds the mutex.
func (c *Cache) removeElement(element *list.Element) {
	entry, ok := element.Value.(*Entry)
	if !ok {
		return
	}
	c.order.Remove(element)
	delete(c.entries, entry.Key)
	c.bytes -= entry.size
}

func (c *Cache) Get(key Key) (*dns.Msg, bool, time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	element, ok := c.entries[key]
	if !ok {
		c.misses.Add(1)
		return nil, false, 0
	}
	entry, ok := element.Value.(*Entry)
	if !ok {
		c.misses.Add(1)
		return nil, false, 0
	}

	remainingTtl := time.Until(entry.Expiration)
	if remainingTtl <= 0 {
		c.removeElement(element)
		c.evictions.Add(1)
		c.misses.Add(1)
		return nil, false, 0
	}

	c.order.MoveToFront(element)
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

	// A negative answer holds for as long as its SOA says (RFC 2308 §5). One
	// without an SOA says nothing about that and is not cached; it would
	// otherwise take the 24h cap. An upstream answering a query it did not
	// recurse for, from what it happened to have cached, sends just that.
	negative := isNegative(message)
	if negative && !hasSoa(message.Ns) {
		c.rejections.Add(1)
		return false
	}

	ttl := dns_utils.EffectiveMessageTtl(message)
	if ttl <= 0 {
		c.rejections.Add(1)
		return false
	}
	ttl = min(ttl, maxCacheTtl)
	if negative {
		ttl = min(ttl, maxNegativeTtl)
	}

	size := entrySize(key, message)
	entry := &Entry{Key: key, Msg: message, Expiration: expirationReference.Add(ttl), size: size}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// An answer too large for the whole cache would only empty it.
	if size > c.maxBytes {
		c.rejections.Add(1)
		return false
	}

	if element, ok := c.entries[key]; ok {
		c.removeElement(element)
	}
	c.entries[key] = c.order.PushFront(entry)
	c.bytes += size
	c.insertions.Add(1)

	for c.order.Len() > c.maxEntries || c.bytes > c.maxBytes {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.removeElement(back)
		c.evictions.Add(1)
	}

	return true
}

// isNegative reports whether message says the name does not exist (NXDOMAIN)
// or has no records of the type asked for (NODATA). A NODATA answer for a name
// that is an alias carries the CNAME chain and nothing of the type asked for
// (RFC 2308 §2.2.1), so the type, not an empty answer section, decides.
func isNegative(message *dns.Msg) bool {
	if message.Rcode == dns.RcodeNameError {
		return true
	}
	if len(message.Question) == 0 {
		return len(message.Answer) == 0
	}

	asked := message.Question[0].Qtype
	for _, record := range message.Answer {
		if record != nil && (asked == dns.TypeANY || record.Header().Rrtype == asked) {
			return false
		}
	}
	return true
}

func hasSoa(records []dns.RR) bool {
	for _, record := range records {
		if _, ok := record.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

// Stats returns a snapshot of the cache counters and current size.
func (c *Cache) Stats() Stats {
	c.mutex.Lock()
	entries := c.order.Len()
	bytes := c.bytes
	c.mutex.Unlock()

	return Stats{
		Entries:    entries,
		Bytes:      bytes,
		MaxEntries: c.maxEntries,
		MaxBytes:   c.maxBytes,
		Hits:       c.hits.Load(),
		Misses:     c.misses.Load(),
		Evictions:  c.evictions.Load(),
		Insertions: c.insertions.Load(),
		Rejections: c.rejections.Load(),
	}
}

// Snapshot summarises live (non-expired) entries, most recently used first,
// for answering "is this name cached, and as what?" from the diagnostic
// endpoint. A non-empty name lists only that name's entries, matched as
// DeleteName matches; at most limit are listed, or DefaultSnapshotLimit when
// limit is not positive.
func (c *Cache) Snapshot(name string, limit int) []EntryInfo {
	if limit <= 0 {
		limit = DefaultSnapshotLimit
	}
	var target string
	if name != "" {
		target = strings.ToLower(dns.Fqdn(name))
	}

	now := time.Now()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	infos := make([]EntryInfo, 0, min(limit, c.order.Len()))
	for element := c.order.Front(); element != nil && len(infos) < limit; element = element.Next() {
		entry, ok := element.Value.(*Entry)
		if !ok {
			continue
		}
		if target != "" && entry.Key.Name != target {
			continue
		}
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
			Name:       entry.Key.Name,
			Type:       dns.TypeToString[entry.Key.Qtype],
			Class:      dns.ClassToString[entry.Key.Qclass],
			DO:         entry.Key.DO,
			CD:         entry.Key.CD,
			Rcode:      rcode,
			Answers:    answers,
			RemainingS: int(remaining.Seconds()),
		})
	}
	return infos
}

// Flush removes every entry and returns the number removed.
func (c *Cache) Flush() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	removed := c.order.Len()
	c.entries = make(map[Key]*list.Element)
	c.order.Init()
	c.bytes = 0
	return removed
}

// DeleteName removes every entry for the given name — across all qtypes,
// classes and DO variants — and returns the number removed. The name is matched
// the way keys are stored (lower-cased and fully qualified), so callers may pass
// either "www.google.com" or "www.google.com.". This is the targeted "unpoison
// one name" control without flushing the whole cache.
func (c *Cache) DeleteName(name string) int {
	target := strings.ToLower(dns.Fqdn(name))

	c.mutex.Lock()
	defer c.mutex.Unlock()

	var removed int
	for key, element := range c.entries {
		if key.Name == target {
			c.removeElement(element)
			removed++
		}
	}
	return removed
}

// sweep removes expired entries.
func (c *Cache) sweep() {
	now := time.Now()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	for element := c.order.Front(); element != nil; {
		next := element.Next()
		if entry, ok := element.Value.(*Entry); ok && now.After(entry.Expiration) {
			c.removeElement(element)
			c.evictions.Add(1)
		}
		element = next
	}
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
