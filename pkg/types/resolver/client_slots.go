package resolver

import (
	"net/netip"
	"sync"
)

// clientSlots bounds the forwards one client has in flight at once. It tracks
// only clients with a forward in flight, so it holds no more of them than the
// resolver has forwards. A nil clientSlots bounds nothing.
type clientSlots struct {
	mutex  sync.Mutex
	limit  int
	counts map[netip.Addr]int
}

func newClientSlots(limit int) *clientSlots {
	return &clientSlots{limit: limit, counts: make(map[netip.Addr]int)}
}

// acquire takes a slot for client, reporting false when it holds all of its
// own already.
func (s *clientSlots) acquire(client netip.Addr) bool {
	if s == nil {
		return true
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.counts[client] >= s.limit {
		return false
	}
	s.counts[client]++
	return true
}

func (s *clientSlots) release(client netip.Addr) {
	if s == nil {
		return
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.counts[client] <= 1 {
		delete(s.counts, client)
		return
	}
	s.counts[client]--
}
