package nextdns

import (
	"sync"
	"sync/atomic"
)

// shards is the number of independently locked buckets in a store. Cache
// lookups sit on the query path, so contention matters more than exactness.
const shards = 256

// store is a bounded, sharded key/value store for cache entries.
//
// Eviction is "drop an arbitrary entry when the shard is full", the same
// strategy CoreDNS' own cache uses: a DNS cache is self-cleaning through TTLs,
// so the LRU bookkeeping costs more than it saves.
type store struct {
	shards [shards]*storeShard
	n      atomic.Int64 // total entries, so Len is O(1) on the query path
}

type storeShard struct {
	mu    sync.RWMutex
	items map[uint64]*cacheEntry
	size  int
}

// newStore returns a store holding about capacity entries.
//
// Capacity is divided across the shards and rounded up, so the real ceiling is
// capacity rounded up to a whole number of shards. Since a shard cannot hold
// less than one entry, a store never holds fewer than `shards` entries however
// small the requested capacity — asking for 100 gets you 256, not 100.
func newStore(capacity int) *store {
	s := &store{}
	size := (capacity + shards - 1) / shards
	if size < 1 {
		size = 1
	}
	for i := range s.shards {
		s.shards[i] = &storeShard{items: make(map[uint64]*cacheEntry), size: size}
	}
	return s
}

// capacity is the total number of entries this store can hold.
func (s *store) capacity() int { return s.shards[0].size * shards }

func (s *store) shard(key uint64) *storeShard { return s.shards[key&(shards-1)] }

func (s *store) Get(key uint64) (*cacheEntry, bool) {
	sh := s.shard(key)
	sh.mu.RLock()
	e, ok := sh.items[key]
	sh.mu.RUnlock()
	return e, ok
}

func (s *store) Add(key uint64, e *cacheEntry) {
	sh := s.shard(key)
	sh.mu.Lock()
	_, replacing := sh.items[key]
	if !replacing && len(sh.items) >= sh.size {
		for k := range sh.items {
			delete(sh.items, k)
			replacing = true // one out, one in: the total is unchanged
			break
		}
	}
	sh.items[key] = e
	sh.mu.Unlock()

	if !replacing {
		s.n.Add(1)
	}
}

func (s *store) Len() int { return int(s.n.Load()) }
