package traefikx402

import (
	"crypto/sha256"
	"sync"
	"time"
)

const (
	replayShards      = 16
	replayShardMax    = 8192
	replayTTLMargin   = 60 * time.Second
	replaySweepPeriod = 30 * time.Second
)

// replayGuard stops one payment authorization from unlocking several requests
// while its settlement is still pending. The chain enforces single use of a
// nonce, but only at settlement; this closes the window in between.
type replayGuard struct {
	now    func() time.Time
	shards []*replayShard
}

type replayShard struct {
	seen      map[string]int64
	nextSweep int64
	mu        sync.Mutex
}

func newReplayGuard(now func() time.Time) *replayGuard {
	g := &replayGuard{now: now, shards: make([]*replayShard, replayShards)}
	for i := range g.shards {
		g.shards[i] = &replayShard{seen: make(map[string]int64)}
	}
	return g
}

// guardKey derives the dedup key from the raw PAYMENT-SIGNATURE value.
func guardKey(sig string) string {
	sum := sha256.Sum256([]byte(sig))
	return string(sum[:])
}

// claim registers key for ttl and reports false when it is already live.
// A full shard fails open: the chain still prevents a double spend.
func (g *replayGuard) claim(key string, ttl time.Duration) bool {
	now := g.now().UnixNano()
	s := g.shards[int(key[0])%replayShards]
	s.mu.Lock()
	defer s.mu.Unlock()
	if now >= s.nextSweep {
		for k, exp := range s.seen {
			if exp <= now {
				delete(s.seen, k)
			}
		}
		s.nextSweep = now + int64(replaySweepPeriod)
	}
	if exp, ok := s.seen[key]; ok && exp > now {
		return false
	}
	if len(s.seen) < replayShardMax {
		s.seen[key] = now + int64(ttl+replayTTLMargin)
	}
	return true
}

// release forgets key so a payment that was never settled can be retried.
func (g *replayGuard) release(key string) {
	s := g.shards[int(key[0])%replayShards]
	s.mu.Lock()
	delete(s.seen, key)
	s.mu.Unlock()
}
