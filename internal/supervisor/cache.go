package supervisor

import (
	"sync"
	"time"

	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

// cachedLease is the session's view of one open lease.
type cachedLease struct {
	info     protocol.LeaseInfo
	lastUsed time.Time // local, wall clock
	used     bool      // at least one gated use since it opened
	targets  map[string]bool
}

// leaseCache mirrors the daemon's leases for this agent, updated by pushes
// and decisions, with local sliding extension between touch flushes.
type leaseCache struct {
	mu      sync.Mutex
	leases  map[space.Space]*cachedLease
	closed  map[space.Space]uint64 // highest Gen seen closed per space
	pending map[space.Space]protocol.TouchAt
	current space.Space
	now     func() time.Time
}

func newLeaseCache(now func() time.Time) *leaseCache {
	return &leaseCache{leases: map[space.Space]*cachedLease{}, closed: map[space.Space]uint64{},
		pending: map[space.Space]protocol.TouchAt{}, now: now}
}

// replace resets the cache from a welcome.
func (c *leaseCache) replace(leases []protocol.LeaseInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leases = map[space.Space]*cachedLease{}
	c.closed = map[space.Space]uint64{}
	for _, l := range leases {
		c.openLocked(l)
	}
}

func (c *leaseCache) openLocked(l protocol.LeaseInfo) {
	sp, err := space.Parse(l.Space)
	if err != nil {
		return
	}
	if cur, ok := c.leases[sp]; ok && cur.info.Gen >= l.Gen {
		return
	}
	if c.closed[sp] >= l.Gen {
		return
	}
	last := l.LastUsed
	if last.IsZero() {
		last = l.GrantedAt
	}
	c.leases[sp] = &cachedLease{info: l, lastUsed: last, targets: map[string]bool{}}
}

// apply handles a lease push.
func (c *leaseCache) apply(u protocol.LeaseUpdate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sp, err := space.Parse(u.Lease.Space)
	if err != nil {
		return
	}
	if u.Open {
		c.openLocked(u.Lease)
		return
	}
	if cur, ok := c.leases[sp]; ok && (u.Lease.Gen == 0 || u.Lease.Gen >= cur.info.Gen) {
		delete(c.leases, sp)
	}
	if u.Lease.Gen > c.closed[sp] {
		c.closed[sp] = u.Lease.Gen
	}
}

// open reports whether sp has an open lease at now.
func (c *leaseCache) open(sp space.Space) (*cachedLease, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.leases[sp]
	if !ok {
		return nil, false
	}
	if !c.isOpenLocked(l) {
		delete(c.leases, sp)
		return nil, false
	}
	return l, true
}

func (c *leaseCache) isOpenLocked(l *cachedLease) bool {
	now := c.now()
	exp := l.info.ExpiresAt
	if l.info.Kind == string(space.Sliding) {
		exp = l.lastUsed.Add(l.info.TTL.D())
	}
	if l.info.HoldUntil.After(exp) {
		exp = l.info.HoldUntil
	}
	return now.Before(exp)
}

// touch records a use of sp; returns (firstUse, newTarget).
func (c *leaseCache) touch(sp space.Space, targetKey string) (first, newTarget bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = sp
	l, ok := c.leases[sp]
	if !ok || !c.isOpenLocked(l) {
		return false, false
	}
	now := c.now()
	l.lastUsed = now
	first = !l.used
	l.used = true
	if targetKey != "" && !l.targets[targetKey] {
		if len(l.targets) < 512 {
			l.targets[targetKey] = true
		}
		newTarget = true
	}
	c.pending[sp] = protocol.TouchAt{At: now, Gen: l.info.Gen}
	return first, newTarget
}

// flush returns and clears the pending touches.
func (c *leaseCache) flush() (map[string]protocol.TouchAt, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return nil, c.current.String()
	}
	out := make(map[string]protocol.TouchAt, len(c.pending))
	for sp, t := range c.pending {
		out[sp.String()] = t
	}
	c.pending = map[space.Space]protocol.TouchAt{}
	cur := ""
	if c.current.UserFacing() {
		cur = c.current.String()
	}
	return out, cur
}

func (c *leaseCache) currentSpace() space.Space {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}
