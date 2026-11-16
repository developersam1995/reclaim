package lease

import (
	"cmp"
	"slices"
	"strings"
	"sync"
	"time"

	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

// tableImpl is the state behind Table. mu guards current and records; now is
// immutable after construction.
//
// "Open" follows Table.Open everywhere: a lease is open while now <
// ExpiresAt. A lease that has expired stays in current until Sweep closes it
// (or Grant/Hold replaces it), so that its closure is reported exactly once
// and with its natural cause.
type tableImpl struct {
	now func() time.Time

	mu      sync.Mutex
	gen     uint64           // daemon-wide generation; bumped on every open and close
	current map[Key]Lease    // granted and not yet closed by Revoke or Sweep
	records map[Key]*History // what is remembered per key across leases
}

func newTableImpl(now func() time.Time) *tableImpl {
	if now == nil {
		now = func() time.Time { return time.Now().Round(0) }
	}
	return &tableImpl{
		now:     now,
		current: make(map[Key]Lease),
		records: make(map[Key]*History),
	}
}

// clock reads the injected clock in the table's canonical time form.
func (t *tableImpl) clock() time.Time { return normalizeTime(t.now()) }

// normalizeTime strips the monotonic clock reading and converts to UTC.
//
// Lease expiry must follow the wall clock: Go's monotonic clock stops while
// the machine is suspended, so monotonic arithmetic would let a lease survive
// a night with the lid closed, and leases persisted across daemon restarts can
// only be compared by wall time anyway. UTC gives every stored instant a
// single representation that encoding/json round-trips unchanged.
func normalizeTime(ts time.Time) time.Time { return ts.Round(0).UTC() }

// policyExpiry is when the lease ends by its own kind, ignoring any hold.
func policyExpiry(l Lease) time.Time {
	if l.Kind == space.Sliding {
		return l.LastUsed.Add(l.TTL)
	}
	return l.GrantedAt.Add(l.TTL)
}

// expiresAt implements Lease.ExpiresAt: max(policy expiry, HoldUntil).
func expiresAt(l Lease) time.Time {
	e := policyExpiry(l)
	if l.HoldUntil.After(e) {
		return l.HoldUntil
	}
	return e
}

// info implements Lease.Info.
func info(l Lease) protocol.LeaseInfo {
	return protocol.LeaseInfo{
		AgentID:   l.AgentID,
		Agent:     l.Agent,
		Space:     l.Space.String(),
		Kind:      string(l.Kind),
		Source:    l.Source,
		GrantedAt: l.GrantedAt,
		LastUsed:  l.LastUsed,
		TTL:       protocol.Duration(l.TTL),
		ExpiresAt: expiresAt(l),
		HoldUntil: l.HoldUntil,
		Gen:       l.Gen,
	}
}

// isOpen reports whether l still grants access at now.
func isOpen(l Lease, now time.Time) bool { return now.Before(expiresAt(l)) }

// expiryCause is the close cause Sweep records for an expired lease.
func expiryCause(l Lease) string {
	switch {
	case l.HoldUntil.After(policyExpiry(l)):
		return CauseHoldEnded
	case l.Kind == space.Sliding:
		return CauseIdle
	default:
		return CauseExpired
	}
}

// leaseKind maps any kind other than sliding to fixed, the stricter decay
// that ExpiresAt already applies to non-sliding leases, so the stored kind,
// the wire form and the sweep cause all agree.
func leaseKind(k space.LeaseKind) space.LeaseKind {
	if k == space.Sliding {
		return space.Sliding
	}
	return space.Fixed
}

func (t *tableImpl) open(k Key) (Lease, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.current[k]
	if !ok || !isOpen(l, t.clock()) {
		return Lease{}, false
	}
	return l, true
}

func (t *tableImpl) grant(k Key, agent string, kind space.LeaseKind, ttl time.Duration, source string) Lease {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	l := Lease{Key: k, Agent: agent, Kind: leaseKind(kind), Source: source, TTL: ttl, GrantedAt: now, LastUsed: now}
	if prev, ok := t.current[k]; ok && isOpen(prev, now) {
		l.HoldUntil = prev.HoldUntil
		if !expiresAt(prev).Before(expiresAt(l)) {
			return prev // a grant never shortens an open lease
		}
	}
	return t.putLocked(l, now)
}

func (t *tableImpl) hold(k Key, agent string, kind space.LeaseKind, ttl, d time.Duration) Lease {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	until := now.Add(d)
	if prev, ok := t.current[k]; ok && isOpen(prev, now) {
		prev.HoldUntil = until
		t.gen++
		prev.Gen = t.gen
		t.current[k] = prev
		return prev
	}
	l := Lease{Key: k, Agent: agent, Kind: leaseKind(kind), Source: protocol.SourceHold, TTL: ttl,
		GrantedAt: now, LastUsed: now, HoldUntil: until}
	return t.putLocked(l, now)
}

func (t *tableImpl) generation() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gen
}

// putLocked stores l as the lease for l.Key with a fresh Gen (replacing any
// previous lease without reporting a closure) and records the grant.
func (t *tableImpl) putLocked(l Lease, now time.Time) Lease {
	t.gen++
	l.Gen = t.gen
	t.current[l.Key] = l
	h := t.recordLocked(l.Key)
	if h.FirstGranted.IsZero() {
		h.FirstGranted = now
	}
	h.LastKind, h.LastTTL = l.Kind, l.TTL
	return l
}

func (t *tableImpl) touch(k Key, at time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	l, ok := t.current[k]
	if !ok || !isOpen(l, now) {
		return false
	}
	used := normalizeTime(at)
	if used.After(now) {
		used = now // a session clock ahead of ours must not stretch the lease
	}
	if used.After(l.LastUsed) {
		l.LastUsed = used
		t.current[k] = l
	}
	return true
}

// revoke closes k's lease if it is open. An expired lease that has not been
// swept yet is left for Sweep, which reports it with its natural cause. An
// empty cause is recorded as CauseManual.
func (t *tableImpl) revoke(k Key, cause string) (Closure, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.revokeLocked(k, cause, t.clock())
}

// revokeWhere closes every open lease whose key satisfies match (nil matches
// every key). match runs without the table lock held, so it may call other
// Table methods. Closures are sorted by AgentID, then Space.
func (t *tableImpl) revokeWhere(match func(Key) bool, cause string) []Closure {
	t.mu.Lock()
	keys := make([]Key, 0, len(t.current))
	for k := range t.current {
		keys = append(keys, k)
	}
	t.mu.Unlock()

	selected := keys[:0]
	for _, k := range keys {
		if match == nil || match(k) {
			selected = append(selected, k)
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	var out []Closure
	for _, k := range selected {
		if c, ok := t.revokeLocked(k, cause, now); ok {
			out = append(out, c)
		}
	}
	sortClosures(out)
	return out
}

func (t *tableImpl) revokeLocked(k Key, cause string, now time.Time) (Closure, bool) {
	l, ok := t.current[k]
	if !ok || !isOpen(l, now) {
		return Closure{}, false
	}
	if cause == "" {
		cause = CauseManual
	}
	return t.closeLocked(l, cause, now), true
}

// sweep closes every lease whose ExpiresAt is not after now. Closures are
// stamped with the sweep time (At = now), sorted by AgentID, then Space.
func (t *tableImpl) sweep() []Closure {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	var out []Closure
	for _, l := range t.current {
		if !isOpen(l, now) {
			out = append(out, t.closeLocked(l, expiryCause(l), now))
		}
	}
	sortClosures(out)
	return out
}

// closeLocked removes l from the table and records the closure in history.
func (t *tableImpl) closeLocked(l Lease, cause string, now time.Time) Closure {
	delete(t.current, l.Key)
	t.gen++
	l.Gen = t.gen
	idle := now.Sub(l.LastUsed)
	if idle < 0 {
		idle = 0 // the clock stepped backwards; never report negative idleness
	}
	h := t.recordLocked(l.Key)
	h.LastClosed = now
	h.LastCloseCause = cause
	h.LastIdleFor = idle
	h.LastKind = l.Kind
	h.LastTTL = l.TTL
	return Closure{Lease: l, Cause: cause, At: now, IdleFor: idle}
}

// nextExpiry returns the earliest ExpiresAt among leases not yet closed by
// Sweep or Revoke. It is in the past when a lease has expired but has not been
// swept yet, which tells a scheduler to sweep right away.
func (t *tableImpl) nextExpiry() (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var next time.Time
	found := false
	for _, l := range t.current {
		if e := expiresAt(l); !found || e.Before(next) {
			next, found = e, true
		}
	}
	return next, found
}

// leases returns the open leases (expired-but-unswept ones excluded, matching
// Open) sorted by AgentID, then Space.
func (t *tableImpl) leases() []Lease {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	out := make([]Lease, 0, len(t.current))
	for _, l := range t.current {
		if isOpen(l, now) {
			out = append(out, l)
		}
	}
	sortLeases(out)
	return out
}

// applyTTL changes the idle window of the open sliding leases of sp and
// returns how many leases had a different TTL before. Fixed leases keep the
// lifetime they were granted with.
func (t *tableImpl) applyTTL(sp space.Space, ttl time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	changed := 0
	for k, l := range t.current {
		if k.Space != sp || l.Kind != space.Sliding || l.TTL == ttl || !isOpen(l, now) {
			continue
		}
		l.TTL = ttl
		t.current[k] = l
		changed++
	}
	return changed
}

// compareKeys orders keys by AgentID, then by numeric Space.
func compareKeys(a, b Key) int {
	if c := strings.Compare(a.AgentID, b.AgentID); c != 0 {
		return c
	}
	return cmp.Compare(a.Space, b.Space)
}

func sortLeases(ls []Lease) {
	slices.SortFunc(ls, func(a, b Lease) int { return compareKeys(a.Key, b.Key) })
}

func sortClosures(cs []Closure) {
	slices.SortFunc(cs, func(a, b Closure) int { return compareKeys(a.Lease.Key, b.Lease.Key) })
}
