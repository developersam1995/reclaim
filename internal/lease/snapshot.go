package lease

import (
	"strings"
	"time"

	"reclaim/internal/space"
)

// historyKeySep separates AgentID and space name in Snapshot.History keys.
// Keys are split at the last separator because a project root (part of the
// AgentID) may itself contain one; a space name never does.
const historyKeySep = "|"

func historyKey(k Key) string { return k.AgentID + historyKeySep + k.Space.String() }

// parseHistoryKey inverts historyKey. It accepts only canonical space names,
// so two spellings can never collide on the same Key.
func parseHistoryKey(s string) (Key, bool) {
	i := strings.LastIndex(s, historyKeySep)
	if i < 0 {
		return Key{}, false
	}
	name := s[i+len(historyKeySep):]
	sp, err := space.Parse(name)
	if err != nil || sp.String() != name {
		return Key{}, false
	}
	return Key{AgentID: s[:i], Space: sp}, true
}

// snapshot copies every lease not yet closed (expired-but-unswept ones
// included, so a restored table reports them) and every history record.
func (t *tableImpl) snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Snapshot{
		Gen:     t.gen,
		Leases:  make([]Lease, 0, len(t.current)),
		History: make(map[string]History, len(t.records)),
	}
	for _, l := range t.current {
		s.Leases = append(s.Leases, l)
	}
	sortLeases(s.Leases)
	for k, h := range t.records {
		s.History[historyKey(k)] = cloneHistory(*h)
	}
	return s
}

// restore replaces the table's state with s. Expired leases are kept so the
// next Sweep closes and reports them. Input that a Table never produces is
// repaired rather than rejected:
//   - history entries whose key does not parse are dropped;
//   - of several leases for one key, the most recently granted wins;
//   - a lease whose key has no recorded first grant gets one from the lease;
//   - known targets are capped at 256 and an empty target key is dropped;
//   - times are normalized to UTC wall-clock instants and unknown lease
//     kinds become fixed, as for Grant.
func (t *tableImpl) restore(s Snapshot) {
	current := make(map[Key]Lease, len(s.Leases))
	for _, l := range s.Leases {
		l.Kind = leaseKind(l.Kind)
		l.GrantedAt = normalizeTime(l.GrantedAt)
		l.LastUsed = normalizeTime(l.LastUsed)
		if !l.HoldUntil.IsZero() {
			l.HoldUntil = normalizeTime(l.HoldUntil)
		}
		if prev, dup := current[l.Key]; dup && l.GrantedAt.Before(prev.GrantedAt) {
			continue
		}
		current[l.Key] = l
	}

	records := make(map[Key]*History, len(s.History))
	for name, h := range s.History {
		k, ok := parseHistoryKey(name)
		if !ok {
			continue
		}
		h := normalizeHistory(h)
		records[k] = &h
	}
	for k, l := range current {
		h, ok := records[k]
		if !ok {
			h = &History{}
			records[k] = h
		}
		if h.FirstGranted.IsZero() {
			h.FirstGranted = l.GrantedAt
			h.LastKind, h.LastTTL = l.Kind, l.TTL
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.current, t.records = current, records
	t.gen = s.Gen
	for _, l := range current {
		if l.Gen > t.gen {
			t.gen = l.Gen
		}
	}
}

// normalizeHistory returns a copy of h in the table's canonical form, sharing
// no map with the caller's snapshot.
func normalizeHistory(h History) History {
	h.FirstGranted = normalizeTime(h.FirstGranted)
	h.LastClosed = normalizeTime(h.LastClosed)
	h.LastDenied = normalizeTime(h.LastDenied)
	var targets map[string]time.Time
	for key, at := range h.KnownTargets {
		if key == "" {
			continue
		}
		if targets == nil {
			targets = make(map[string]time.Time, len(h.KnownTargets))
		}
		targets[key] = normalizeTime(at)
	}
	trimTargets(targets, maxKnownTargets, "") // "" was skipped, so nothing is exempt
	h.KnownTargets = targets
	return h
}
