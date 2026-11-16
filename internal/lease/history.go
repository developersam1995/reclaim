package lease

import (
	"maps"
	"slices"
	"strings"
	"time"
)

// maxKnownTargets caps History.KnownTargets; the least recently approved
// targets are forgotten first.
const maxKnownTargets = 256

// recordLocked returns k's mutable history record, creating it on first use.
func (t *tableImpl) recordLocked(k Key) *History {
	h, ok := t.records[k]
	if !ok {
		h = &History{}
		t.records[k] = h
	}
	return h
}

func (t *tableImpl) history(k Key) History {
	t.mu.Lock()
	defer t.mu.Unlock()
	h, ok := t.records[k]
	if !ok {
		return History{}
	}
	return cloneHistory(*h)
}

// rememberTarget stamps targetKey as approved now. An empty targetKey is
// ignored: an unidentified target must never count as known.
func (t *tableImpl) rememberTarget(k Key, targetKey string) {
	if targetKey == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.recordLocked(k)
	if h.KnownTargets == nil {
		h.KnownTargets = make(map[string]time.Time)
	}
	h.KnownTargets[targetKey] = t.clock()
	trimTargets(h.KnownTargets, maxKnownTargets, targetKey)
}

func (t *tableImpl) knownTarget(k Key, targetKey string) bool {
	if targetKey == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	h, ok := t.records[k]
	if !ok {
		return false
	}
	_, known := h.KnownTargets[targetKey]
	return known
}

func (t *tableImpl) noteDenied(k Key) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recordLocked(k).LastDenied = t.clock()
}

// cloneHistory returns a copy of h that shares no map with it. An empty
// KnownTargets becomes nil, which is what a JSON round trip produces.
func cloneHistory(h History) History {
	if len(h.KnownTargets) == 0 {
		h.KnownTargets = nil
	} else {
		h.KnownTargets = maps.Clone(h.KnownTargets)
	}
	return h
}

// trimTargets deletes the least recently approved entries of m until at most
// limit remain, never deleting keep. Entries approved at the same instant are
// evicted in key order so the outcome is deterministic.
func trimTargets(m map[string]time.Time, limit int, keep string) {
	excess := len(m) - limit
	if excess <= 0 {
		return
	}
	type entry struct {
		key string
		at  time.Time
	}
	victims := make([]entry, 0, len(m))
	for key, at := range m {
		if key != keep {
			victims = append(victims, entry{key, at})
		}
	}
	slices.SortFunc(victims, func(a, b entry) int {
		if c := a.at.Compare(b.at); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	for _, v := range victims[:min(excess, len(victims))] {
		delete(m, v.key)
	}
}
