package lease

import (
	"fmt"
	"strings"
	"time"

	"reclaim/internal/space"
)

// denialMemory is how long a denial is mentioned in the reclamation context.
const denialMemory = 10 * time.Minute

// why builds the PRD 4.4 reclamation-context sentence for a prompt about k.
// It is empty while k has an open lease, since callers only prompt for closed
// Spaces.
func (t *tableImpl) why(k Key, agent string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	l, unswept := t.current[k]
	if unswept && isOpen(l, now) {
		return ""
	}
	var h History
	if rec, ok := t.records[k]; ok {
		h = *rec
	}
	title := k.Space.Title()
	name := agentName(agent, k)

	var b strings.Builder
	switch {
	case h.FirstGranted.IsZero():
		fmt.Fprintf(&b, "First time %s enters %s.", name, title)
	case unswept || h.LastCloseCause == "":
		// The latest lease expired but Sweep has not recorded its closure
		// yet, so any recorded cause would describe an older lease.
		fmt.Fprintf(&b, "%s has used %s before; it is closed now.", name, title)
	case h.LastCloseCause == CauseIdle:
		fmt.Fprintf(&b, "%s was reclaimed %s after %s of inactivity.",
			title, since(now, h.LastClosed), space.HumanDuration(h.LastIdleFor))
	case h.LastCloseCause == CauseExpired:
		fmt.Fprintf(&b, "%s was reclaimed %s when its fixed %s lease ended.",
			title, since(now, h.LastClosed), space.HumanDuration(h.LastTTL))
	case h.LastCloseCause == CauseManual:
		fmt.Fprintf(&b, "You reclaimed %s manually %s.", title, since(now, h.LastClosed))
	case h.LastCloseCause == CauseHoldEnded:
		fmt.Fprintf(&b, "Your hold on %s ended %s.", title, since(now, h.LastClosed))
	default:
		// A caller-defined Revoke cause: say when, not why.
		fmt.Fprintf(&b, "%s was reclaimed %s.", title, since(now, h.LastClosed))
	}
	if !h.LastDenied.IsZero() && now.Sub(h.LastDenied) <= denialMemory {
		fmt.Fprintf(&b, " You denied a request here %s.", since(now, h.LastDenied))
	}
	return b.String()
}

// since renders how long before now an instant was: "5m ago", or "just now"
// for anything under a second (including instants in the future, which a
// clock stepping backwards can produce).
func since(now, then time.Time) string {
	d := now.Sub(then)
	if d < time.Second {
		return "just now"
	}
	return space.HumanDuration(d) + " ago"
}

// agentName is the agent as named in Why sentences: the caller's display
// name, else the name part of the AgentID ("claude" in
// "claude@/home/u/project").
func agentName(agent string, k Key) string {
	if a := strings.TrimSpace(agent); a != "" {
		return a
	}
	if name, _, _ := strings.Cut(k.AgentID, "@"); strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return "the agent"
}
