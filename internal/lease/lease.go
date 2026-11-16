// Package lease implements Reclaim's lease table: grants per (AgentID, Space),
// sliding / fixed / hold decay, manual revocation, the expiry sweep, and the
// per-key history used for reclamation context in prompts. Pure logic with an
// injected clock; safe for concurrent use.
package lease

import (
	"time"

	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

// Key identifies a lease.
type Key struct {
	AgentID string
	Space   space.Space
}

// Lease is an open permission grant.
type Lease struct {
	Key
	Agent     string          // display name of the agent
	Kind      space.LeaseKind // sliding or fixed
	Source    string          // protocol.SourceLaunch | SourcePrompt | SourceHold
	GrantedAt time.Time
	LastUsed  time.Time
	TTL       time.Duration // sliding: idle window; fixed: lifetime from GrantedAt
	HoldUntil time.Time     // manual hold: the lease cannot close before this (zero = none)
	Gen       uint64        // generation assigned at the last open/close of this key
}

// ExpiresAt is max(policy expiry, HoldUntil) where policy expiry is
// LastUsed+TTL for sliding and GrantedAt+TTL for fixed leases.
func (l Lease) ExpiresAt() time.Time { return expiresAt(l) }

// Clock values are wall-clock (time.Now().Round(0), no monotonic reading) so
// laptop suspend counts as elapsed time and JSON round-trips compare equal.

// Info converts to the wire form.
func (l Lease) Info() protocol.LeaseInfo { return info(l) }

// Close causes.
const (
	CauseIdle      = "idle"       // sliding lease idled out
	CauseExpired   = "expired"    // fixed lease reached its lifetime
	CauseHoldEnded = "hold-ended" // manual hold ran out
	CauseManual    = "manual"     // revoked by the user ("reclaim now")
)

// Closure describes a lease that just closed.
type Closure struct {
	Lease   Lease
	Cause   string
	At      time.Time
	IdleFor time.Duration // At - Lease.LastUsed
}

// History is what Reclaim remembers about one (AgentID, Space) across leases.
type History struct {
	FirstGranted   time.Time            `json:"first_granted"`
	LastClosed     time.Time            `json:"last_closed"`
	LastCloseCause string               `json:"last_close_cause"`
	LastIdleFor    time.Duration        `json:"last_idle_for"`
	LastKind       space.LeaseKind      `json:"last_kind"`
	LastTTL        time.Duration        `json:"last_ttl"`
	LastDenied     time.Time            `json:"last_denied"`
	KnownTargets   map[string]time.Time `json:"known_targets,omitempty"` // TargetKey → last approval (capped at 256 newest)
}

// Snapshot is the persistable state of a Table.
type Snapshot struct {
	Gen     uint64             `json:"gen"`
	Leases  []Lease            `json:"leases"`
	History map[string]History `json:"history"` // key: AgentID + "|" + space name
}

// Table holds leases and history.
type Table struct{ impl *tableImpl }

// NewTable creates an empty table using now as its clock (nil → time.Now).
func NewTable(now func() time.Time) *Table { return &Table{impl: newTableImpl(now)} }

// Open returns the open lease for k, if any (an expired-but-unswept lease is
// NOT open).
func (t *Table) Open(k Key) (Lease, bool) { return t.impl.open(k) }

// Grant opens the lease for k with GrantedAt = LastUsed = now and a new Gen.
// If k is already open, the existing lease is kept when its ExpiresAt is
// later (a grant never shortens an open lease); otherwise it is replaced,
// preserving HoldUntil. Records History.FirstGranted on first grant.
func (t *Table) Grant(k Key, agent string, kind space.LeaseKind, ttl time.Duration, source string) Lease {
	return t.impl.grant(k, agent, kind, ttl, source)
}

// Hold sets HoldUntil = now+d on k's open lease (new Gen), or, when k is
// closed, grants a lease of the given kind/ttl with Source
// protocol.SourceHold and that HoldUntil.
func (t *Table) Hold(k Key, agent string, kind space.LeaseKind, ttl, d time.Duration) Lease {
	return t.impl.hold(k, agent, kind, ttl, d)
}

// Gen returns the current daemon-wide generation counter.
func (t *Table) Gen() uint64 { return t.impl.generation() }

// Touch records use of k at time at (LastUsed = max(LastUsed, at), never
// beyond now). Returns false if k has no open lease.
func (t *Table) Touch(k Key, at time.Time) bool { return t.impl.touch(k, at) }

// Revoke closes k's lease with cause.
func (t *Table) Revoke(k Key, cause string) (Closure, bool) { return t.impl.revoke(k, cause) }

// RevokeWhere closes every open lease whose key matches.
func (t *Table) RevokeWhere(match func(Key) bool, cause string) []Closure {
	return t.impl.revokeWhere(match, cause)
}

// Sweep closes every lease with ExpiresAt <= now, with cause idle (sliding),
// expired (fixed), or hold-ended when HoldUntil was what kept it open,
// updating History. Every closure gets a new Gen.
func (t *Table) Sweep() []Closure { return t.impl.sweep() }

// NextExpiry returns the earliest ExpiresAt among open leases.
func (t *Table) NextExpiry() (time.Time, bool) { return t.impl.nextExpiry() }

// Leases returns open leases sorted by AgentID then Space.
func (t *Table) Leases() []Lease { return t.impl.leases() }

// ApplyTTL sets TTL on open sliding leases of sp (fixed leases keep the
// lifetime they were granted with). Returns how many changed.
func (t *Table) ApplyTTL(sp space.Space, ttl time.Duration) int { return t.impl.applyTTL(sp, ttl) }

// History returns a copy of k's history.
func (t *Table) History(k Key) History { return t.impl.history(k) }

// RememberTarget records that the user approved targetKey for k.
func (t *Table) RememberTarget(k Key, targetKey string) { t.impl.rememberTarget(k, targetKey) }

// KnownTarget reports whether targetKey was ever approved for k.
func (t *Table) KnownTarget(k Key, targetKey string) bool { return t.impl.knownTarget(k, targetKey) }

// NoteDenied records a user denial for k at now.
func (t *Table) NoteDenied(k Key) { t.impl.noteDenied(k) }

// Why returns the reclamation-context sentence for a prompt (PRD 4.4), e.g.
//
//	"First time claude enters Vault Space."
//	"Home Space was reclaimed 2h ago after 10m of inactivity."
//	"Vault Space was reclaimed 5m ago when its fixed 2m lease ended."
//	"You reclaimed Home Space manually 4m ago."
//	"Your hold on Remote Space ended 1h ago."
//
// with " You denied a request here 2m ago." appended when the last denial
// is within the last 10 minutes.
func (t *Table) Why(k Key, agent string) string { return t.impl.why(k, agent) }

// Snapshot returns persistable state; Restore replaces state from one.
// Restore keeps expired leases so the next Sweep reports them as reclaimed.
func (t *Table) Snapshot() Snapshot { return t.impl.snapshot() }
func (t *Table) Restore(s Snapshot) { t.impl.restore(s) }
