// Package audit writes and reads Reclaim's append-only audit log
// (JSONL of protocol.AuditEvent) and renders events as human-readable lines.
package audit

import (
	"context"

	"reclaim/internal/protocol"
)

// Log appends audit events to a file and keeps the most recent 200 in memory.
// Safe for concurrent use.
type Log struct{ impl *logImpl }

// Open opens (creating with mode 0600) path for appending and preloads the
// in-memory ring with the file's last 200 events.
func Open(path string) (*Log, error) {
	impl, err := openLog(path)
	if err != nil {
		return nil, err
	}
	return &Log{impl: impl}, nil
}

// Append writes ev as one JSON line (setting ev.Time to now if zero).
func (l *Log) Append(ev protocol.AuditEvent) error { return l.impl.append(ev) }

// Recent returns up to n most recent events, oldest first.
func (l *Log) Recent(n int) []protocol.AuditEvent { return l.impl.recent(n) }

// Close closes the file.
func (l *Log) Close() error { return l.impl.close() }

// Query reads path and returns the last q.Limit (default 50) events matching
// q.AgentID / q.Space (empty = any), oldest first. Large files are read from
// the end; malformed lines are skipped.
func Query(path string, q protocol.AuditQuery) ([]protocol.AuditEvent, error) { return query(path, q) }

// Follow calls fn for every event appended to path after Follow starts (poll
// every 250ms; tolerates the file not existing yet) until ctx is done.
func Follow(ctx context.Context, path string, fn func(protocol.AuditEvent)) error {
	return follow(ctx, path, fn)
}

// Format renders one event as a single human-readable line, e.g.
//
//	2026-11-06 16:42:10  claude·reclaim  APPROVED    Vault    read ~/.ssh/id_ed25519 (SSH private key) · fixed 2m · via console
//	2026-11-06 17:01:33  claude·reclaim  RECLAIMED   Home     after 10m of inactivity
//
// The agent column shows Agent + "·" + base name of the project in AgentID.
// With color, the kind is colored with ANSI codes (approved green, denied/
// timeout/blocked red, reclaimed/revoked yellow).
func Format(ev protocol.AuditEvent, color bool) string { return format(ev, color) }
