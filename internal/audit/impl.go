package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

const ringSize = 200

type logImpl struct {
	mu   sync.Mutex
	f    *os.File
	ring []protocol.AuditEvent
}

func openLog(path string) (*logImpl, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := &logImpl{f: f}
	if recent, err := query(path, protocol.AuditQuery{Limit: ringSize}); err == nil {
		l.ring = recent
	}
	return l, nil
}

func (l *logImpl) append(ev protocol.AuditEvent) error {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: encode: %w", err)
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(b); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	l.ring = append(l.ring, ev)
	if len(l.ring) > ringSize {
		l.ring = l.ring[len(l.ring)-ringSize:]
	}
	return nil
}

func (l *logImpl) recent(n int) []protocol.AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.ring) {
		n = len(l.ring)
	}
	out := make([]protocol.AuditEvent, n)
	copy(out, l.ring[len(l.ring)-n:])
	return out
}

func (l *logImpl) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

func matches(ev protocol.AuditEvent, q protocol.AuditQuery) bool {
	if q.AgentID != "" && ev.AgentID != q.AgentID {
		return false
	}
	if q.Agent != "" && ev.Agent != q.Agent {
		return false
	}
	if q.Space != "" && ev.Space != q.Space {
		return false
	}
	return true
}

// query reads the file backwards in growing chunks until limit matches.
func query(path string, q protocol.AuditQuery) ([]protocol.AuditEvent, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	var out []protocol.AuditEvent // newest first while collecting
	chunk := int64(64 << 10)
	end := size
	var carry []byte // partial first line of the previous (later) chunk
	for end > 0 && len(out) < limit {
		start := end - chunk
		if start < 0 {
			start = 0
		}
		buf := make([]byte, end-start)
		if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		buf = append(buf, carry...)
		lines := bytes.Split(buf, []byte("\n"))
		first := 0
		if start > 0 {
			carry = lines[0] // may be partial; prepend to the next chunk
			first = 1
		} else {
			carry = nil
		}
		for i := len(lines) - 1; i >= first && len(out) < limit; i-- {
			line := bytes.TrimSpace(lines[i])
			if len(line) == 0 {
				continue
			}
			var ev protocol.AuditEvent
			if json.Unmarshal(line, &ev) != nil {
				continue
			}
			if matches(ev, q) {
				out = append(out, ev)
			}
		}
		end = start
		chunk *= 2
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func follow(ctx context.Context, path string, fn func(protocol.AuditEvent)) error {
	var offset int64 = -1
	var partial []byte
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		fi, err := os.Stat(path)
		if err != nil && offset < 0 {
			offset = 0 // the file does not exist yet: deliver everything once it appears
		}
		if err == nil {
			if offset < 0 || fi.Size() < offset {
				if offset < 0 {
					offset = fi.Size() // start at the end
				} else {
					offset = 0 // truncated or rotated
				}
				partial = nil
			}
			if fi.Size() > offset {
				f, err := os.Open(path)
				if err == nil {
					if _, err := f.Seek(offset, io.SeekStart); err == nil {
						r := bufio.NewReader(f)
						for {
							line, err := r.ReadBytes('\n')
							offset += int64(len(line))
							if err != nil {
								partial = append(partial, line...)
								break
							}
							line = append(partial, line...)
							partial = nil
							var ev protocol.AuditEvent
							if json.Unmarshal(bytes.TrimSpace(line), &ev) == nil {
								fn(ev)
							}
						}
					}
					f.Close()
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

var kindNames = map[string]string{
	protocol.AuditDaemonStart:  "DAEMON-UP",
	protocol.AuditDaemonStop:   "DAEMON-DOWN",
	protocol.AuditSessionStart: "SESSION+",
	protocol.AuditSessionEnd:   "SESSION-",
	protocol.AuditGranted:      "GRANTED",
	protocol.AuditApproved:     "APPROVED",
	protocol.AuditApprovedOnce: "APPROVED×1",
	protocol.AuditDenied:       "DENIED",
	protocol.AuditTimeout:      "TIMEOUT",
	protocol.AuditAutoDenied:   "AUTO-DENIED",
	protocol.AuditCancelled:    "CANCELLED",
	protocol.AuditEntered:      "ENTERED",
	protocol.AuditReclaimed:    "RECLAIMED",
	protocol.AuditRevoked:      "REVOKED",
	protocol.AuditHeld:         "HELD",
	protocol.AuditTTLChanged:   "TTL",
	protocol.AuditBlocked:      "BLOCKED",
	protocol.AuditObserved:     "OBSERVED",
	protocol.AuditUnreadable:   "UNREADABLE",
}

const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiDim    = "\x1b[2m"
)

func kindColor(kind string) string {
	switch kind {
	case protocol.AuditApproved, protocol.AuditApprovedOnce, protocol.AuditGranted:
		return ansiGreen
	case protocol.AuditDenied, protocol.AuditTimeout, protocol.AuditAutoDenied, protocol.AuditBlocked, protocol.AuditUnreadable:
		return ansiRed
	case protocol.AuditReclaimed, protocol.AuditRevoked:
		return ansiYellow
	case protocol.AuditEntered, protocol.AuditObserved, protocol.AuditHeld, protocol.AuditTTLChanged:
		return ansiCyan
	}
	return ansiDim
}

// AgentColumn renders "agent·project" for an event.
func AgentColumn(ev protocol.AuditEvent) string {
	name, proj, ok := strings.Cut(ev.AgentID, "@")
	if !ok {
		if ev.Agent != "" {
			return ev.Agent
		}
		if ev.AgentID != "" {
			return ev.AgentID
		}
		return "-"
	}
	if ev.Agent != "" {
		name = ev.Agent
	}
	return name + "·" + filepath.Base(proj)
}

func pad(s string, w int) string {
	n := len([]rune(s))
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

func format(ev protocol.AuditEvent, color bool) string {
	kind, ok := kindNames[ev.Kind]
	if !ok {
		kind = strings.ToUpper(ev.Kind)
	}
	kindCol := pad(kind, 12)
	if color {
		kindCol = kindColor(ev.Kind) + kindCol + ansiReset
	}
	sp := "-"
	if ev.Space != "" {
		if s, err := space.Parse(ev.Space); err == nil {
			sp = strings.TrimSuffix(s.Title(), " Space")
		} else {
			sp = ev.Space
		}
	}
	var d strings.Builder
	switch {
	case ev.Target != "":
		if ev.Op != "" {
			d.WriteString(space.Op(ev.Op).Verb() + " ")
		}
		d.WriteString(ev.Target)
		if ev.Label != "" {
			d.WriteString(" (" + ev.Label + ")")
		}
		if ev.Detail != "" {
			d.WriteString(" · " + ev.Detail)
		}
	case ev.Kind == protocol.AuditSessionStart || ev.Kind == protocol.AuditSessionEnd:
		d.WriteString(ev.Command)
		if ev.Detail != "" {
			d.WriteString(" · " + ev.Detail)
		}
	default:
		d.WriteString(ev.Detail)
	}
	if via, ok := strings.CutPrefix(ev.By, "user:"); ok {
		d.WriteString(" · via " + via)
	}
	return fmt.Sprintf("%s  %s  %s  %s  %s",
		ev.Time.Local().Format("2006-01-02 15:04:05"), pad(AgentColumn(ev), 18), kindCol, pad(sp, 8), strings.TrimSpace(d.String()))
}
