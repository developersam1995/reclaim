package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"reclaim/internal/audit"
	"reclaim/internal/config"
	"reclaim/internal/lease"
	"reclaim/internal/notify"
	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

var errAlreadyRunning = errors.New("reclaim daemon already running")

// persisted is the on-disk state.json.
type persisted struct {
	Leases       lease.Snapshot    `json:"leases"`
	TTLOverrides map[string]string `json:"ttl_overrides,omitempty"` // space name → duration string
}

type daemon struct {
	opts     Options
	paths    config.Paths
	cfg      config.Config
	now      func() time.Time
	table    *lease.Table
	log      *audit.Log
	notifier Notifier
	logf     func(string, ...any)

	ctx    context.Context
	cancel context.CancelFunc

	mu           sync.Mutex
	base         map[space.Space]space.Policy // from config
	ttlOverrides map[space.Space]time.Duration
	sessions     map[string]*session
	conns        map[*conn]struct{}
	prompts      map[string]*prompt
	byKey        map[lease.Key]*prompt
	cooldowns    map[string]time.Time // AgentID|space|targetKey → denied at
	approvals    []time.Time
	lastWord     string
	startedAt    time.Time
	dirty        bool
	seq          uint64

	changed chan struct{}
}

func run(ctx context.Context, opts Options) error {
	d := &daemon{opts: opts, paths: opts.Paths, cfg: opts.Config, now: opts.Now, notifier: opts.Notifier, logf: opts.Logf,
		sessions: map[string]*session{}, conns: map[*conn]struct{}{}, prompts: map[string]*prompt{},
		byKey: map[lease.Key]*prompt{}, cooldowns: map[string]time.Time{}, ttlOverrides: map[space.Space]time.Duration{},
		changed: make(chan struct{}, 1)}
	if d.now == nil {
		d.now = func() time.Time { return time.Now().Round(0) }
	}
	if d.logf == nil {
		d.logf = log.Printf
	}
	if d.notifier == nil {
		d.notifier = defaultNotifier{cfg: d.cfg.Prompt}
	}
	var err error
	if d.base, err = d.cfg.Policies(); err != nil {
		return err
	}
	if err := d.paths.EnsureDirs(); err != nil {
		return err
	}
	lockFD, err := unix.Open(d.paths.LockFile, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("open lock %s: %w", d.paths.LockFile, err)
	}
	defer unix.Close(lockFD)
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errAlreadyRunning
	}
	d.table = lease.NewTable(d.now)
	d.loadState()
	if d.log, err = audit.Open(d.paths.AuditFile); err != nil {
		return err
	}
	defer d.log.Close()

	_ = os.Remove(d.paths.Socket)
	ln, err := net.Listen("unix", d.paths.Socket)
	if err != nil {
		return fmt.Errorf("listen %s: %w", d.paths.Socket, err)
	}
	_ = os.Chmod(d.paths.Socket, 0o600)
	defer os.Remove(d.paths.Socket)

	d.ctx, d.cancel = context.WithCancel(ctx)
	defer d.cancel()
	d.startedAt = d.now()
	d.audit(protocol.AuditEvent{Kind: protocol.AuditDaemonStart, Detail: fmt.Sprintf("pid %d", os.Getpid())})
	d.logf("reclaim daemon listening on %s", d.paths.Socket)

	// Expired leases from a previous run are reported by the first sweep.
	d.sweep()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); d.sweeper() }()
	go func() { defer wg.Done(); d.pusher() }()
	go func() {
		<-d.ctx.Done()
		ln.Close()
	}()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if d.ctx.Err() != nil {
				break
			}
			d.logf("accept: %v", err)
			continue
		}
		go d.serve(nc)
	}
	d.shutdown()
	wg.Wait()
	d.saveState()
	d.audit(protocol.AuditEvent{Kind: protocol.AuditDaemonStop})
	return nil
}

// ── policies ─────────────────────────────────────────────────────────────

func (d *daemon) policyLocked(sp space.Space) space.Policy {
	p := d.base[sp]
	if ttl, ok := d.ttlOverrides[sp]; ok {
		p.TTL = ttl
	}
	return p
}

func (d *daemon) policiesInfoLocked() map[string]protocol.PolicyInfo {
	out := map[string]protocol.PolicyInfo{}
	for _, sp := range space.All {
		p := d.policyLocked(sp)
		ops := make([]string, len(p.GatedOps))
		for i, o := range p.GatedOps {
			ops[i] = string(o)
		}
		out[sp.String()] = protocol.PolicyInfo{Kind: string(p.Kind), TTL: protocol.Duration(p.TTL),
			Friction: p.Friction.String(), GatedOps: ops, AllowOnce: p.AllowOnce, GrantOnLaunch: p.GrantOnLaunch}
	}
	return out
}

// ── persistence ──────────────────────────────────────────────────────────

func (d *daemon) loadState() {
	b, err := os.ReadFile(d.paths.StateFile)
	if err != nil {
		return
	}
	var st persisted
	if err := json.Unmarshal(b, &st); err != nil {
		d.logf("state.json unreadable, starting fresh: %v", err)
		return
	}
	d.table.Restore(st.Leases)
	for name, ds := range st.TTLOverrides {
		sp, err := space.Parse(name)
		dur, derr := time.ParseDuration(ds)
		if err == nil && derr == nil {
			d.ttlOverrides[sp] = dur
		}
	}
}

func (d *daemon) saveState() {
	d.mu.Lock()
	st := persisted{Leases: d.table.Snapshot(), TTLOverrides: map[string]string{}}
	for sp, ttl := range d.ttlOverrides {
		st.TTLOverrides[sp.String()] = ttl.String()
	}
	d.dirty = false
	d.mu.Unlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	tmp := d.paths.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		d.logf("save state: %v", err)
		return
	}
	if err := os.Rename(tmp, d.paths.StateFile); err != nil {
		d.logf("save state: %v", err)
	}
}

// ── audit & change notification ──────────────────────────────────────────

func (d *daemon) audit(ev protocol.AuditEvent) {
	if ev.Time.IsZero() {
		ev.Time = d.now()
	}
	if err := d.log.Append(ev); err != nil {
		d.logf("audit: %v", err)
	}
	d.touchState()
}

func (d *daemon) touchState() {
	select {
	case d.changed <- struct{}{}:
	default:
	}
}

func (d *daemon) markDirty() {
	d.mu.Lock()
	d.dirty = true
	d.mu.Unlock()
}

// ── sessions & agents ────────────────────────────────────────────────────

type session struct {
	info protocol.SessionInfo
	conn *conn
}

func agentName(agentID string) string {
	name, _, _ := strings.Cut(agentID, "@")
	return name
}

// matchAgent reports whether agentID matches a name (every AgentID of that
// agent) or an exact AgentID.
func matchAgent(agentID, name, exact string) bool {
	if exact != "" && agentID != exact {
		return false
	}
	if name != "" && agentName(agentID) != name && agentID != name {
		return false
	}
	return true
}

func (d *daemon) sessionsOfLocked(agentID string) []*session {
	var out []*session
	for _, s := range d.sessions {
		if s.info.AgentID == agentID {
			out = append(out, s)
		}
	}
	return out
}

func (d *daemon) pushLeaseLocked(l lease.Lease, open bool, reason string) {
	upd := protocol.LeaseUpdate{Lease: l.Info(), Open: open, Reason: reason}
	for _, s := range d.sessionsOfLocked(l.AgentID) {
		s.conn.push(protocol.TypeLease, upd)
	}
}

// closeLeases audits and pushes closures (caller must NOT hold d.mu).
func (d *daemon) closeLeases(closures []lease.Closure, kind, by string) {
	for _, c := range closures {
		detail := ""
		switch c.Cause {
		case lease.CauseIdle:
			detail = "after " + space.HumanDuration(c.IdleFor) + " of inactivity"
		case lease.CauseExpired:
			detail = "fixed " + space.HumanDuration(c.Lease.TTL) + " lease ended"
		case lease.CauseHoldEnded:
			detail = "hold ended"
		case lease.CauseManual:
			detail = "reclaimed now"
		}
		d.audit(protocol.AuditEvent{Kind: kind, AgentID: c.Lease.AgentID, Agent: c.Lease.Agent,
			Space: c.Lease.Space.String(), Detail: detail, By: by})
		d.mu.Lock()
		d.pushLeaseLocked(c.Lease, false, c.Cause)
		d.mu.Unlock()
	}
	if len(closures) > 0 {
		d.markDirty()
	}
}

// ── sweeper & state pusher ───────────────────────────────────────────────

func (d *daemon) sweep() {
	d.closeLeases(d.table.Sweep(), protocol.AuditReclaimed, "timer")
}

func (d *daemon) sweeper() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	last := d.now()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
		}
		now := d.now()
		if now.Sub(last) > 3*time.Second {
			d.logf("clock jumped %s (suspend?); sweeping", now.Sub(last))
		}
		last = now
		d.sweep()
		d.expirePrompts()
		d.mu.Lock()
		dirty := d.dirty
		d.mu.Unlock()
		if dirty {
			d.saveState()
		}
	}
}

func (d *daemon) pusher() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.changed:
			debounce.Reset(50 * time.Millisecond)
			continue
		case <-debounce.C:
		case <-tick.C:
		}
		st := d.state()
		d.mu.Lock()
		for c := range d.conns {
			if c.subscribed {
				c.push(protocol.TypeState, st)
			}
		}
		d.mu.Unlock()
	}
}

func (d *daemon) state() protocol.State {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := protocol.State{Now: d.now(), DaemonPID: os.Getpid(), StartedAt: d.startedAt, Policies: d.policiesInfoLocked(),
		Recent: d.log.Recent(20)}
	for _, s := range d.sessions {
		st.Sessions = append(st.Sessions, s.info)
	}
	sort.Slice(st.Sessions, func(i, j int) bool { return st.Sessions[i].StartedAt.Before(st.Sessions[j].StartedAt) })
	for _, l := range d.table.Leases() {
		st.Leases = append(st.Leases, l.Info())
	}
	for _, p := range d.prompts {
		st.Prompts = append(st.Prompts, p.snapshotLocked())
	}
	sort.Slice(st.Prompts, func(i, j int) bool { return st.Prompts[i].CreatedAt.Before(st.Prompts[j].CreatedAt) })
	for c := range d.conns {
		if c.subscribed {
			st.UIClients++
		}
	}
	return st
}

func (d *daemon) uiAttachedLocked() bool {
	for c := range d.conns {
		if c.subscribed {
			return true
		}
	}
	return false
}

// ── shutdown ─────────────────────────────────────────────────────────────

func (d *daemon) shutdown() {
	d.mu.Lock()
	conns := make([]*conn, 0, len(d.conns))
	for c := range d.conns {
		conns = append(conns, c)
	}
	prompts := make([]*prompt, 0, len(d.prompts))
	for _, p := range d.prompts {
		prompts = append(prompts, p)
	}
	d.mu.Unlock()
	for _, c := range conns {
		c.push(protocol.TypeStopping, nil)
	}
	for _, p := range prompts {
		d.resolve(p, protocol.Decision{Scope: protocol.ScopeCancelled, Reason: "daemon stopping"}, protocol.AuditCancelled, "daemon", nil)
	}
	for _, c := range conns {
		c.close()
	}
}

// ── default notifier ─────────────────────────────────────────────────────

type defaultNotifier struct{ cfg config.PromptConfig }

func (n defaultNotifier) Notify(p protocol.PromptInfo) {
	if !n.cfg.DesktopNotify {
		return
	}
	title, body := notify.Summary(p)
	_ = notify.Desktop(title, body, p.Friction == space.FrictionHigh.String())
}

func (n defaultNotifier) DialogAvailable() bool { return notify.DialogAvailable() }

func (n defaultNotifier) Dialog(ctx context.Context, p protocol.PromptInfo) (string, string, error) {
	return notify.Dialog(ctx, p)
}
