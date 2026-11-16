package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"reclaim/internal/friction"
	"reclaim/internal/lease"
	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

type waiter struct {
	conn  *conn
	reqID uint64
	req   protocol.AccessRequest
}

type prompt struct {
	info    protocol.PromptInfo
	key     lease.Key
	policy  space.Policy
	waiters []*waiter
	cancel  context.CancelFunc // dialog
	done    bool
}

func (p *prompt) dropConn(c *conn) {
	kept := p.waiters[:0]
	for _, w := range p.waiters {
		if w.conn != c {
			kept = append(kept, w)
		}
	}
	p.waiters = kept
}

func (p *prompt) snapshotLocked() protocol.PromptInfo {
	info := p.info
	info.Waiting = len(p.waiters)
	info.MoreTargets = nil
	seen := map[string]bool{info.TargetKey: true}
	for _, w := range p.waiters {
		if seen[w.req.TargetKey] {
			continue
		}
		seen[w.req.TargetKey] = true
		info.MoreTargets = append(info.MoreTargets, protocol.Waiter{Target: w.req.Target, TargetKey: w.req.TargetKey,
			Op: w.req.Op, Label: w.req.Label, SessionID: w.req.SessionID, Command: lastCmd(w.req.Chain)})
	}
	return info
}

func lastCmd(chain []protocol.ProcInfo) string {
	if len(chain) == 0 {
		return ""
	}
	return chain[len(chain)-1].Cmdline
}

func newPromptID() string {
	b := make([]byte, 2)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func cooldownKey(agentID string, sp space.Space, target string) string {
	return agentID + "|" + sp.String() + "|" + target
}

// access handles an AccessRequest from a session.
func (d *daemon) access(c *conn, reqID uint64, req protocol.AccessRequest) {
	sp, err := space.Parse(req.Space)
	if err != nil || !sp.UserFacing() {
		c.reply(reqID, protocol.TypeDecision, protocol.Decision{Scope: protocol.ScopeError, Reason: "bad space"})
		return
	}
	if c.session == nil {
		c.reply(reqID, protocol.TypeDecision, protocol.Decision{Scope: protocol.ScopeError, Reason: "not a session"})
		return
	}
	req.AgentID = c.session.info.AgentID
	req.SessionID = c.session.info.ID
	key := lease.Key{AgentID: req.AgentID, Space: sp}
	d.mu.Lock()
	if l, open := d.table.Open(key); open {
		d.mu.Unlock()
		info := l.Info()
		c.reply(reqID, protocol.TypeDecision, protocol.Decision{Allow: true, Scope: protocol.ScopeLease, Lease: &info})
		return
	}
	if at, ok := d.cooldowns[cooldownKey(req.AgentID, sp, req.TargetKey)]; ok && d.now().Sub(at) < d.cfg.Prompt.DenyCooldown.Duration {
		d.mu.Unlock()
		c.reply(reqID, protocol.TypeDecision, protocol.Decision{Scope: protocol.ScopeCooldown, Reason: "denied moments ago"})
		d.audit(protocol.AuditEvent{Kind: protocol.AuditAutoDenied, AgentID: req.AgentID, Agent: c.session.info.Agent, SessionID: req.SessionID,
			Space: sp.String(), Op: req.Op, Target: req.Target, Label: req.Label, Detail: "denied " + space.HumanDuration(d.now().Sub(at)) + " ago", Command: lastCmd(req.Chain)})
		return
	}
	w := &waiter{conn: c, reqID: reqID, req: req}
	if p, ok := d.byKey[key]; ok {
		p.waiters = append(p.waiters, w)
		d.mu.Unlock()
		d.touchState()
		return
	}
	p := d.newPromptLocked(key, c.session.info.Agent, []*waiter{w}, d.now().Add(d.cfg.Prompt.Timeout.Duration))
	d.mu.Unlock()
	d.announce(p)
}

// newPromptLocked creates and registers a prompt for the waiters (the first
// one is the primary target). Caller holds d.mu.
func (d *daemon) newPromptLocked(key lease.Key, agent string, waiters []*waiter, deadline time.Time) *prompt {
	req := waiters[0].req
	pol := d.policyLocked(key.Space)
	base := pol.Friction
	if f, err := space.ParseFriction(req.Friction); err == nil && f != space.FrictionNone {
		base = f
	}
	known := d.table.KnownTarget(key, req.TargetKey)
	unexpected := key.Space == space.Remote && !known
	recent := 0
	cut := d.now().Add(-60 * time.Second)
	for _, t := range d.approvals {
		if t.After(cut) {
			recent++
		}
	}
	level := friction.Level(base, unexpected, known, recent)
	id := newPromptID()
	for d.prompts[id] != nil {
		id = newPromptID()
	}
	now := d.now()
	// A prompt must stay answerable past its arming delay.
	if min := now.Add(friction.ArmDelay(level) + 2*time.Second); deadline.Before(min) {
		deadline = min
	}
	info := protocol.PromptInfo{ID: id, SessionID: req.SessionID, AgentID: key.AgentID, Agent: agent, Space: key.Space.String(),
		Op: req.Op, Target: req.Target, TargetKey: req.TargetKey, Label: req.Label, Detail: req.Detail, Syscall: req.Syscall,
		Chain: req.Chain, Cwd: req.Cwd, FromSpace: req.FromSpace, Why: d.table.Why(key, agent), Friction: level.String(),
		Unexpected: unexpected, ArmDelay: protocol.Duration(friction.ArmDelay(level)), AllowOnce: pol.AllowOnce,
		LeaseText: friction.LeaseText(pol), CreatedAt: now, Deadline: deadline}
	if level == space.FrictionHigh {
		info.Challenge = friction.Challenge(d.lastWord)
		d.lastWord = info.Challenge
	}
	p := &prompt{info: info, key: key, policy: pol, waiters: waiters}
	d.prompts[id] = p
	d.byKey[key] = p
	return p
}

// announce delivers a new prompt to the user: desktop notification, and a
// dialog when no console is attached.
func (d *daemon) announce(p *prompt) {
	d.touchState()
	d.mu.Lock()
	info := p.snapshotLocked()
	ui := d.uiAttachedLocked()
	d.mu.Unlock()
	d.notifier.Notify(info)
	mode := d.cfg.Prompt.Dialog
	if mode == "never" || (mode == "auto" && ui) || !d.notifier.DialogAvailable() {
		return
	}
	ctx, cancel := context.WithDeadline(d.ctx, info.Deadline)
	d.mu.Lock()
	if p.done {
		d.mu.Unlock()
		cancel()
		return
	}
	p.cancel = cancel
	d.mu.Unlock()
	go func() {
		defer cancel()
		for ctx.Err() == nil {
			d.mu.Lock()
			info := p.snapshotLocked()
			d.mu.Unlock()
			action, challenge, err := d.notifier.Dialog(ctx, info)
			if err != nil {
				return
			}
			err = d.answer(protocol.Answer{PromptID: info.ID, Action: action, Challenge: challenge, Via: "dialog"})
			if err == nil || !strings.HasPrefix(err.Error(), "too fast") && !strings.HasPrefix(err.Error(), "wrong word") {
				return
			}
			// Answered before the arming delay or with the wrong word: show it again.
		}
	}()
}

// answer resolves a prompt on the user's behalf.
func (d *daemon) answer(a protocol.Answer) error {
	d.mu.Lock()
	p, ok := d.prompts[a.PromptID]
	if !ok || p.done {
		d.mu.Unlock()
		return fmt.Errorf("no pending prompt %q", a.PromptID)
	}
	now := d.now()
	armedAt := p.info.CreatedAt.Add(p.info.ArmDelay.D())
	if a.Action != protocol.ActionDeny && now.Before(armedAt) {
		d.mu.Unlock()
		return fmt.Errorf("too fast: read the prompt; it accepts answers in %s", space.HumanDuration(armedAt.Sub(now).Round(time.Second)+time.Second))
	}
	switch a.Action {
	case protocol.ActionAllow, protocol.ActionOnce:
		if p.info.Challenge != "" && !friction.Verify(p.info.Challenge, a.Challenge) {
			d.mu.Unlock()
			return fmt.Errorf("wrong word: type %q to approve", p.info.Challenge)
		}
		if a.Action == protocol.ActionOnce && !p.info.AllowOnce {
			d.mu.Unlock()
			return errors.New("this space does not offer allow-once")
		}
	case protocol.ActionDeny:
	default:
		d.mu.Unlock()
		return fmt.Errorf("unknown action %q", a.Action)
	}
	via := "user:" + a.Via
	if a.Via == "" {
		via = "user:cli"
	}
	switch a.Action {
	case protocol.ActionAllow:
		l := d.table.Grant(p.key, p.info.Agent, p.policy.Kind, p.policy.TTL, protocol.SourcePrompt)
		for _, w := range p.waiters {
			d.table.RememberTarget(p.key, w.req.TargetKey)
		}
		d.approvals = append(d.approvals, now)
		if len(d.approvals) > 50 {
			d.approvals = d.approvals[len(d.approvals)-50:]
		}
		d.pushLeaseLocked(l, true, "")
		d.mu.Unlock()
		info := l.Info()
		d.resolve(p, protocol.Decision{Allow: true, Scope: protocol.ScopeLease, Lease: &info}, protocol.AuditApproved, via, nil)
		d.markDirty()
	case protocol.ActionOnce:
		d.table.RememberTarget(p.key, p.info.TargetKey)
		d.approvals = append(d.approvals, now)
		var rest []*waiter
		for _, w := range p.waiters {
			if w.req.TargetKey != p.info.TargetKey {
				rest = append(rest, w)
			}
		}
		d.mu.Unlock()
		d.resolve(p, protocol.Decision{Allow: true, Scope: protocol.ScopeOnce}, protocol.AuditApprovedOnce, via, rest)
		d.markDirty()
	case protocol.ActionDeny:
		for _, w := range p.waiters {
			d.cooldowns[cooldownKey(p.key.AgentID, p.key.Space, w.req.TargetKey)] = now
		}
		d.table.NoteDenied(p.key)
		d.mu.Unlock()
		d.resolve(p, protocol.Decision{Scope: protocol.ScopeDeny, Reason: "denied by user"}, protocol.AuditDenied, via, nil)
	}
	return nil
}

// resolve answers every waiter of p (except those in rest, which get a new
// prompt), audits, and removes the prompt.
func (d *daemon) resolve(p *prompt, dec protocol.Decision, auditKind, by string, rest []*waiter) {
	d.mu.Lock()
	if p.done {
		d.mu.Unlock()
		return
	}
	p.done = true
	delete(d.prompts, p.info.ID)
	if d.byKey[p.key] == p {
		delete(d.byKey, p.key)
	}
	if p.cancel != nil {
		p.cancel()
	}
	restSet := map[*waiter]bool{}
	for _, w := range rest {
		restSet[w] = true
	}
	var answered []*waiter
	for _, w := range p.waiters {
		if !restSet[w] {
			answered = append(answered, w)
		}
	}
	var next *prompt
	if len(rest) > 0 {
		next = d.newPromptLocked(p.key, p.info.Agent, rest, p.info.Deadline)
	}
	d.mu.Unlock()
	for _, w := range answered {
		w.conn.reply(w.reqID, protocol.TypeDecision, dec)
	}
	detail := ""
	switch auditKind {
	case protocol.AuditApproved:
		detail = friction.LeaseText(p.policy)
	case protocol.AuditTimeout:
		detail = "no answer within " + space.HumanDuration(d.cfg.Prompt.Timeout.Duration)
	}
	if n := len(answered); n > 1 {
		detail = strings.TrimSpace(detail + fmt.Sprintf(" · %d operations", n))
	}
	if auditKind != "" {
		d.audit(protocol.AuditEvent{Kind: auditKind, AgentID: p.key.AgentID, Agent: p.info.Agent, SessionID: p.info.SessionID,
			Space: p.key.Space.String(), Op: p.info.Op, Target: p.info.Target, Label: p.info.Label, Detail: detail, By: by,
			Command: lastCmd(p.info.Chain)})
	}
	if next != nil {
		d.announce(next)
	}
	d.touchState()
}

func (d *daemon) cancelRequest(c *conn, reqID uint64) {
	d.mu.Lock()
	var empty *prompt
	for _, p := range d.prompts {
		kept := p.waiters[:0]
		for _, w := range p.waiters {
			if w.conn == c && w.reqID == reqID {
				continue
			}
			kept = append(kept, w)
		}
		p.waiters = kept
		if len(p.waiters) == 0 {
			empty = p
		}
	}
	d.mu.Unlock()
	if empty != nil {
		d.resolve(empty, protocol.Decision{Scope: protocol.ScopeCancelled}, protocol.AuditCancelled, "session", nil)
	}
	d.touchState()
}

func (d *daemon) expirePrompts() {
	now := d.now()
	d.mu.Lock()
	var expired []*prompt
	for _, p := range d.prompts {
		if !now.Before(p.info.Deadline) {
			expired = append(expired, p)
		}
	}
	d.mu.Unlock()
	for _, p := range expired {
		d.resolve(p, protocol.Decision{Scope: protocol.ScopeTimeout, Reason: "no answer"}, protocol.AuditTimeout, "timer", nil)
	}
}
