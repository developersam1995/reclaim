package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"reclaim/internal/audit"
	"reclaim/internal/lease"
	"reclaim/internal/protocol"
	"reclaim/internal/space"
	"reclaim/internal/supervisor/procfs"
)

// conn is one client connection.
type conn struct {
	d          *daemon
	nc         net.Conn
	codec      *protocol.Codec
	role       string
	peerPID    int
	subscribed bool
	session    *session
	closeOnce  sync.Once
}

func (c *conn) push(typ string, body any) {
	if err := c.codec.Write(typ, 0, body); err != nil {
		c.close()
	}
}

func (c *conn) reply(id uint64, typ string, body any) {
	if err := c.codec.Write(typ, id, body); err != nil {
		c.close()
	}
}

func (c *conn) errorf(id uint64, format string, args ...any) {
	c.reply(id, protocol.TypeError, protocol.Error{Message: fmt.Sprintf(format, args...)})
}

func (c *conn) close() { c.closeOnce.Do(func() { c.nc.Close() }) }

// insideSession reports whether the peer process runs under a supervised
// session (and therefore may not widen access).
func (c *conn) insideSession() bool {
	if c.peerPID <= 0 {
		return true // unknown: be safe
	}
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	for _, s := range c.d.sessions {
		if c.peerPID == s.info.LauncherPID || procfs.IsDescendant(c.peerPID, s.info.LauncherPID) {
			return true
		}
	}
	return false
}

func peerCred(nc net.Conn) (uid, pid int, err error) {
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		return -1, -1, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, -1, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return -1, -1, err
	}
	if cerr != nil {
		return -1, -1, cerr
	}
	return int(cred.Uid), int(cred.Pid), nil
}

func (d *daemon) serve(nc net.Conn) {
	c := &conn{d: d, nc: nc, codec: protocol.NewCodec(nc)}
	defer c.close()
	uid, pid, err := peerCred(nc)
	if err != nil || uid != os.Getuid() {
		d.logf("rejecting connection: uid %d (%v)", uid, err)
		return
	}
	c.peerPID = pid
	nc.SetReadDeadline(time.Now().Add(10 * time.Second))
	env, err := c.codec.Read()
	if err != nil {
		return
	}
	nc.SetReadDeadline(time.Time{})
	if env.Type != protocol.TypeHello {
		c.errorf(env.ID, "expected hello")
		return
	}
	hello, err := protocol.Decode[protocol.Hello](env)
	if err != nil {
		c.errorf(env.ID, "%v", err)
		return
	}
	if hello.Version != protocol.Version {
		c.errorf(env.ID, "protocol version %d not supported (daemon speaks %d)", hello.Version, protocol.Version)
		return
	}
	switch hello.Role {
	case protocol.RoleSession, protocol.RoleUI, protocol.RoleCLI:
	default:
		c.errorf(env.ID, "unknown role %q", hello.Role)
		return
	}
	c.role = hello.Role
	w, err := d.register(c, hello)
	if err != nil {
		c.errorf(env.ID, "%v", err)
		return
	}
	c.reply(env.ID, protocol.TypeWelcome, w)
	defer d.unregister(c)
	for {
		env, err := c.codec.Read()
		if err != nil {
			return
		}
		c.handle(env)
	}
}

func (d *daemon) register(c *conn, hello protocol.Hello) (protocol.Welcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := protocol.Welcome{Version: protocol.Version, DaemonPID: os.Getpid(), Policies: d.policiesInfoLocked(),
		PromptTimeout: protocol.Duration(d.cfg.Prompt.Timeout.Duration)}
	d.conns[c] = struct{}{}
	if hello.Role != protocol.RoleSession {
		return w, nil
	}
	if hello.Session == nil || hello.Session.AgentID == "" {
		return w, errors.New("session hello needs session info")
	}
	info := *hello.Session
	resumed := false
	if hello.Resume != "" {
		if old, ok := d.sessions[hello.Resume]; ok {
			old.conn.close()
			delete(d.sessions, hello.Resume)
		}
		info.ID = hello.Resume
		resumed = true
	} else {
		d.seq++
		info.ID = fmt.Sprintf("s%d-%d", os.Getpid()%1000, d.seq)
	}
	if info.StartedAt.IsZero() {
		info.StartedAt = d.now()
	}
	s := &session{info: info, conn: c}
	c.session = s
	d.sessions[info.ID] = s
	w.SessionID = info.ID
	if !resumed {
		d.mu.Unlock()
		d.audit(protocol.AuditEvent{Kind: protocol.AuditSessionStart, AgentID: info.AgentID, Agent: info.Agent,
			SessionID: info.ID, Command: strings.Join(info.Command, " "), Detail: "pid " + fmt.Sprint(info.AgentPID)})
		d.mu.Lock()
		pp := d.policyLocked(space.Project)
		k := lease.Key{AgentID: info.AgentID, Space: space.Project}
		if pp.GrantOnLaunch && !info.Observe {
			if _, open := d.table.Open(k); !open {
				l := d.table.Grant(k, info.Agent, pp.Kind, pp.TTL, protocol.SourceLaunch)
				d.mu.Unlock()
				d.audit(protocol.AuditEvent{Kind: protocol.AuditGranted, AgentID: info.AgentID, Agent: info.Agent,
					SessionID: info.ID, Space: "project", Detail: "opened at launch, " + leaseDetail(l), By: "launch"})
				d.markDirty()
				d.mu.Lock()
				d.pushLeaseLocked(l, true, "")
			}
		}
	}
	for _, l := range d.table.Leases() {
		if l.AgentID == info.AgentID {
			w.Leases = append(w.Leases, l.Info())
		}
	}
	d.touchState()
	return w, nil
}

func leaseDetail(l lease.Lease) string {
	if l.Kind == space.Fixed {
		return "fixed " + space.HumanDuration(l.TTL)
	}
	return "until " + space.HumanDuration(l.TTL) + " idle"
}

func (d *daemon) unregister(c *conn) {
	d.mu.Lock()
	delete(d.conns, c)
	s := c.session
	if s != nil && d.sessions[s.info.ID] == s {
		delete(d.sessions, s.info.ID)
	} else {
		s = nil
	}
	// Drop this connection's waiters from every prompt.
	var empty []*prompt
	for _, p := range d.prompts {
		p.dropConn(c)
		if len(p.waiters) == 0 {
			empty = append(empty, p)
		}
	}
	d.mu.Unlock()
	for _, p := range empty {
		d.resolve(p, protocol.Decision{Scope: protocol.ScopeCancelled}, protocol.AuditCancelled, "session", nil)
	}
	if s != nil {
		d.audit(protocol.AuditEvent{Kind: protocol.AuditSessionEnd, AgentID: s.info.AgentID, Agent: s.info.Agent,
			SessionID: s.info.ID, Command: strings.Join(s.info.Command, " ")})
	}
	d.touchState()
}

func (c *conn) handle(env protocol.Envelope) {
	d := c.d
	switch env.Type {
	case protocol.TypeAccess:
		req, err := protocol.Decode[protocol.AccessRequest](env)
		if err != nil {
			c.errorf(env.ID, "%v", err)
			return
		}
		d.access(c, env.ID, req)
	case protocol.TypeCancel:
		body, _ := protocol.Decode[protocol.Cancel](env)
		d.cancelRequest(c, body.RequestID)
	case protocol.TypeTouch:
		body, err := protocol.Decode[protocol.Touch](env)
		if err == nil {
			d.touch(c, body)
		}
	case protocol.TypeEvent:
		body, err := protocol.Decode[protocol.SessionEvent](env)
		if err == nil && c.session != nil {
			d.sessionEvent(c.session, body)
		}
	case protocol.TypeStatus:
		c.reply(env.ID, protocol.TypeState, d.state())
	case protocol.TypeSubscribe:
		d.mu.Lock()
		c.subscribed = true
		d.mu.Unlock()
		c.reply(env.ID, protocol.TypeOK, protocol.OK{})
		c.push(protocol.TypeState, d.state())
		d.touchState()
	case protocol.TypeAnswer:
		body, err := protocol.Decode[protocol.Answer](env)
		if err != nil {
			c.errorf(env.ID, "%v", err)
			return
		}
		if c.insideSession() {
			c.errorf(env.ID, "answers from inside an agent session are not accepted")
			return
		}
		if err := d.answer(body); err != nil {
			c.errorf(env.ID, "%v", err)
			return
		}
		c.reply(env.ID, protocol.TypeOK, protocol.OK{})
	case protocol.TypeReclaim:
		body, _ := protocol.Decode[protocol.ReclaimRequest](env)
		n, err := d.reclaimNow(body)
		if err != nil {
			c.errorf(env.ID, "%v", err)
			return
		}
		c.reply(env.ID, protocol.TypeReclaimResult, protocol.ReclaimResult{Revoked: n})
	case protocol.TypeHold:
		body, err := protocol.Decode[protocol.HoldRequest](env)
		if err != nil {
			c.errorf(env.ID, "%v", err)
			return
		}
		if c.insideSession() {
			c.errorf(env.ID, "holds from inside an agent session are not accepted")
			return
		}
		msg, err := d.hold(body)
		if err != nil {
			c.errorf(env.ID, "%v", err)
			return
		}
		c.reply(env.ID, protocol.TypeOK, protocol.OK{Message: msg})
	case protocol.TypeSetTTL:
		body, err := protocol.Decode[protocol.SetTTLRequest](env)
		if err != nil {
			c.errorf(env.ID, "%v", err)
			return
		}
		if c.insideSession() {
			c.errorf(env.ID, "ttl changes from inside an agent session are not accepted")
			return
		}
		msg, err := d.setTTL(body)
		if err != nil {
			c.errorf(env.ID, "%v", err)
			return
		}
		c.reply(env.ID, protocol.TypeOK, protocol.OK{Message: msg})
	case protocol.TypeAudit:
		body, _ := protocol.Decode[protocol.AuditQuery](env)
		evs, err := audit.Query(d.paths.AuditFile, body)
		if err != nil {
			c.errorf(env.ID, "%v", err)
			return
		}
		c.reply(env.ID, protocol.TypeAuditResult, protocol.AuditResult{Events: evs})
	case protocol.TypeShutdown:
		if c.insideSession() {
			c.errorf(env.ID, "shutdown from inside an agent session is not accepted")
			return
		}
		c.reply(env.ID, protocol.TypeOK, protocol.OK{Message: "stopping"})
		d.cancel()
	default:
		c.errorf(env.ID, "unknown message type %q", env.Type)
	}
}

// ── touches & events ─────────────────────────────────────────────────────

func (d *daemon) touch(c *conn, t protocol.Touch) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c.session != nil && t.Current != "" {
		c.session.info.CurrentSpace = t.Current
	}
	for name, at := range t.Used {
		sp, err := space.Parse(name)
		if err != nil {
			continue
		}
		k := lease.Key{AgentID: t.AgentID, Space: sp}
		l, open := d.table.Open(k)
		if !open || (at.Gen != 0 && l.Gen != at.Gen) {
			// Stale: tell the session so it drops its cache entry.
			stale := protocol.LeaseInfo{AgentID: t.AgentID, Space: name, Gen: d.table.Gen()}
			if open {
				stale = l.Info()
			}
			c.push(protocol.TypeLease, protocol.LeaseUpdate{Lease: stale, Open: open, Reason: "stale"})
			continue
		}
		d.table.Touch(k, at.At)
	}
	d.dirty = true
}

func (d *daemon) sessionEvent(s *session, ev protocol.SessionEvent) {
	kind := map[string]string{
		protocol.EventEntered: protocol.AuditEntered, protocol.EventBlocked: protocol.AuditBlocked,
		protocol.EventObserved: protocol.AuditObserved, "unreadable": protocol.AuditUnreadable,
	}[ev.Kind]
	if kind == "" {
		return
	}
	d.audit(protocol.AuditEvent{Kind: kind, AgentID: s.info.AgentID, Agent: s.info.Agent, SessionID: s.info.ID,
		Space: ev.Space, Op: ev.Op, Target: ev.Target, Label: ev.Label, Detail: ev.Detail, Command: ev.Command, By: "session"})
}

// ── user controls ────────────────────────────────────────────────────────

func (d *daemon) reclaimNow(req protocol.ReclaimRequest) (int, error) {
	var sp space.Space
	if req.Space != "" {
		var err error
		if sp, err = space.Parse(req.Space); err != nil {
			return 0, err
		}
	}
	closures := d.table.RevokeWhere(func(k lease.Key) bool {
		if req.Space != "" && k.Space != sp {
			return false
		}
		return matchAgent(k.AgentID, req.Agent, req.AgentID)
	}, lease.CauseManual)
	d.closeLeases(closures, protocol.AuditRevoked, "user:cli")
	return len(closures), nil
}

func (d *daemon) hold(req protocol.HoldRequest) (string, error) {
	sp, err := space.Parse(req.Space)
	if err != nil || !sp.UserFacing() {
		return "", fmt.Errorf("unknown space %q", req.Space)
	}
	if req.Duration.D() < time.Second {
		return "", errors.New("hold duration must be at least 1s")
	}
	d.mu.Lock()
	agents := map[string]string{} // AgentID → name
	for _, s := range d.sessions {
		if matchAgent(s.info.AgentID, req.Agent, req.AgentID) {
			agents[s.info.AgentID] = s.info.Agent
		}
	}
	for _, l := range d.table.Leases() {
		if matchAgent(l.AgentID, req.Agent, req.AgentID) {
			agents[l.AgentID] = l.Agent
		}
	}
	p := d.policyLocked(sp)
	var held []lease.Lease
	for id, name := range agents {
		held = append(held, d.table.Hold(lease.Key{AgentID: id, Space: sp}, name, p.Kind, p.TTL, req.Duration.D()))
	}
	for _, l := range held {
		d.pushLeaseLocked(l, true, "")
	}
	d.mu.Unlock()
	if len(held) == 0 {
		return "", errors.New("no matching agent (no live session or open lease)")
	}
	for _, l := range held {
		d.audit(protocol.AuditEvent{Kind: protocol.AuditHeld, AgentID: l.AgentID, Agent: l.Agent, Space: sp.String(),
			Detail: "held for " + space.HumanDuration(req.Duration.D()), By: "user:cli"})
	}
	d.markDirty()
	return fmt.Sprintf("%s held open for %s for %d agent(s)", sp.Title(), space.HumanDuration(req.Duration.D()), len(held)), nil
}

func (d *daemon) setTTL(req protocol.SetTTLRequest) (string, error) {
	sp, err := space.Parse(req.Space)
	if err != nil || !sp.UserFacing() {
		return "", fmt.Errorf("unknown space %q", req.Space)
	}
	d.mu.Lock()
	var ttl time.Duration
	if req.Reset {
		delete(d.ttlOverrides, sp)
		ttl = d.base[sp].TTL
	} else {
		if req.TTL.D() < time.Second {
			d.mu.Unlock()
			return "", errors.New("ttl must be at least 1s")
		}
		ttl = req.TTL.D()
		d.ttlOverrides[sp] = ttl
	}
	n := d.table.ApplyTTL(sp, ttl)
	d.dirty = true
	d.mu.Unlock()
	d.saveState()
	msg := fmt.Sprintf("%s lease is now %s (%d open lease(s) updated)", sp.Title(), space.HumanDuration(ttl), n)
	d.audit(protocol.AuditEvent{Kind: protocol.AuditTTLChanged, Space: sp.String(), Detail: msg, By: "user:cli"})
	return msg, nil
}
