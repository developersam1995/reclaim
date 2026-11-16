package supervisor

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"reclaim/internal/policy"
	"reclaim/internal/protocol"
	"reclaim/internal/space"
	"reclaim/internal/supervisor/procfs"
	"reclaim/internal/supervisor/seccomp"
)

// target is one classified thing a syscall touches.
type target struct {
	res    policy.Result
	op     space.Op
	gated  bool
	syscal string
}

func (s *session) cont(id uint64) {
	if err := seccomp.Continue(s.notifyFD, id); err != nil && s.opts.Observe {
		s.warnf("continue: %v", err)
	}
}

func (s *session) deny(id uint64) { _ = seccomp.Fail(s.notifyFD, id, unix.EACCES) }

// handle decides one notification. Panics are converted into a denial so the
// agent thread never hangs.
func (s *session) handle(n seccomp.Notif) {
	defer func() {
		if r := recover(); r != nil {
			s.warnf("internal error handling %s: %v", seccomp.Name(n.Data.Nr), r)
			s.deny(n.ID)
		}
	}()
	call, ok := seccomp.Decode(n.Data)
	if !ok {
		s.cont(n.ID)
		return
	}
	tid := int(n.Pid)
	tgid, err := procfs.Tgid(tid)
	if err != nil {
		s.cont(n.ID) // process already gone; the response fails harmlessly
		return
	}
	mem, err := procfs.OpenMem(tid)
	if err != nil {
		s.unreadable(n, call.Name, err)
		return
	}
	defer mem.Close()

	var targets []target
	var syscallText string
	if call.Sock != nil {
		t, text, err := s.decodeSock(mem, call, tgid)
		if err != nil {
			s.unreadable(n, call.Name, err)
			return
		}
		syscallText = text
		if t != nil {
			targets = append(targets, *t)
		}
	} else {
		ts, text, err := s.decodePaths(mem, call, tid, tgid)
		if err != nil {
			s.unreadable(n, call.Name, err)
			return
		}
		syscallText = text
		targets = ts
	}
	if !seccomp.IDValid(s.notifyFD, n.ID) {
		return
	}
	s.decide(n, tgid, call, targets, syscallText)
}

func (s *session) unreadable(n seccomp.Notif, name string, err error) {
	s.deny(n.ID)
	s.sendEvent(protocol.SessionEvent{Kind: "unreadable", Op: name, Target: fmt.Sprintf("pid %d", n.Pid),
		Detail: err.Error(), PID: int(n.Pid), Command: procfs.Cmdline(int(n.Pid), 200)})
}

// decodeSock reads and classifies a sockaddr argument.
func (s *session) decodeSock(mem *procfs.Mem, call seccomp.Call, tgid int) (*target, string, error) {
	ln := int(call.Sock.Len)
	if ln > 256 {
		ln = 256
	}
	if ln < 2 {
		return nil, call.Name + "()", nil // the kernel rejects it
	}
	b, err := mem.Read(call.Sock.Ptr, ln)
	if err != nil {
		return nil, "", err
	}
	st, err := procfs.ParseSockaddr(b)
	if err != nil {
		return nil, call.Name + "()", nil
	}
	if st.Family == "unix" && st.Path != "" {
		raw := st.Path
		if !path.IsAbs(raw) {
			if cwd, err := procfs.Cwd(tgid); err == nil {
				raw = path.Join(cwd, raw)
			}
		}
		st.Path = path.Clean(raw)
		if info, err := procfs.Resolve(tgid, tgid, unix.AT_FDCWD, st.Path, true, false); err == nil {
			st.Resolved = info.Resolved
			if fi, err := os.Stat(st.Resolved); err == nil {
				if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
					st.Dev, st.Ino = uint64(sys.Dev), sys.Ino
				}
			}
		}
	}
	op := call.Sock.Op
	res := s.classif.ClassifySocket(op, st, tgid == s.agentPID, s.cpHosts.lookup)
	text := fmt.Sprintf("%s(%d, %s)", call.Name, call.Sock.FD, res.Display)
	if st.Family == "unix" && op == space.OpConnect {
		// Connecting to a socket that does not exist fails anyway.
		if _, err := os.Stat(st.Path); err != nil && res.Space != space.Control {
			return nil, text, nil
		}
	}
	return &target{res: res, op: op, gated: s.gates(res, op), syscal: text}, text, nil
}

// decodePaths reads, resolves and classifies every path argument.
func (s *session) decodePaths(mem *procfs.Mem, call seccomp.Call, tid, tgid int) ([]target, string, error) {
	var targets []target
	var parts []string
	for _, pa := range call.Paths {
		raw := ""
		if pa.Ptr != 0 {
			var err error
			raw, err = mem.ReadString(pa.Ptr, unix.PathMax)
			if err != nil {
				return nil, "", err
			}
		}
		op := pa.Op
		create, follow := pa.Create, pa.FollowFinal
		if call.HowPtr != 0 { // openat2: flags live in struct open_how
			b, err := mem.Read(call.HowPtr, 8)
			if err != nil {
				return nil, "", err
			}
			flags := binary.LittleEndian.Uint64(b)
			var noFollow, isPath bool
			op, create, noFollow, isPath = seccomp.OpenOp(flags)
			follow = !noFollow
			if isPath {
				return nil, call.Name + "()", nil
			}
		}
		info, err := procfs.Resolve(tid, tgid, pa.Dirfd, raw, follow, pa.EmptyPath)
		if err != nil {
			parts = append(parts, fmt.Sprintf("%q", raw))
			continue // the kernel will fail it (ENOENT/ENOTDIR)
		}
		if op == space.OpRead && info.IsDir {
			op = space.OpList
		}
		res := s.classif.ClassifyPath(policy.PathTarget{Lexical: info.Lexical, Resolved: info.Resolved, SelfPID: tgid})
		parts = append(parts, res.Display)
		t := target{res: res, op: op}
		switch {
		case res.Space == space.Control:
			t.gated = true
		case !s.gates(res, op):
		case !create && !info.Exists:
			// Nothing is touched: the kernel returns ENOENT.
		case create && info.Exists && pa.Role == "link" || create && info.Exists && isExclusive(call):
			// Creating over an existing name fails with EEXIST.
		case op == space.OpWrite && !procfs.Writable(info):
			// Would fail with EACCES anyway.
		default:
			t.gated = true
		}
		targets = append(targets, t)
	}
	text := call.Name + "(" + strings.Join(parts, ", ") + ")"
	if call.Name == "execve" || call.Name == "execveat" {
		if argv, err := mem.ReadStrings(call.ArgvPtr, 32, 200); err == nil && len(argv) > 0 {
			text = call.Name + "(" + strings.Join(argv, " ") + ")"
		}
	}
	return targets, text, nil
}

func isExclusive(call seccomp.Call) bool {
	return call.OpenFlags&unix.O_CREAT != 0 && call.OpenFlags&unix.O_EXCL != 0 ||
		call.Name == "mkdir" || call.Name == "mkdirat" || call.Name == "symlink" || call.Name == "symlinkat"
}

func (s *session) gates(res policy.Result, op space.Op) bool {
	if !res.Space.UserFacing() {
		return false
	}
	return s.policies[res.Space].Gates(op)
}

// decide applies leases and, when needed, asks the daemon.
func (s *session) decide(n seccomp.Notif, tgid int, call seccomp.Call, targets []target, syscallText string) {
	// Touch every classified space the operation uses; pick the most
	// sensitive gated target.
	var pick *target
	for i := range targets {
		t := &targets[i]
		if t.res.Space.UserFacing() {
			first, newT := s.cache.touch(t.res.Space, t.res.Key)
			if first || (newT && t.res.Space != space.Project && t.res.Space != space.Home) {
				if _, open := s.cache.open(t.res.Space); open {
					s.sendEvent(protocol.SessionEvent{Kind: protocol.EventEntered, Space: t.res.Space.String(), Op: string(t.op),
						Target: t.res.Display, Label: t.res.Label, Detail: t.res.Detail, PID: tgid, Command: procfs.Cmdline(tgid, 200)})
				}
			}
		}
		if !t.gated {
			continue
		}
		if pick == nil || t.res.Space.Rank() > pick.res.Space.Rank() {
			pick = t
		}
	}
	if pick == nil {
		s.cont(n.ID)
		return
	}
	if pick.res.Space == space.Control {
		s.deny(n.ID)
		s.sendEvent(protocol.SessionEvent{Kind: protocol.EventBlocked, Space: "control", Op: string(pick.op), Target: pick.res.Display,
			Label: pick.res.Label, PID: tgid, Command: procfs.Cmdline(tgid, 200)})
		return
	}
	if _, open := s.cache.open(pick.res.Space); open {
		s.cont(n.ID)
		return
	}
	if s.opts.Observe {
		s.cont(n.ID)
		key := pick.res.Space.String() + "|" + pick.res.Key
		if _, seen := s.observed.LoadOrStore(key, struct{}{}); !seen {
			s.sendEvent(protocol.SessionEvent{Kind: protocol.EventObserved, Space: pick.res.Space.String(), Op: string(pick.op),
				Target: pick.res.Display, Label: pick.res.Label, Detail: pick.res.Detail, PID: tgid, Command: procfs.Cmdline(tgid, 200)})
		}
		return
	}
	if call.Name == "execve" && strings.HasPrefix(pick.res.Key, "/snap/") {
		if _, seen := s.snapWarn.LoadOrStore(pick.res.Key, struct{}{}); !seen {
			s.warnf("%s is a snap and cannot run inside a supervised session", pick.res.Display)
		}
	}
	dec := s.ask(n, tgid, pick, syscallText)
	if !seccomp.IDValid(s.notifyFD, n.ID) {
		return
	}
	if dec.Allow {
		if dec.Lease != nil {
			s.cache.apply(protocol.LeaseUpdate{Lease: *dec.Lease, Open: true})
			s.cache.touch(pick.res.Space, pick.res.Key)
		}
		s.cont(n.ID)
		return
	}
	s.deny(n.ID)
}

// ask sends an access request (coalescing identical in-flight ones) and
// waits for the decision, cancelling if the paused process dies.
func (s *session) ask(n seccomp.Notif, tgid int, t *target, syscallText string) protocol.Decision {
	key := t.res.Space.String() + "|" + t.res.Key + "|" + string(t.op)
	s.connMu.Lock()
	if f, ok := s.inflight[key]; ok {
		s.connMu.Unlock()
		return s.await(n, f)
	}
	f := &inflight{done: make(chan struct{})}
	s.inflight[key] = f
	conn, connected := s.conn, s.connected
	s.connMu.Unlock()
	defer func() {
		s.connMu.Lock()
		delete(s.inflight, key)
		s.connMu.Unlock()
		close(f.done)
	}()
	if !connected || conn == nil {
		f.dec = protocol.Decision{Scope: protocol.ScopeError, Reason: "daemon unavailable"}
		return f.dec
	}
	cwd, _ := procfs.Cwd(tgid)
	from := s.cache.currentSpace()
	fromName := ""
	if from.UserFacing() {
		fromName = from.String()
	}
	req := protocol.AccessRequest{SessionID: s.sessionID, AgentID: s.agentID, Space: t.res.Space.String(), Op: string(t.op),
		Target: t.res.Display, TargetKey: t.res.Key, Label: t.res.Label, RuleID: t.res.RuleID, Detail: t.res.Detail,
		Syscall: syscallText, PID: tgid, Chain: procfs.Chain(tgid, s.launcher, 6), Cwd: policy.Pretty(s.opts.Paths.Home, cwd),
		FromSpace: fromName}
	if t.res.Friction != space.FrictionNone {
		req.Friction = t.res.Friction.String()
	}
	s.logf("paused: %s wants to %s %s (%s) — answer in 'reclaim ui' or the desktop dialog", s.opts.Agent, t.op.Verb(), t.res.Display, t.res.Space.Title())
	id, ch, err := conn.Start(protocol.TypeAccess, req)
	if err != nil {
		f.dec = protocol.Decision{Scope: protocol.ScopeError, Reason: err.Error()}
		return f.dec
	}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				f.dec = protocol.Decision{Scope: protocol.ScopeError, Reason: "daemon disconnected"}
				return f.dec
			}
			d, err := protocol.Decode[protocol.Decision](e)
			if err != nil || e.Type != protocol.TypeDecision {
				d = protocol.Decision{Scope: protocol.ScopeError, Reason: "bad decision"}
			}
			f.dec = d
			s.report(t, d)
			return d
		case <-tick.C:
			if !seccomp.IDValid(s.notifyFD, n.ID) {
				conn.Forget(id)
				_ = conn.Send(protocol.TypeCancel, protocol.Cancel{RequestID: id, Reason: "process exited"})
				f.dec = protocol.Decision{Scope: protocol.ScopeCancelled}
				return f.dec
			}
		}
	}
}

func (s *session) await(n seccomp.Notif, f *inflight) protocol.Decision {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-f.done:
			return f.dec
		case <-tick.C:
			if !seccomp.IDValid(s.notifyFD, n.ID) {
				return protocol.Decision{Scope: protocol.ScopeCancelled}
			}
		case <-ctx.Done():
			return protocol.Decision{Scope: protocol.ScopeCancelled}
		}
	}
}

func (s *session) report(t *target, d protocol.Decision) {
	switch d.Scope {
	case protocol.ScopeLease:
		s.logf("allowed: %s open %s", t.res.Space.Title(), leaseText(d.Lease))
	case protocol.ScopeOnce:
		s.logf("allowed once: %s %s", t.op.Verb(), t.res.Display)
	case protocol.ScopeDeny:
		s.logf("denied: %s %s", t.op.Verb(), t.res.Display)
	case protocol.ScopeTimeout:
		s.logf("denied (no answer): %s %s", t.op.Verb(), t.res.Display)
	case protocol.ScopeCooldown:
		s.logf("denied (you said no moments ago): %s %s", t.op.Verb(), t.res.Display)
	}
}

func leaseText(l *protocol.LeaseInfo) string {
	if l == nil {
		return ""
	}
	if l.Kind == string(space.Fixed) {
		return "for " + space.HumanDuration(l.TTL.D())
	}
	return "until " + space.HumanDuration(l.TTL.D()) + " idle"
}
