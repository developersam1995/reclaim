package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"reclaim/internal/client"
	"reclaim/internal/policy"
	"reclaim/internal/protocol"
	"reclaim/internal/space"
	"reclaim/internal/supervisor/seccomp"
)

func defaultProjects(cwd string) []string {
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return []string{dir}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return []string{cwd}
		}
		dir = parent
	}
}

func agentID(agent string, projects []string) string {
	if len(projects) == 0 {
		return agent
	}
	return agent + "@" + projects[0]
}

// session is one supervised agent run.
type session struct {
	opts     Options
	stderr   io.Writer
	agentID  string
	classif  *policy.Classifier
	policies map[space.Space]space.Policy
	notifyFD int
	launcher int
	agentPID int
	cache    *leaseCache
	now      func() time.Time
	cpHosts  *hostCache
	observed sync.Map // space|targetKey → struct{} (observe mode dedupe)
	snapWarn sync.Map
	shimSock int

	connMu    sync.Mutex
	conn      *client.Conn
	sessionID string
	connected bool
	stopping  time.Time
	inflight  map[string]*inflight

	rootExit chan int
	rootDone bool
	muRoot   sync.Mutex
}

type inflight struct {
	done chan struct{}
	dec  protocol.Decision
}

func (s *session) logf(format string, args ...any) {
	if s.opts.Quiet {
		return
	}
	fmt.Fprintf(s.stderr, "reclaim: "+format+"\n", args...)
}

func (s *session) warnf(format string, args ...any) {
	fmt.Fprintf(s.stderr, "reclaim: "+format+"\n", args...)
}

func run(ctx context.Context, opts Options) (int, error) {
	if len(opts.Command) == 0 {
		return 2, errors.New("no command")
	}
	s := &session{opts: opts, stderr: opts.Stderr, now: func() time.Time { return time.Now().Round(0) },
		inflight: map[string]*inflight{}, rootExit: make(chan int, 1)}
	if s.stderr == nil {
		s.stderr = os.Stderr
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 2, err
	}
	if opts.Agent == "" {
		opts.Agent = filepath.Base(opts.Command[0])
	}
	if len(opts.Projects) == 0 {
		opts.Projects = defaultProjects(cwd)
	}
	for i, p := range opts.Projects {
		abs, err := filepath.Abs(p)
		if err != nil {
			return 2, err
		}
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			abs = r
		}
		opts.Projects[i] = abs
		if abs == opts.Paths.Home {
			s.warnf("warning: project root is your home directory; Project Space will cover all personal files")
		}
	}
	if opts.Exe == "" {
		opts.Exe, _ = os.Executable()
	}
	s.opts = opts
	s.agentID = agentID(opts.Agent, opts.Projects)
	if s.classif, err = policy.ForSession(opts.Paths, opts.Config, opts.Agent, opts.Projects, opts.Exe); err != nil {
		return 2, err
	}
	if s.policies, err = opts.Config.Policies(); err != nil {
		return 2, err
	}
	s.cache = newLeaseCache(s.now)
	s.cpHosts = newHostCache(opts.Config.Network.ControlPlaneHosts)
	s.launcher = os.Getpid()
	if _, err := exec.LookPath(opts.Command[0]); err != nil {
		return 127, err
	}
	s.warnSnaps()

	// Daemon first: fail closed if it cannot be reached.
	started, err := client.EnsureDaemon(opts.Paths, opts.Exe, 5*time.Second)
	if err != nil {
		return 2, fmt.Errorf("reclaim daemon unavailable: %w", err)
	}
	if started {
		s.logf("started reclaim daemon")
	}

	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return 2, fmt.Errorf("PR_SET_CHILD_SUBREAPER: %w", err)
	}
	// Reap everything ourselves; exec.Cmd.Wait must not be used.
	sigchld := make(chan os.Signal, 1)
	signal.Notify(sigchld, syscall.SIGCHLD)
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGHUP)

	shimPID, notifyFD, err := s.startShim()
	if err != nil {
		return 2, err
	}
	s.agentPID = shimPID
	s.notifyFD = notifyFD
	go s.reaper(sigchld)

	if err := s.connect(ctx, ""); err != nil {
		syscall.Kill(shimPID, syscall.SIGKILL)
		return 2, fmt.Errorf("reclaim daemon: %w", err)
	}
	s.logf("supervising %s (pid %d) — project %s; session %s", opts.Agent, shimPID, strings.Join(opts.Projects, ", "), s.sessionID)
	if opts.Observe {
		s.logf("observe mode: nothing is blocked; would-be prompts are logged")
	}
	// Release the shim: it execs the agent now.
	if err := s.ack(); err != nil {
		return 2, err
	}

	loopCtx, cancelLoop := context.WithCancel(context.Background())
	defer cancelLoop()
	go s.touchLoop(loopCtx)
	go s.netLoop(loopCtx)
	go s.pushLoop(loopCtx)

	done := make(chan struct{})
	go func() { s.notifyLoop(); close(done) }()

	exitCode := 0
	rootExited := false
	terminating := false
	for {
		select {
		case code := <-s.rootExit:
			exitCode = code
			rootExited = true
			s.muRoot.Lock()
			s.rootDone = true
			s.muRoot.Unlock()
			signal.Reset(syscall.SIGINT, syscall.SIGQUIT)
			signal.Notify(term, syscall.SIGINT, syscall.SIGQUIT)
			if n := len(sessionPIDs(s.launcher)); n > 0 && !terminating {
				s.logf("%s exited; %d background process(es) from the session are still running (Ctrl-C to end them)", opts.Agent, n)
			}
		case <-term:
			if !terminating {
				terminating = true
				s.logf("terminating session processes")
				go s.terminateTree()
			}
		case <-ctx.Done():
			if !terminating {
				terminating = true
				go s.terminateTree()
			}
		case <-done:
			if !rootExited {
				// All filter users gone but the root status not yet reaped: wait briefly.
				select {
				case code := <-s.rootExit:
					exitCode = code
				case <-time.After(2 * time.Second):
				}
			}
			s.disconnect()
			return exitCode, nil
		}
	}
}

func (s *session) warnSnaps() {
	var snaps []string
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir != "/snap/bin" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			snaps = append(snaps, e.Name())
		}
	}
	if len(snaps) > 0 && !s.opts.Quiet {
		if len(snaps) > 8 {
			snaps = append(snaps[:8], "…")
		}
		s.logf("note: snap-packaged commands cannot run inside a supervised session (%s); install non-snap builds to use them", strings.Join(snaps, ", "))
	}
}

// startShim starts the re-exec'd shim and receives the notify fd from it.
func (s *session) startShim() (int, int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, 0, err
	}
	child := os.NewFile(uintptr(fds[1]), "shim")
	parent := fds[0]
	optsJSON, _ := json.Marshal(seccomp.FilterOptions{BlockNamespaces: s.opts.Config.BlockNamespaces()})
	cmd := exec.Command(s.opts.Exe, append([]string{ShimArg}, s.opts.Command...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{child}
	cmd.Env = append(os.Environ(), ShimOptsEnv+"="+string(optsJSON), "RECLAIM_SESSION=1")
	if err := cmd.Start(); err != nil {
		child.Close()
		unix.Close(parent)
		return 0, 0, err
	}
	child.Close()
	s.shimSock = parent
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	unix.SetNonblock(parent, false)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := unix.SetsockoptTimeval(parent, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10}); err != nil {
			break
		}
		_, oobn, _, _, err := unix.Recvmsg(parent, buf, oob, 0)
		if err == unix.EINTR && time.Now().Before(deadline) {
			continue
		}
		if err != nil {
			unix.Close(parent)
			return 0, 0, fmt.Errorf("shim did not hand over a seccomp listener (see messages above): %w", err)
		}
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(msgs) == 0 {
			unix.Close(parent)
			return 0, 0, errors.New("shim sent no fd")
		}
		nfds, err := unix.ParseUnixRights(&msgs[0])
		if err != nil || len(nfds) == 0 {
			unix.Close(parent)
			return 0, 0, errors.New("shim sent no fd")
		}
		return cmd.Process.Pid, nfds[0], nil
	}
	unix.Close(parent)
	return 0, 0, errors.New("shim handshake failed")
}

func (s *session) ack() error {
	_, err := unix.Write(s.shimSock, []byte{1})
	unix.Close(s.shimSock)
	return err
}

// reaper owns wait4 for every child (the shim/agent and reparented orphans).
func (s *session) reaper(sigchld <-chan os.Signal) {
	for range sigchld {
		for {
			var ws unix.WaitStatus
			pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil || pid <= 0 {
				break
			}
			if pid == s.agentPID {
				code := ws.ExitStatus()
				if ws.Signaled() {
					code = 128 + int(ws.Signal())
				}
				s.rootExit <- code
			}
		}
	}
}

func (s *session) terminateTree() {
	pids := sessionPIDs(s.launcher)
	for _, p := range pids {
		syscall.Kill(p, syscall.SIGTERM)
	}
	time.Sleep(5 * time.Second)
	for _, p := range sessionPIDs(s.launcher) {
		syscall.Kill(p, syscall.SIGKILL)
	}
}

// notifyLoop serves seccomp notifications until every session process is gone.
func (s *session) notifyLoop() {
	for {
		readable, hup, err := seccomp.Poll(s.notifyFD, 500*time.Millisecond)
		if err != nil {
			s.warnf("poll: %v", err)
			return
		}
		if hup {
			return
		}
		if !readable {
			continue
		}
		var n seccomp.Notif
		if err := seccomp.Recv(s.notifyFD, &n); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // target died before we could receive
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		go s.handle(n)
	}
}

// ── daemon connection ────────────────────────────────────────────────────

func (s *session) sessionInfo() protocol.SessionInfo {
	cwd, _ := os.Getwd()
	return protocol.SessionInfo{Agent: s.opts.Agent, AgentID: s.agentID, Projects: s.opts.Projects, Command: s.opts.Command,
		Cwd: cwd, LauncherPID: s.launcher, AgentPID: s.agentPID, StartedAt: s.now(), Observe: s.opts.Observe}
}

func (s *session) connect(ctx context.Context, resume string) error {
	info := s.sessionInfo()
	hello := protocol.Hello{Role: protocol.RoleSession, Version: protocol.Version, Session: &info, Resume: resume}
	conn, w, err := client.Dial(s.opts.Paths.Socket, hello)
	if err != nil {
		return err
	}
	s.connMu.Lock()
	s.conn = conn
	s.sessionID = w.SessionID
	s.connected = true
	s.connMu.Unlock()
	// The daemon is the source of policy.
	pols := map[space.Space]space.Policy{}
	for name, pi := range w.Policies {
		sp, err := space.Parse(name)
		if err != nil {
			continue
		}
		p := space.Policy{Kind: space.LeaseKind(pi.Kind), TTL: pi.TTL.D(), AllowOnce: pi.AllowOnce, GrantOnLaunch: pi.GrantOnLaunch}
		p.Friction, _ = space.ParseFriction(pi.Friction)
		for _, o := range pi.GatedOps {
			p.GatedOps = append(p.GatedOps, space.Op(o))
		}
		pols[sp] = p
	}
	if len(pols) > 0 {
		s.policies = pols
	}
	s.cache.replace(w.Leases)
	return nil
}

func (s *session) current() (*client.Conn, bool) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conn, s.connected
}

func (s *session) disconnect() {
	s.connMu.Lock()
	c := s.conn
	s.connected = false
	s.connMu.Unlock()
	if c != nil {
		c.Close()
	}
}

// pushLoop applies lease pushes and reconnects (with Resume) when the
// connection drops.
func (s *session) pushLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		conn, ok := s.current()
		if !ok || conn == nil {
			return
		}
	drain:
		for {
			select {
			case <-ctx.Done():
				return
			case e, open := <-conn.Pushes():
				if !open {
					break drain
				}
				switch e.Type {
				case protocol.TypeLease:
					if u, err := protocol.Decode[protocol.LeaseUpdate](e); err == nil {
						s.cache.apply(u)
					}
				case protocol.TypeStopping:
					s.connMu.Lock()
					s.stopping = time.Now()
					s.connMu.Unlock()
				}
			}
		}
		// Connection lost.
		s.connMu.Lock()
		s.connected = false
		resume := s.sessionID
		stopping := s.stopping
		s.connMu.Unlock()
		if ctx.Err() != nil {
			return
		}
		s.warnf("lost connection to the reclaim daemon; new boundary crossings are denied until it is back")
		if time.Since(stopping) < 5*time.Second {
			time.Sleep(5 * time.Second)
		}
		for ctx.Err() == nil {
			if _, err := client.EnsureDaemon(s.opts.Paths, s.opts.Exe, 5*time.Second); err == nil {
				if err := s.connect(ctx, resume); err == nil {
					s.logf("reconnected to the reclaim daemon")
					backoff = time.Second
					break
				}
			}
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
		}
	}
}

func (s *session) touchLoop(ctx context.Context) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		used, cur := s.cache.flush()
		if len(used) == 0 && cur == "" {
			continue
		}
		if len(used) == 0 {
			continue
		}
		if conn, ok := s.current(); ok {
			_ = conn.Send(protocol.TypeTouch, protocol.Touch{AgentID: s.agentID, Used: used, Current: cur})
		}
	}
}

// netLoop keeps Remote Space alive while a session process holds an
// established connection to a non-local peer.
func (s *session) netLoop(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, ok := s.cache.open(space.Remote); !ok {
			continue
		}
		set := map[uint64]bool{}
		for _, pid := range sessionPIDs(s.launcher) {
			socketInodes(pid, set)
		}
		socketInodes(s.agentPID, set)
		if peer, ok := establishedRemote(set); ok {
			s.cache.touch(space.Remote, "net:"+peer)
		}
	}
}

func (s *session) sendEvent(ev protocol.SessionEvent) {
	if conn, ok := s.current(); ok {
		_ = conn.Send(protocol.TypeEvent, ev)
	}
}

// ── control-plane host resolution ────────────────────────────────────────

type hostCache struct {
	mu    sync.Mutex
	hosts []string
	ips   map[string]string // ip → host
	at    time.Time
}

func newHostCache(hosts []string) *hostCache {
	h := &hostCache{hosts: hosts, ips: map[string]string{}}
	go h.refresh()
	return h
}

func (h *hostCache) refresh() {
	ips := map[string]string{}
	for _, host := range h.hosts {
		addrs, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ips[a.String()] = host
		}
	}
	h.mu.Lock()
	h.ips = ips
	h.at = time.Now()
	h.mu.Unlock()
}

func (h *hostCache) lookup(ip net.IP) (string, bool) {
	h.mu.Lock()
	host, ok := h.ips[ip.String()]
	stale := time.Since(h.at) > 10*time.Minute
	h.mu.Unlock()
	if stale {
		go h.refresh()
	}
	return host, ok
}
