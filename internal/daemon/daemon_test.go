package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reclaim/internal/client"
	"reclaim/internal/config"
	"reclaim/internal/protocol"
)

type fakeNotifier struct{ notified chan protocol.PromptInfo }

func (f *fakeNotifier) Notify(p protocol.PromptInfo) {
	select {
	case f.notified <- p:
	default:
	}
}
func (f *fakeNotifier) DialogAvailable() bool { return false }
func (f *fakeNotifier) Dialog(ctx context.Context, p protocol.PromptInfo) (string, string, error) {
	return "", "", errors.New("no dialog")
}

func startDaemon(t *testing.T, cfg config.Config) (config.Paths, *fakeNotifier, context.CancelFunc) {
	t.Helper()
	base := ""
	if len(os.TempDir()) > 40 {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "rcd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	paths := config.Paths{Home: dir, ConfigDir: filepath.Join(dir, "c"), StateDir: filepath.Join(dir, "s"), RuntimeDir: filepath.Join(dir, "r")}
	paths.StateFile = filepath.Join(paths.StateDir, "state.json")
	paths.AuditFile = filepath.Join(paths.StateDir, "audit.jsonl")
	paths.Socket = filepath.Join(paths.RuntimeDir, "d.sock")
	paths.LockFile = filepath.Join(paths.RuntimeDir, "d.lock")
	n := &fakeNotifier{notified: make(chan protocol.PromptInfo, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Options{Paths: paths, Config: cfg, Notifier: n, Logf: t.Logf}) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(paths.Socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("daemon: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	return paths, n, cancel
}

func sessionHello(agentID string) protocol.Hello {
	return protocol.Hello{Role: protocol.RoleSession, Version: protocol.Version, Session: &protocol.SessionInfo{
		Agent: "claude", AgentID: agentID, Projects: []string{"/home/u/p"}, Command: []string{"claude"}, LauncherPID: 999999, AgentPID: 999998}}
}

func cliConn(t *testing.T, paths config.Paths) *client.Conn {
	t.Helper()
	c, _, err := client.Dial(paths.Socket, protocol.Hello{Role: protocol.RoleCLI, Version: protocol.Version})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func status(t *testing.T, c *client.Conn) protocol.State {
	t.Helper()
	var st protocol.State
	if err := c.Call(context.Background(), protocol.TypeStatus, nil, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestPromptLifecycle(t *testing.T) {
	cfg := config.Default()
	cfg.Prompt.Timeout = config.Duration{Duration: 5 * time.Second}
	cfg.Prompt.DesktopNotify = false
	paths, n, _ := startDaemon(t, cfg)

	sess, w, err := client.Dial(paths.Socket, sessionHello("claude@/home/u/p"))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if w.SessionID == "" || len(w.Leases) != 1 || w.Leases[0].Space != "project" || w.Leases[0].Source != protocol.SourceLaunch {
		t.Fatalf("welcome = %+v", w)
	}
	cli := cliConn(t, paths)

	// A Vault access with no lease → prompt (high friction, challenge).
	req := protocol.AccessRequest{Space: "vault", Op: "read", Target: "~/.ssh/id_ed25519", TargetKey: "/home/u/.ssh/id_ed25519",
		Label: "SSH private key", Syscall: "openat(...)", PID: 42, Chain: []protocol.ProcInfo{{PID: 42, Comm: "cat", Cmdline: "cat ~/.ssh/id_ed25519"}}}
	_, dec1, err := sess.Start(protocol.TypeAccess, req)
	if err != nil {
		t.Fatal(err)
	}
	var p protocol.PromptInfo
	select {
	case p = <-n.notified:
	case <-time.After(3 * time.Second):
		t.Fatal("no notification")
	}
	if p.Friction != "high" || p.Challenge == "" || !strings.HasPrefix(p.Why, "First time claude enters Vault Space") {
		t.Fatalf("prompt = %+v", p)
	}
	// Same target again attaches to the same prompt; a different target is listed.
	req2 := req
	req2.Target, req2.TargetKey = "~/.ssh/id_rsa", "/home/u/.ssh/id_rsa"
	_, dec2, _ := sess.Start(protocol.TypeAccess, req2)
	time.Sleep(100 * time.Millisecond)
	st := status(t, cli)
	if len(st.Prompts) != 1 || st.Prompts[0].Waiting != 2 || len(st.Prompts[0].MoreTargets) != 1 {
		t.Fatalf("prompts = %+v", st.Prompts)
	}
	// Too fast.
	err = cli.Call(context.Background(), protocol.TypeAnswer, protocol.Answer{PromptID: p.ID, Action: protocol.ActionAllow, Challenge: p.Challenge, Via: "cli"}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "too fast") {
		t.Fatalf("early answer: %v", err)
	}
	time.Sleep(p.ArmDelay.D() + 100*time.Millisecond)
	// Wrong word.
	err = cli.Call(context.Background(), protocol.TypeAnswer, protocol.Answer{PromptID: p.ID, Action: protocol.ActionAllow, Challenge: "nope"}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "wrong word") {
		t.Fatalf("wrong word: %v", err)
	}
	// Allow once: only the primary target proceeds; the other gets a new prompt.
	if err := cli.Call(context.Background(), protocol.TypeAnswer, protocol.Answer{PromptID: p.ID, Action: protocol.ActionOnce, Challenge: p.Challenge, Via: "cli"}, nil); err != nil {
		t.Fatal(err)
	}
	d := <-dec1
	dd, _ := protocol.Decode[protocol.Decision](d)
	if !dd.Allow || dd.Scope != protocol.ScopeOnce {
		t.Fatalf("decision1 = %+v", dd)
	}
	var p2 protocol.PromptInfo
	select {
	case p2 = <-n.notified:
	case <-time.After(3 * time.Second):
		t.Fatal("no re-prompt for remaining target")
	}
	if p2.Target != "~/.ssh/id_rsa" || p2.Friction != "high" {
		t.Fatalf("re-prompt = %+v", p2)
	}
	time.Sleep(p2.ArmDelay.D() + 100*time.Millisecond)
	// Full allow → lease push.
	if err := cli.Call(context.Background(), protocol.TypeAnswer, protocol.Answer{PromptID: p2.ID, Action: protocol.ActionAllow, Challenge: p2.Challenge, Via: "cli"}, nil); err != nil {
		t.Fatal(err)
	}
	dd, _ = protocol.Decode[protocol.Decision](<-dec2)
	if !dd.Allow || dd.Scope != protocol.ScopeLease || dd.Lease == nil || dd.Lease.Kind != "fixed" {
		t.Fatalf("decision2 = %+v", dd)
	}
	gotPush := false
	for !gotPush {
		select {
		case e := <-sess.Pushes():
			if e.Type == protocol.TypeLease {
				u, _ := protocol.Decode[protocol.LeaseUpdate](e)
				if u.Open && u.Lease.Space == "vault" {
					gotPush = true
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no lease push")
		}
	}
	// Known target now → medium friction next time (after reclaim).
	var rr protocol.ReclaimResult
	if err := cli.Call(context.Background(), protocol.TypeReclaim, protocol.ReclaimRequest{Agent: "claude", Space: "vault"}, &rr); err != nil || rr.Revoked != 1 {
		t.Fatalf("reclaim = %+v %v", rr, err)
	}
	_, dec3, _ := sess.Start(protocol.TypeAccess, req)
	p3 := <-n.notified
	if p3.Friction != "medium" || p3.Challenge != "" || !strings.Contains(p3.Why, "You reclaimed Vault Space manually") {
		t.Fatalf("known-target prompt = %+v", p3)
	}
	time.Sleep(p3.ArmDelay.D() + 100*time.Millisecond)
	// Deny → cooldown auto-denies the next identical request.
	if err := cli.Call(context.Background(), protocol.TypeAnswer, protocol.Answer{PromptID: p3.ID, Action: protocol.ActionDeny, Via: "cli"}, nil); err != nil {
		t.Fatal(err)
	}
	dd, _ = protocol.Decode[protocol.Decision](<-dec3)
	if dd.Allow || dd.Scope != protocol.ScopeDeny {
		t.Fatalf("deny decision = %+v", dd)
	}
	var dec4 protocol.Decision
	if err := sess.Call(context.Background(), protocol.TypeAccess, req, &dec4); err != nil || dec4.Scope != protocol.ScopeCooldown {
		t.Fatalf("cooldown = %+v %v", dec4, err)
	}
	// Timeout.
	req3 := req
	req3.TargetKey, req3.Target = "/home/u/.ssh/other", "~/.ssh/other"
	var dec5 protocol.Decision
	start := time.Now()
	if err := sess.Call(context.Background(), protocol.TypeAccess, req3, &dec5); err != nil || dec5.Scope != protocol.ScopeTimeout {
		t.Fatalf("timeout = %+v %v", dec5, err)
	}
	if time.Since(start) < 5*time.Second {
		t.Fatal("timed out too early")
	}
	// Hold, TTL, audit.
	var ok protocol.OK
	if err := cli.Call(context.Background(), protocol.TypeHold, protocol.HoldRequest{Agent: "claude", Space: "home", Duration: protocol.Duration(time.Hour)}, &ok); err != nil {
		t.Fatal(err)
	}
	if err := cli.Call(context.Background(), protocol.TypeSetTTL, protocol.SetTTLRequest{Space: "home", TTL: protocol.Duration(time.Minute)}, &ok); err != nil {
		t.Fatal(err)
	}
	st = status(t, cli)
	if st.Policies["home"].TTL.D() != time.Minute {
		t.Fatalf("ttl override not applied: %+v", st.Policies["home"])
	}
	found := false
	for _, l := range st.Leases {
		if l.Space == "home" && !l.HoldUntil.IsZero() {
			found = true
		}
	}
	if !found {
		t.Fatalf("hold lease missing: %+v", st.Leases)
	}
	var ar protocol.AuditResult
	if err := cli.Call(context.Background(), protocol.TypeAudit, protocol.AuditQuery{Limit: 100}, &ar); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, e := range ar.Events {
		kinds[e.Kind]++
	}
	for _, k := range []string{protocol.AuditSessionStart, protocol.AuditGranted, protocol.AuditApprovedOnce, protocol.AuditApproved,
		protocol.AuditRevoked, protocol.AuditDenied, protocol.AuditAutoDenied, protocol.AuditTimeout, protocol.AuditHeld, protocol.AuditTTLChanged} {
		if kinds[k] == 0 {
			t.Errorf("audit missing %s: %v", k, kinds)
		}
	}
	// Session ends → audit.
	sess.Close()
	time.Sleep(200 * time.Millisecond)
	cli.Call(context.Background(), protocol.TypeAudit, protocol.AuditQuery{Limit: 5}, &ar)
	if n := len(ar.Events); n == 0 || ar.Events[n-1].Kind != protocol.AuditSessionEnd {
		t.Fatalf("last events = %+v", ar.Events)
	}
}

func TestPersistenceAndResume(t *testing.T) {
	cfg := config.Default()
	cfg.Prompt.DesktopNotify = false
	paths, _, cancel := startDaemon(t, cfg)
	sess, w, err := client.Dial(paths.Socket, sessionHello("claude@/home/u/p"))
	if err != nil {
		t.Fatal(err)
	}
	cli := cliConn(t, paths)
	var ok protocol.OK
	if err := cli.Call(context.Background(), protocol.TypeSetTTL, protocol.SetTTLRequest{Space: "remote", TTL: protocol.Duration(7 * time.Minute)}, &ok); err != nil {
		t.Fatal(err)
	}
	sess.Close()
	cli.Close()
	cancel()
	time.Sleep(300 * time.Millisecond)
	// Restart: leases and overrides survive; resume keeps the session id.
	ctx, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		Run(ctx, Options{Paths: paths, Config: cfg, Notifier: &fakeNotifier{notified: make(chan protocol.PromptInfo, 1)}, Logf: t.Logf})
		close(done2)
	}()
	defer func() { cancel2(); <-done2 }()
	time.Sleep(300 * time.Millisecond)
	h := sessionHello("claude@/home/u/p")
	h.Resume = w.SessionID
	sess2, w2, err := client.Dial(paths.Socket, h)
	if err != nil {
		t.Fatal(err)
	}
	defer sess2.Close()
	if w2.SessionID != w.SessionID || len(w2.Leases) != 1 || w2.Policies["remote"].TTL.D() != 7*time.Minute {
		t.Fatalf("resumed welcome = %+v", w2)
	}
	if w2.Leases[0].Gen != w.Leases[0].Gen {
		t.Fatalf("gen changed across restart: %d → %d", w.Leases[0].Gen, w2.Leases[0].Gen)
	}
}
