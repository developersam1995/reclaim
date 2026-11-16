// Package e2e runs real supervised sessions against a real daemon using the
// built reclaim binary. Linux only; skipped when seccomp user notification
// is unavailable.
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"reclaim/internal/protocol"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("/tmp", "rcl-e2e")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "reclaim")
	build := exec.Command("go", "build", "-o", bin, "../../cmd/reclaim")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	t     *testing.T
	vars  []string
	home  string
	proj  string
	state string

	lastOut <-chan string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	act := uint32(unix.SECCOMP_RET_USER_NOTIF)
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_ACTION_AVAIL, 0, uintptrOf(&act)); errno != 0 {
		t.Skip("seccomp user notification unavailable")
	}
	root, err := os.MkdirTemp("/tmp", "rcl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	e := &env{t: t, home: filepath.Join(root, "home"), proj: filepath.Join(root, "home", "proj"), state: filepath.Join(root, "state")}
	for _, d := range []string{e.proj, filepath.Join(e.home, ".ssh"), filepath.Join(e.home, "Documents"), filepath.Join(root, "cfg", "reclaim"), filepath.Join(root, "rt")} {
		os.MkdirAll(d, 0o700)
	}
	os.WriteFile(filepath.Join(e.home, ".ssh", "id_ed25519"), []byte("secret"), 0o600)
	os.WriteFile(filepath.Join(e.home, "Documents", "notes.txt"), []byte("personal"), 0o600)
	os.WriteFile(filepath.Join(e.proj, "main.go"), []byte("package main"), 0o644)
	os.WriteFile(filepath.Join(root, "cfg", "reclaim", "config.toml"), []byte("[prompt]\ntimeout = \"6s\"\ndeny_cooldown = \"1s\"\ndesktop_notify = false\ndialog = \"never\"\n"), 0o600)
	e.vars = append(os.Environ(), "HOME="+e.home, "XDG_CONFIG_HOME="+filepath.Join(root, "cfg"), "XDG_STATE_HOME="+e.state,
		"XDG_RUNTIME_DIR="+filepath.Join(root, "rt"), "TMPDIR=/tmp")
	ctx, cancel := context.WithCancel(context.Background())
	d := exec.CommandContext(ctx, bin, "daemon")
	d.Env = e.vars
	d.Stderr = os.Stderr
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); d.Wait() })
	sock := filepath.Join(root, "rt", "reclaim", "reclaimd.sock")
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return e
}

func uintptrOf(p *uint32) uintptr { return uintptr(unsafePointer(p)) }

func (e *env) cmd(args ...string) *exec.Cmd {
	c := exec.Command(bin, args...)
	c.Env = e.vars
	c.Dir = e.proj
	return c
}

func (e *env) status() protocol.State {
	out, err := e.cmd("status", "--json").Output()
	if err != nil {
		e.t.Fatalf("status: %v", err)
	}
	var st protocol.State
	if err := json.Unmarshal(out, &st); err != nil {
		e.t.Fatal(err)
	}
	return st
}

func (e *env) waitPrompt() protocol.PromptInfo {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st := e.status(); len(st.Prompts) > 0 {
			return st.Prompts[0]
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e.lastOut != nil {
		select {
		case s := <-e.lastOut:
			e.t.Logf("session output:\n%s", s)
		case <-time.After(2 * time.Second):
		}
	}
	e.t.Fatal("no prompt appeared")
	return protocol.PromptInfo{}
}

// run starts a supervised bash -c script and returns its combined output.
func (e *env) run(script string, extra ...string) (<-chan string, *exec.Cmd) {
	args := append([]string{"run", "--agent", "testagent"}, extra...)
	args = append(args, "--", "bash", "-c", script)
	c := e.cmd(args...)
	out := make(chan string, 1)
	go func() {
		b, _ := c.CombinedOutput()
		out <- string(b)
	}()
	e.lastOut = out
	return out, c
}

func TestVaultDenyAndApprove(t *testing.T) {
	e := newEnv(t)
	out, _ := e.run(`cat main.go >/dev/null && echo project-ok; cat ~/.ssh/id_ed25519; echo vault-exit=$?`)
	p := e.waitPrompt()
	if p.Space != "vault" || p.Friction != "high" || p.Challenge == "" {
		t.Fatalf("prompt = %+v", p)
	}
	if err := e.cmd("deny", p.ID).Run(); err != nil {
		t.Fatalf("deny: %v", err)
	}
	s := <-out
	if !strings.Contains(s, "project-ok") || !strings.Contains(s, "Permission denied") || !strings.Contains(s, "vault-exit=1") || strings.Contains(s, "secret") {
		t.Fatalf("output:\n%s", s)
	}
	// Approve with the word: the secret is readable, and a fixed lease is open.
	out, _ = e.run(`sleep 3.5; cat ~/.ssh/id_ed25519; echo; cat ~/.ssh/id_ed25519 >/dev/null && echo second-read-free`)
	p = e.waitPrompt()
	time.Sleep(p.ArmDelay.D() + 200*time.Millisecond)
	if b, err := e.cmd("approve", p.ID, "--word", p.Challenge).CombinedOutput(); err != nil {
		t.Fatalf("approve: %v %s", err, b)
	}
	s = <-out
	if !strings.Contains(s, "secret") || !strings.Contains(s, "second-read-free") {
		t.Fatalf("output:\n%s", s)
	}
	st := e.status()
	found := false
	for _, l := range st.Leases {
		if l.Space == "vault" && l.Kind == "fixed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no vault lease: %+v", st.Leases)
	}
	// Reclaim now closes it.
	if b, err := e.cmd("now", "--space", "vault").CombinedOutput(); err != nil || !strings.Contains(string(b), "reclaimed 1") {
		t.Fatalf("now: %v %s", err, b)
	}
	for _, l := range e.status().Leases {
		if l.Space == "vault" {
			t.Fatal("vault lease survived reclaim now")
		}
	}
}

func TestHomeTimeoutAndAudit(t *testing.T) {
	e := newEnv(t)
	start := time.Now()
	out, _ := e.run(`cat ~/Documents/notes.txt; echo home-exit=$?`)
	p := e.waitPrompt()
	if p.Space != "home" || p.Friction != "medium" {
		t.Fatalf("prompt = %+v", p)
	}
	s := <-out
	if !strings.Contains(s, "home-exit=1") || strings.Contains(s, "personal") {
		t.Fatalf("output:\n%s", s)
	}
	if time.Since(start) < 5*time.Second {
		t.Fatal("prompt did not wait for the timeout")
	}
	b, err := e.cmd("log", "-n", "20").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SESSION+", "GRANTED", "TIMEOUT", "SESSION-"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("log missing %s:\n%s", want, b)
		}
	}
}

func TestObserveAndControlPlane(t *testing.T) {
	e := newEnv(t)
	out, _ := e.run(`cat ~/.ssh/id_ed25519 && echo; echo observe-exit=$?`, "--observe")
	s := <-out
	if !strings.Contains(s, "secret") || !strings.Contains(s, "observe-exit=0") {
		t.Fatalf("observe output:\n%s", s)
	}
	b, _ := e.cmd("log", "-n", "5").Output()
	if !strings.Contains(string(b), "OBSERVED") {
		t.Fatalf("log missing OBSERVED:\n%s", b)
	}
	// Agents cannot read reclaim's state or answer prompts from inside.
	out, _ = e.run(`cat "$XDG_STATE_HOME"/reclaim/state.json; echo state-exit=$?; "` + bin + `" now; echo now-exit=$?`)
	s = <-out
	if !strings.Contains(s, "state-exit=1") || !strings.Contains(s, "now-exit=1") {
		t.Fatalf("control plane output:\n%s", s)
	}
}

func TestProjectWorkIsSilent(t *testing.T) {
	e := newEnv(t)
	out, c := e.run(`/usr/bin/env true && mkdir sub && echo x > sub/f && mv sub/f sub/g && rm -r sub && ls ~/.ssh >/dev/null && echo all-ok`)
	select {
	case s := <-out:
		if !strings.Contains(s, "all-ok") {
			t.Fatalf("output:\n%s", s)
		}
	case <-time.After(8 * time.Second):
		c.Process.Kill()
		t.Fatal("project work blocked on a prompt")
	}
	if st := e.status(); len(st.Prompts) != 0 {
		t.Fatalf("unexpected prompts: %+v", st.Prompts)
	}
}
