package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reclaim/internal/protocol"
)

func TestAppendQueryRecent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		sp := "home"
		if i%3 == 0 {
			sp = "vault"
		}
		if err := l.Append(protocol.AuditEvent{Kind: protocol.AuditEntered, AgentID: "claude@/p", Agent: "claude", Space: sp, Target: strings.Repeat("x", 500)}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	// Corrupt a line.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("not json\n")
	f.Close()
	if r := func() []protocol.AuditEvent { l, _ := Open(path); defer l.Close(); return l.Recent(10) }(); len(r) != 10 {
		t.Fatalf("recent preload = %d", len(r))
	}
	evs, err := Query(path, protocol.AuditQuery{Limit: 20, Space: "vault"})
	if err != nil || len(evs) != 20 {
		t.Fatalf("query = %d %v", len(evs), err)
	}
	for _, e := range evs {
		if e.Space != "vault" {
			t.Fatal("filter failed")
		}
	}
	all, _ := Query(path, protocol.AuditQuery{Limit: 1000})
	if len(all) != 300 || all[0].Time.After(all[299].Time) {
		t.Fatalf("all = %d, order wrong", len(all))
	}
	if evs, _ := Query(path, protocol.AuditQuery{Agent: "codex"}); len(evs) != 0 {
		t.Fatal("agent filter failed")
	}
	if evs, err := Query(filepath.Join(t.TempDir(), "missing"), protocol.AuditQuery{}); err != nil || evs != nil {
		t.Fatal("missing file should be empty, nil error")
	}
}

func TestFollow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan protocol.AuditEvent, 10)
	done := make(chan struct{})
	go func() { Follow(ctx, path, func(e protocol.AuditEvent) { got <- e }); close(done) }()
	time.Sleep(300 * time.Millisecond)
	l, _ := Open(path)
	l.Append(protocol.AuditEvent{Kind: "a"})
	l.Append(protocol.AuditEvent{Kind: "b"})
	for _, want := range []string{"a", "b"} {
		select {
		case e := <-got:
			if e.Kind != want {
				t.Fatalf("got %q want %q", e.Kind, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("follow timed out")
		}
	}
	// Truncate and append: restart from 0.
	l.Close()
	os.Truncate(path, 0)
	l, _ = Open(path)
	l.Append(protocol.AuditEvent{Kind: "c"})
	select {
	case e := <-got:
		if e.Kind != "c" {
			t.Fatalf("after truncate got %q", e.Kind)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("follow after truncate timed out")
	}
	cancel()
	<-done
}

func TestFormat(t *testing.T) {
	tz := time.FixedZone("X", 0)
	ts := time.Date(2026, 11, 6, 16, 42, 10, 0, tz)
	ev := protocol.AuditEvent{Time: ts, Kind: protocol.AuditApproved, AgentID: "claude@/home/u/reclaim", Agent: "claude",
		Space: "vault", Op: "read", Target: "~/.ssh/id_ed25519", Label: "SSH private key", Detail: "fixed 2m", By: "user:console"}
	got := Format(ev, false)
	want := ts.Local().Format("2006-01-02 15:04:05") + "  claude·reclaim      APPROVED      Vault     read ~/.ssh/id_ed25519 (SSH private key) · fixed 2m · via console"
	if got != want {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	if c := Format(ev, true); !strings.Contains(c, ansiGreen) {
		t.Fatal("color missing")
	}
	ev = protocol.AuditEvent{Time: ts, Kind: protocol.AuditReclaimed, AgentID: "claude@/p", Space: "home", Detail: "after 10m of inactivity", By: "timer"}
	if got := Format(ev, false); !strings.HasSuffix(got, "RECLAIMED     Home      after 10m of inactivity") {
		t.Fatalf("reclaimed line = %q", got)
	}
	ev = protocol.AuditEvent{Time: ts, Kind: protocol.AuditDaemonStart}
	if got := Format(ev, false); !strings.Contains(got, "  -                   DAEMON-UP     -         ") {
		t.Fatalf("daemon line = %q", got)
	}
}
