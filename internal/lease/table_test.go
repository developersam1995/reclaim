package lease

import (
	"encoding/json"
	"testing"
	"time"

	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock {
	return &clock{t: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
}

var (
	kHome  = Key{AgentID: "claude@/home/u/p", Space: space.Home}
	kVault = Key{AgentID: "claude@/home/u/p", Space: space.Vault}
)

func TestSlidingRefreshAndIdle(t *testing.T) {
	c := newClock()
	tb := NewTable(c.now)
	l := tb.Grant(kHome, "claude", space.Sliding, 10*time.Minute, protocol.SourcePrompt)
	if l.Gen != 1 {
		t.Fatalf("gen = %d, want 1", l.Gen)
	}
	c.advance(8 * time.Minute)
	if !tb.Touch(kHome, c.now()) {
		t.Fatal("touch on open lease returned false")
	}
	c.advance(8 * time.Minute) // 16m after grant, 8m after touch: still open
	if _, ok := tb.Open(kHome); !ok {
		t.Fatal("sliding lease should have been refreshed by touch")
	}
	c.advance(3 * time.Minute)
	if _, ok := tb.Open(kHome); ok {
		t.Fatal("lease should have idled out")
	}
	cl := tb.Sweep()
	if len(cl) != 1 || cl[0].Cause != CauseIdle || cl[0].IdleFor != 11*time.Minute {
		t.Fatalf("sweep = %+v", cl)
	}
	if cl[0].Lease.Gen != 2 {
		t.Fatalf("close gen = %d, want 2", cl[0].Lease.Gen)
	}
	if got := tb.Why(kHome, "claude"); got != "Home Space was reclaimed just now after 11m of inactivity." {
		t.Fatalf("why = %q", got)
	}
}

func TestFixedIsNotRefreshed(t *testing.T) {
	c := newClock()
	tb := NewTable(c.now)
	tb.Grant(kVault, "claude", space.Fixed, 2*time.Minute, protocol.SourcePrompt)
	c.advance(90 * time.Second)
	tb.Touch(kVault, c.now())
	c.advance(31 * time.Second)
	if _, ok := tb.Open(kVault); ok {
		t.Fatal("fixed lease must expire regardless of touches")
	}
	cl := tb.Sweep()
	if len(cl) != 1 || cl[0].Cause != CauseExpired {
		t.Fatalf("sweep = %+v", cl)
	}
	c.advance(5 * time.Minute)
	if got := tb.Why(kVault, "claude"); got != "Vault Space was reclaimed 5m ago when its fixed 2m lease ended." {
		t.Fatalf("why = %q", got)
	}
}

func TestHoldLayersOnLease(t *testing.T) {
	c := newClock()
	tb := NewTable(c.now)
	tb.Grant(kHome, "claude", space.Sliding, 10*time.Minute, protocol.SourcePrompt)
	l := tb.Hold(kHome, "claude", space.Sliding, 10*time.Minute, time.Hour)
	if l.Source != protocol.SourcePrompt || l.HoldUntil != c.now().Add(time.Hour) {
		t.Fatalf("hold on open lease = %+v", l)
	}
	c.advance(50 * time.Minute)
	if _, ok := tb.Open(kHome); !ok {
		t.Fatal("hold should keep the lease open past idle")
	}
	c.advance(11 * time.Minute)
	cl := tb.Sweep()
	if len(cl) != 1 || cl[0].Cause != CauseHoldEnded {
		t.Fatalf("sweep = %+v", cl)
	}
	// Hold on a closed space grants a new lease with the hold.
	l = tb.Hold(kVault, "claude", space.Fixed, 2*time.Minute, 30*time.Minute)
	if l.Source != protocol.SourceHold || l.ExpiresAt() != c.now().Add(30*time.Minute) {
		t.Fatalf("hold on closed space = %+v", l)
	}
}

func TestGrantNeverShortens(t *testing.T) {
	c := newClock()
	tb := NewTable(c.now)
	tb.Hold(kHome, "claude", space.Sliding, 10*time.Minute, time.Hour)
	l := tb.Grant(kHome, "claude", space.Sliding, 10*time.Minute, protocol.SourcePrompt)
	if l.ExpiresAt() != c.now().Add(time.Hour) {
		t.Fatalf("grant shortened a held lease: %+v", l)
	}
}

func TestRevokeAndKnownTargets(t *testing.T) {
	c := newClock()
	tb := NewTable(c.now)
	tb.Grant(kHome, "claude", space.Sliding, 10*time.Minute, protocol.SourcePrompt)
	tb.Grant(kVault, "claude", space.Fixed, 2*time.Minute, protocol.SourcePrompt)
	cl := tb.RevokeWhere(func(k Key) bool { return k.Space == space.Home }, CauseManual)
	if len(cl) != 1 || cl[0].Lease.Space != space.Home {
		t.Fatalf("revokeWhere = %+v", cl)
	}
	if len(tb.Leases()) != 1 {
		t.Fatal("vault lease should remain")
	}
	tb.NoteDenied(kHome)
	c.advance(4 * time.Minute)
	want := "You reclaimed Home Space manually 4m ago. You denied a request here 4m ago."
	if got := tb.Why(kHome, "claude"); got != want {
		t.Fatalf("why = %q, want %q", got, want)
	}
	tb.RememberTarget(kVault, "/home/u/.ssh/id_ed25519")
	if !tb.KnownTarget(kVault, "/home/u/.ssh/id_ed25519") || tb.KnownTarget(kVault, "/x") {
		t.Fatal("known target tracking broken")
	}
	if got := tb.Why(Key{AgentID: "x", Space: space.Remote}, "codex"); got != "First time codex enters Remote Space." {
		t.Fatalf("why = %q", got)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	c := newClock()
	tb := NewTable(c.now)
	tb.Grant(kHome, "claude", space.Sliding, 10*time.Minute, protocol.SourcePrompt)
	tb.Hold(kVault, "claude", space.Fixed, 2*time.Minute, time.Hour)
	tb.RememberTarget(kVault, "k1")
	b, err := json.Marshal(tb.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		t.Fatal(err)
	}
	tb2 := NewTable(c.now)
	tb2.Restore(snap)
	if tb2.Gen() != tb.Gen() {
		t.Fatalf("gen %d != %d", tb2.Gen(), tb.Gen())
	}
	a, b2 := tb.Leases(), tb2.Leases()
	if len(a) != 2 || len(b2) != 2 || a[1].HoldUntil != b2[1].HoldUntil || a[0].ExpiresAt() != b2[0].ExpiresAt() {
		t.Fatalf("leases differ:\n%+v\n%+v", a, b2)
	}
	if !tb2.KnownTarget(kVault, "k1") {
		t.Fatal("known targets lost in round trip")
	}
	// Expired leases survive restore so the next sweep reports them.
	c.advance(2 * time.Hour)
	if n := len(tb2.Sweep()); n != 2 {
		t.Fatalf("swept %d, want 2", n)
	}
}

func TestApplyTTLAndNextExpiry(t *testing.T) {
	c := newClock()
	tb := NewTable(c.now)
	tb.Grant(kHome, "claude", space.Sliding, 10*time.Minute, protocol.SourcePrompt)
	tb.Grant(kVault, "claude", space.Fixed, 2*time.Minute, protocol.SourcePrompt)
	if n := tb.ApplyTTL(space.Home, time.Hour); n != 1 {
		t.Fatalf("applyTTL changed %d", n)
	}
	if n := tb.ApplyTTL(space.Vault, time.Hour); n != 0 {
		t.Fatalf("applyTTL changed fixed lease: %d", n)
	}
	next, ok := tb.NextExpiry()
	if !ok || next != c.now().Add(2*time.Minute) {
		t.Fatalf("next expiry = %v %v", next, ok)
	}
}
