package friction

import (
	"testing"
	"time"

	"reclaim/internal/space"
)

func TestLevel(t *testing.T) {
	cases := []struct {
		base            space.Friction
		unexpected, kno bool
		recent          int
		want            space.Friction
	}{
		{space.FrictionLow, false, false, 0, space.FrictionLow},
		{space.FrictionNone, false, false, 0, space.FrictionLow},
		{space.FrictionMedium, true, false, 0, space.FrictionHigh},
		{space.FrictionHigh, false, true, 0, space.FrictionMedium},
		{space.FrictionMedium, false, true, 0, space.FrictionMedium},
		{space.FrictionLow, false, false, 3, space.FrictionMedium},
		{space.FrictionHigh, false, true, 3, space.FrictionHigh},
		{space.FrictionHigh, false, false, 5, space.FrictionHigh},
	}
	for _, c := range cases {
		if got := Level(c.base, c.unexpected, c.kno, c.recent); got != c.want {
			t.Errorf("Level(%v,%v,%v,%d) = %v, want %v", c.base, c.unexpected, c.kno, c.recent, got, c.want)
		}
	}
}

func TestArmDelay(t *testing.T) {
	if ArmDelay(space.FrictionLow) != 0 || ArmDelay(space.FrictionMedium) != 800*time.Millisecond || ArmDelay(space.FrictionHigh) != 2500*time.Millisecond {
		t.Fatal("arm delays wrong")
	}
}

func TestChallengeWords(t *testing.T) {
	prefixes := map[string]string{}
	for _, w := range Words {
		if len(w) < 4 || len(w) > 7 {
			t.Errorf("word %q has bad length", w)
		}
		p := w[:3]
		if other, dup := prefixes[p]; dup {
			t.Errorf("words %q and %q share prefix %q", w, other, p)
		}
		prefixes[p] = w
	}
	prev := ""
	for i := 0; i < 200; i++ {
		w := Challenge(prev)
		if w == prev {
			t.Fatal("challenge repeated the previous word")
		}
		found := false
		for _, x := range Words {
			if x == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("challenge %q not in vocabulary", w)
		}
		prev = w
	}
}

func TestVerifyAndLeaseText(t *testing.T) {
	if !Verify("amber", "  AMBER ") || Verify("amber", "ambr") || Verify("", "") {
		t.Fatal("verify wrong")
	}
	if got := LeaseText(space.Policy{Kind: space.Sliding, TTL: 15 * time.Minute}); got != "until 15m of inactivity" {
		t.Fatalf("lease text = %q", got)
	}
	if got := LeaseText(space.Policy{Kind: space.Fixed, TTL: 2 * time.Minute}); got != "for 2m (fixed; using it does not extend it)" {
		t.Fatalf("lease text = %q", got)
	}
}
