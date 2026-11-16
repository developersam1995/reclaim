package friction

import (
	"crypto/rand"
	"math/big"
	"strings"
	"time"

	"reclaim/internal/space"
)

// words is the challenge vocabulary. Short, distinct, easy to type; no two
// share their first three letters, so a typo cannot land on another word.
var words = []string{
	"amber", "basil", "cedar", "delta", "ember", "fable", "gamma", "harbor",
	"ivory", "jade", "karma", "lemon", "mango", "nova", "ocean", "pearl",
	"quartz", "river", "sage", "tiger", "umber", "velvet", "willow", "xenon",
	"yarrow", "zephyr", "atlas", "bridge", "coral", "dune", "echo", "forest",
	"glacier", "honey", "island", "jungle", "kernel", "lotus", "meadow", "nectar",
	"orbit", "piano", "quill", "rocket", "silver", "tulip", "ultra", "violet",
	"walnut", "yonder", "zenith", "anchor", "breeze", "canyon", "drift", "eagle",
	"flint", "garden", "hollow", "iris", "jasper", "kite", "lantern", "marble",
}

func level(base space.Friction, unexpected, known bool, recentApprovals int) space.Friction {
	f := base
	if f == space.FrictionNone {
		f = space.FrictionLow
	}
	switch {
	case unexpected:
		f = space.FrictionHigh
	case known && f == space.FrictionHigh:
		f = space.FrictionMedium
	}
	if recentApprovals >= 3 && f < space.FrictionHigh {
		f++
	}
	return f
}

func armDelay(f space.Friction) time.Duration {
	switch f {
	case space.FrictionMedium:
		return 800 * time.Millisecond
	case space.FrictionHigh:
		return 2500 * time.Millisecond
	}
	return 0
}

func challenge(previous string) string {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		var w string
		if err != nil {
			// crypto/rand failing is extraordinary; fall back to a time-based pick
			// rather than refusing to prompt.
			w = words[int(time.Now().UnixNano()/1000)%len(words)]
		} else {
			w = words[n.Int64()]
		}
		if w != previous {
			return w
		}
	}
}

func verify(challenge, answer string) bool {
	c := strings.TrimSpace(challenge)
	if c == "" {
		return false
	}
	return strings.EqualFold(c, strings.TrimSpace(answer))
}

func leaseText(p space.Policy) string {
	ttl := space.HumanDuration(p.TTL)
	if p.Kind == space.Fixed {
		return "for " + ttl + " (fixed; using it does not extend it)"
	}
	return "until " + ttl + " of inactivity"
}
