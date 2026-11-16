// Package friction implements proportional cognitive friction (PRD 4.4):
// effective friction levels, arming delays, typed challenges, and the
// human description of what an approval grants.
package friction

import (
	"time"

	"reclaim/internal/space"
)

// Level returns the effective friction for a prompt:
//   - unexpected (a Remote target never approved before for this agent) → High
//   - known (the exact target was approved before for this agent) and base is
//     High → Medium: a deliberate key instead of a typed word for repeats
//     such as the ssh-agent on every git push
//   - recentApprovals >= 3 (approvals by the user in the last 60s, any prompt)
//     → one level above the result so far (anti-autopilot), capped at High
//   - never FrictionNone for a prompt (min Low).
func Level(base space.Friction, unexpected, known bool, recentApprovals int) space.Friction {
	return level(base, unexpected, known, recentApprovals)
}

// ArmDelay is how long after a prompt appears answers are ignored:
// Low 0, Medium 800ms, High 2500ms.
func ArmDelay(f space.Friction) time.Duration { return armDelay(f) }

// Challenge picks the word a user must type to approve a high-friction
// prompt: a random entry from Words (crypto/rand), so it differs from prompt
// to prompt and cannot become muscle memory. Never the same as previous.
func Challenge(previous string) string { return challenge(previous) }

// Words is the challenge vocabulary: short, distinct, easy to type, no two
// sharing a prefix of 3 letters.
var Words = words

// Verify reports whether answer matches challenge (trimmed, case-insensitive).
func Verify(challenge, answer string) bool { return verify(challenge, answer) }

// LeaseText describes what "allow" grants under p:
// sliding → "until 15m of inactivity"; fixed → "for 2m (fixed; using it does not extend it)".
func LeaseText(p space.Policy) string { return leaseText(p) }
