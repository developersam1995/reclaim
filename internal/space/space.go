// Package space defines Reclaim's core domain model: the six user-facing
// Spaces, the operations an agent can attempt against them, and the lease /
// friction policy that governs each Space.
//
// Two extra, non-user-facing classifications exist:
//   - Ambient: the floor everything stands on (system runtime reads, /proc,
//     loopback networking, DNS, the agent's own state). Never gated.
//   - Control: Reclaim's own control plane (daemon socket, config, state).
//     Always denied from inside an agent session, never prompted.
package space

import (
	"fmt"
	"strings"
	"time"
)

// Space is a human-level category of system access.
type Space uint8

const (
	Ambient Space = iota // not user-facing; never gated
	Project              // where the agent writes, tests, and builds code
	Remote               // reaching outside the laptop
	Vault                // keys, passwords, secrets, browser identity
	Home                 // personal files outside codebases
	System               // how the machine boots, runs services, installs software
	Device               // live inputs/outputs that can observe the user
	Control              // Reclaim's own control plane; hard-denied inside sessions
)

// All lists the six user-facing Spaces in display order.
var All = []Space{Project, Remote, Vault, Home, System, Device}

var names = map[Space]string{
	Ambient: "ambient",
	Project: "project",
	Remote:  "remote",
	Vault:   "vault",
	Home:    "home",
	System:  "system",
	Device:  "device",
	Control: "control",
}

// String returns the lowercase identifier ("vault").
func (s Space) String() string {
	if n, ok := names[s]; ok {
		return n
	}
	return fmt.Sprintf("space(%d)", uint8(s))
}

// Title returns the display name ("Vault Space").
func (s Space) Title() string {
	switch s {
	case Ambient:
		return "Ambient"
	case Control:
		return "Reclaim Control"
	}
	n := s.String()
	return strings.ToUpper(n[:1]) + n[1:] + " Space"
}

// MentalModel returns the one-line user mental model from the PRD.
func (s Space) MentalModel() string {
	switch s {
	case Project:
		return "Where the agent writes, tests, and builds code."
	case Remote:
		return "Reaching outside the laptop to remote servers, data lakes, or external networks."
	case Vault:
		return "Private keys, saved passwords, secrets, and browser identity/history."
	case Home:
		return "Personal folders, documents, and downloads outside of codebases."
	case System:
		return "How the machine boots, runs background services, and installs global software."
	case Device:
		return "Live physical inputs and outputs capable of observing you."
	case Ambient:
		return "System runtime, loopback, and the agent's own state. Always open."
	case Control:
		return "Reclaim's own controls. Agents may never touch these."
	}
	return ""
}

// UserFacing reports whether s is one of the six Spaces shown to users.
func (s Space) UserFacing() bool { return s >= Project && s <= Device }

// Rank orders Spaces by sensitivity for conflict resolution when one
// operation touches several targets (e.g. rename, link): the highest rank
// wins. Control > Vault > Device > System > Remote > Home > Project > Ambient.
func (s Space) Rank() int {
	switch s {
	case Control:
		return 7
	case Vault:
		return 6
	case Device:
		return 5
	case System:
		return 4
	case Remote:
		return 3
	case Home:
		return 2
	case Project:
		return 1
	}
	return 0
}

// Max returns the more sensitive of a and b.
func Max(a, b Space) Space {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// Parse converts "vault", "Vault", "vault space" into a Space.
func Parse(s string) (Space, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	n = strings.TrimSuffix(n, " space")
	n = strings.TrimSuffix(n, "-space")
	for sp, name := range names {
		if name == n {
			return sp, nil
		}
	}
	return Ambient, fmt.Errorf("unknown space %q (want one of project, remote, vault, home, system, device)", s)
}

// Op is the kind of operation an agent attempts.
type Op string

const (
	OpRead    Op = "read"    // open a file for reading
	OpWrite   Op = "write"   // create, modify, truncate, delete, rename, chmod, link
	OpList    Op = "list"    // open a directory (listing its contents)
	OpExec    Op = "exec"    // execute a file
	OpConnect Op = "connect" // connect/send to a socket address
	OpListen  Op = "listen"  // bind a socket to a non-loopback address
)

// AllOps lists every Op.
var AllOps = []Op{OpRead, OpWrite, OpList, OpExec, OpConnect, OpListen}

// ParseOp validates an op name.
func ParseOp(s string) (Op, error) {
	for _, o := range AllOps {
		if string(o) == strings.ToLower(strings.TrimSpace(s)) {
			return o, nil
		}
	}
	return "", fmt.Errorf("unknown op %q", s)
}

// Verb returns a human verb phrase for prompts ("read", "modify", ...).
func (o Op) Verb() string {
	switch o {
	case OpRead:
		return "read"
	case OpWrite:
		return "modify"
	case OpList:
		return "list"
	case OpExec:
		return "run"
	case OpConnect:
		return "connect to"
	case OpListen:
		return "accept connections on"
	}
	return string(o)
}

// LeaseKind determines how a lease decays.
type LeaseKind string

const (
	// Sliding leases expire after TTL of inactivity; every use refreshes them.
	Sliding LeaseKind = "sliding"
	// Fixed leases expire TTL after they were granted, regardless of use, so
	// an agent cannot keep a sensitive Space open by periodic polling.
	Fixed LeaseKind = "fixed"
)

// ParseLeaseKind validates a lease kind.
func ParseLeaseKind(s string) (LeaseKind, error) {
	switch LeaseKind(strings.ToLower(strings.TrimSpace(s))) {
	case Sliding:
		return Sliding, nil
	case Fixed:
		return Fixed, nil
	}
	return "", fmt.Errorf("unknown lease kind %q (want sliding or fixed)", s)
}

// Friction is how much deliberate effort an approval requires.
type Friction uint8

const (
	FrictionNone   Friction = iota // never prompted (ambient)
	FrictionLow                    // single key (Enter / y)
	FrictionMedium                 // short arming delay, then a deliberate non-Enter key
	FrictionHigh                   // longer arming delay, then type a challenge word read from the prompt
)

func (f Friction) String() string {
	switch f {
	case FrictionLow:
		return "low"
	case FrictionMedium:
		return "medium"
	case FrictionHigh:
		return "high"
	}
	return "none"
}

// ParseFriction validates a friction name.
func ParseFriction(s string) (Friction, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		return FrictionNone, nil
	case "low":
		return FrictionLow, nil
	case "medium":
		return FrictionMedium, nil
	case "high":
		return FrictionHigh, nil
	}
	return FrictionNone, fmt.Errorf("unknown friction %q (want low, medium, or high)", s)
}

// Policy governs leases and prompts for one Space.
type Policy struct {
	Kind          LeaseKind     // sliding or fixed
	TTL           time.Duration // idle window (sliding) or total lifetime (fixed)
	Friction      Friction      // base friction for entering this Space
	GatedOps      []Op          // ops that require an open lease; other ops are free
	AllowOnce     bool          // offer "allow once" (this single operation) in prompts
	GrantOnLaunch bool          // open a lease when a session starts (Project Space)
}

// Gates reports whether op requires a lease in this Space.
func (p Policy) Gates(op Op) bool {
	for _, g := range p.GatedOps {
		if g == op {
			return true
		}
	}
	return false
}

// DefaultPolicies returns the PRD's lease and friction behaviour per Space.
//
//   - Project: long sliding lease (48h idle), low friction, opened at launch.
//   - Remote:  task-scoped sliding lease (15m idle), medium friction,
//     escalated to high for never-before-approved targets.
//   - Vault:   strict fixed lease (2m) or single access, high friction.
//   - Home:    short reluctant sliding lease (10m idle), medium friction.
//   - System:  modification gate; fixed 5m lease, high friction. Reads are free.
//   - Device:  locked by default; fixed 10m lease for a bounded task, high friction.
func DefaultPolicies() map[Space]Policy {
	return map[Space]Policy{
		Project: {Kind: Sliding, TTL: 48 * time.Hour, Friction: FrictionLow,
			GatedOps: []Op{OpRead, OpWrite, OpList, OpExec}, AllowOnce: false, GrantOnLaunch: true},
		Remote: {Kind: Sliding, TTL: 15 * time.Minute, Friction: FrictionMedium,
			GatedOps: []Op{OpConnect, OpListen, OpWrite}, AllowOnce: true},
		Vault: {Kind: Fixed, TTL: 2 * time.Minute, Friction: FrictionHigh,
			GatedOps: []Op{OpRead, OpWrite, OpExec, OpConnect}, AllowOnce: true},
		Home: {Kind: Sliding, TTL: 10 * time.Minute, Friction: FrictionMedium,
			GatedOps: []Op{OpRead, OpWrite, OpList, OpExec}, AllowOnce: true},
		System: {Kind: Fixed, TTL: 5 * time.Minute, Friction: FrictionHigh,
			GatedOps: []Op{OpWrite, OpConnect}, AllowOnce: true},
		Device: {Kind: Fixed, TTL: 10 * time.Minute, Friction: FrictionHigh,
			GatedOps: []Op{OpRead, OpWrite, OpConnect}, AllowOnce: true},
	}
}

// HumanDuration renders d compactly: "48h", "15m", "2m30s", "45s".
func HumanDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Round(time.Second)
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	var b strings.Builder
	if days > 0 {
		fmt.Fprintf(&b, "%dd", days)
	}
	if h > 0 {
		fmt.Fprintf(&b, "%dh", h)
	}
	if m > 0 && days == 0 {
		fmt.Fprintf(&b, "%dm", m)
	}
	if s > 0 && days == 0 && h == 0 {
		fmt.Fprintf(&b, "%ds", s)
	}
	if b.Len() == 0 {
		return "0s"
	}
	return b.String()
}

// MustTitle returns the Title of the named space, or the name itself.
func MustTitle(name string) string {
	if s, err := Parse(name); err == nil {
		return s.Title()
	}
	return name
}
