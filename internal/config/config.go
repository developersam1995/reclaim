// Package config resolves Reclaim's filesystem locations (XDG-aware) and
// loads the optional TOML config file. The config file only holds overrides;
// anything unset falls back to the PRD defaults in space.DefaultPolicies and
// the built-in rule set in package policy.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"reclaim/internal/space"
)

// Paths are the locations Reclaim uses.
type Paths struct {
	Home       string // the user's home directory
	ConfigDir  string // $XDG_CONFIG_HOME/reclaim
	StateDir   string // $XDG_STATE_HOME/reclaim
	RuntimeDir string // $XDG_RUNTIME_DIR/reclaim (falls back to /tmp/reclaim-<uid>)
	ConfigFile string // ConfigDir/config.toml
	StateFile  string // StateDir/state.json   (leases, history, TTL overrides)
	AuditFile  string // StateDir/audit.jsonl  (append-only audit log)
	DaemonLog  string // StateDir/daemon.log   (daemon stderr when auto-started)
	Socket     string // RuntimeDir/reclaimd.sock
	LockFile   string // RuntimeDir/reclaimd.lock (single-instance flock)
}

// DefaultPaths resolves Paths from HOME and the XDG environment variables.
func DefaultPaths() (Paths, error) {
	home := os.Getenv("HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, fmt.Errorf("cannot determine home directory: %w", err)
		}
		home = h
	}
	home = filepath.Clean(home)
	xdg := func(env, fallback string) string {
		if v := os.Getenv(env); v != "" && filepath.IsAbs(v) {
			return filepath.Clean(v)
		}
		return fallback
	}
	configBase := xdg("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	stateBase := xdg("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	runtimeBase := xdg("XDG_RUNTIME_DIR", "")
	var runtimeDir string
	if runtimeBase != "" {
		runtimeDir = filepath.Join(runtimeBase, "reclaim")
	} else {
		runtimeDir = filepath.Join(os.TempDir(), fmt.Sprintf("reclaim-%d", os.Getuid()))
	}
	p := Paths{
		Home:       home,
		ConfigDir:  filepath.Join(configBase, "reclaim"),
		StateDir:   filepath.Join(stateBase, "reclaim"),
		RuntimeDir: runtimeDir,
	}
	p.ConfigFile = filepath.Join(p.ConfigDir, "config.toml")
	p.StateFile = filepath.Join(p.StateDir, "state.json")
	p.AuditFile = filepath.Join(p.StateDir, "audit.jsonl")
	p.DaemonLog = filepath.Join(p.StateDir, "daemon.log")
	p.Socket = filepath.Join(p.RuntimeDir, "reclaimd.sock")
	if len(p.Socket) >= 100 { // unix socket paths are limited to 108 bytes
		p.RuntimeDir = filepath.Join(os.TempDir(), fmt.Sprintf("reclaim-%d", os.Getuid()))
		p.Socket = filepath.Join(p.RuntimeDir, "reclaimd.sock")
	}
	p.LockFile = filepath.Join(p.RuntimeDir, "reclaimd.lock")
	return p, nil
}

// EnsureDirs creates StateDir and RuntimeDir with mode 0700 and verifies the
// runtime dir is owned by the current user and not group/world accessible.
func (p Paths) EnsureDirs() error {
	for _, d := range []string{p.StateDir, p.RuntimeDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	fi, err := os.Stat(p.RuntimeDir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(p.RuntimeDir, 0o700); err != nil {
			return fmt.Errorf("runtime dir %s has unsafe permissions: %w", p.RuntimeDir, err)
		}
	}
	return nil
}

// Duration is a TOML-friendly duration ("90s", "15m", "48h").
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", string(b))
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.Duration.String()), nil }

// Config is the parsed config file.
type Config struct {
	Prompt  PromptConfig           `toml:"prompt"`
	Spaces  map[string]SpaceConfig `toml:"spaces"` // keyed by space name: project, remote, vault, home, system, device
	Network NetworkConfig          `toml:"network"`
	Sandbox SandboxConfig          `toml:"sandbox"`
	Agents  map[string]AgentConfig `toml:"agents"` // keyed by agent name (basename of the agent command, or --agent)
	Rules   []RuleConfig           `toml:"rules"`  // user rules, evaluated before the built-in rules
}

// PromptConfig controls pause-and-ask behaviour.
type PromptConfig struct {
	Timeout       Duration `toml:"timeout"`        // how long a paused operation waits for an answer before failing with EACCES
	DesktopNotify bool     `toml:"desktop_notify"` // send a desktop notification for each new prompt
	Dialog        string   `toml:"dialog"`         // "auto" (zenity dialog when no console is attached) | "always" | "never"
	DenyCooldown  Duration `toml:"deny_cooldown"`  // after a denial, identical requests are auto-denied for this long
}

// SpaceConfig overrides one Space's policy. Zero values mean "use default".
type SpaceConfig struct {
	Lease         string    `toml:"lease"` // "sliding" | "fixed"
	TTL           *Duration `toml:"ttl"`
	Friction      string    `toml:"friction"` // "low" | "medium" | "high"
	GatedOps      []string  `toml:"gated_ops"`
	AllowOnce     *bool     `toml:"allow_once"`
	GrantOnLaunch *bool     `toml:"grant_on_launch"`
}

// NetworkConfig tunes Remote Space classification.
type NetworkConfig struct {
	// ControlPlanePorts: connections from the agent's root process to these
	// ports are the agent talking to its own model API, not a Remote Space entry.
	ControlPlanePorts []int `toml:"control_plane_ports"`
	// ControlPlaneHosts: hostnames whose resolved addresses (port 443) count as
	// the agent's control plane for every process in the session.
	ControlPlaneHosts []string `toml:"control_plane_hosts"`
	// LocalCIDRs: extra networks treated as local (never Remote Space).
	LocalCIDRs []string `toml:"local_cidrs"`
	// DNSIsLocal: port-53 lookups are not boundary crossings.
	DNSIsLocal *bool `toml:"dns_is_local"`
}

// SandboxConfig toggles kernel-level hardening applied inside sessions.
type SandboxConfig struct {
	// BlockNamespaces refuses new user/mount namespaces inside sessions
	// (unshare/clone with CLONE_NEWUSER|CLONE_NEWNS, setns; clone3 -> ENOSYS),
	// which would otherwise let a process see a different filesystem view
	// than the one Reclaim classifies. Default true.
	BlockNamespaces *bool `toml:"block_namespaces"`
}

// AgentConfig describes an agent's own state (always open for that agent).
type AgentConfig struct {
	State []string `toml:"state"` // globs, e.g. "~/.claude/**"
}

// RuleConfig is a user classification rule. See policy.Rule.
type RuleConfig struct {
	ID       string   `toml:"id"`
	Space    string   `toml:"space"` // project|remote|vault|home|system|device|ambient
	Label    string   `toml:"label"`
	Paths    []string `toml:"paths"`    // globs; "~", "$XDG_RUNTIME_DIR", "{project}" expand; "**" spans directories
	Except   []string `toml:"except"`   // globs excluded from this rule
	Sockets  []string `toml:"sockets"`  // AF_UNIX socket path globs
	Abstract []string `toml:"abstract"` // abstract AF_UNIX names (without the leading '@')
	Agents   []string `toml:"agents"`   // restrict the rule to these agent names
	Friction string   `toml:"friction"` // optional: override the Space's friction for targets matched by this rule
}

// DefaultControlPlaneHosts are well-known agent model/telemetry endpoints.
var DefaultControlPlaneHosts = []string{
	"api.anthropic.com", "statsig.anthropic.com", "claude.ai",
	"api.openai.com", "chatgpt.com", "ab.chatgpt.com",
	"generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com",
}

// Default returns the built-in configuration.
func Default() Config {
	t := true
	return Config{
		Prompt: PromptConfig{
			Timeout:       Duration{60 * time.Second},
			DesktopNotify: true,
			Dialog:        "auto",
			DenyCooldown:  Duration{30 * time.Second},
		},
		Spaces: map[string]SpaceConfig{},
		Network: NetworkConfig{
			ControlPlanePorts: []int{443},
			ControlPlaneHosts: append([]string(nil), DefaultControlPlaneHosts...),
			DNSIsLocal:        &t,
		},
		Sandbox: SandboxConfig{BlockNamespaces: &t},
		Agents:  map[string]AgentConfig{},
	}
}

// Load reads path over Default(). A missing file is not an error.
func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	md, err := toml.Decode(string(b), &c)
	if err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return c, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if c.Spaces == nil {
		c.Spaces = map[string]SpaceConfig{}
	}
	if c.Agents == nil {
		c.Agents = map[string]AgentConfig{}
	}
	return c, c.Validate()
}

// Validate checks enumerations and CIDRs.
func (c Config) Validate() error {
	switch c.Prompt.Dialog {
	case "auto", "always", "never":
	default:
		return fmt.Errorf("prompt.dialog: want auto, always, or never (got %q)", c.Prompt.Dialog)
	}
	if c.Prompt.Timeout.Duration < 5*time.Second {
		return fmt.Errorf("prompt.timeout must be at least 5s")
	}
	if _, err := c.Policies(); err != nil {
		return err
	}
	for _, cidr := range c.Network.LocalCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("network.local_cidrs: %w", err)
		}
	}
	for i, r := range c.Rules {
		if _, err := space.Parse(r.Space); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
		if r.Friction != "" {
			if _, err := space.ParseFriction(r.Friction); err != nil {
				return fmt.Errorf("rules[%d]: %w", i, err)
			}
		}
		if len(r.Paths) == 0 && len(r.Sockets) == 0 && len(r.Abstract) == 0 {
			return fmt.Errorf("rules[%d]: needs at least one of paths, sockets, abstract", i)
		}
	}
	return nil
}

// Policies merges the config's space overrides onto space.DefaultPolicies().
func (c Config) Policies() (map[space.Space]space.Policy, error) {
	out := space.DefaultPolicies()
	for name, sc := range c.Spaces {
		sp, err := space.Parse(name)
		if err != nil || !sp.UserFacing() {
			return nil, fmt.Errorf("spaces.%s: unknown space", name)
		}
		p := out[sp]
		if sc.Lease != "" {
			k, err := space.ParseLeaseKind(sc.Lease)
			if err != nil {
				return nil, fmt.Errorf("spaces.%s.lease: %w", name, err)
			}
			p.Kind = k
		}
		if sc.TTL != nil {
			if sc.TTL.Duration < time.Second {
				return nil, fmt.Errorf("spaces.%s.ttl must be at least 1s", name)
			}
			p.TTL = sc.TTL.Duration
		}
		if sc.Friction != "" {
			f, err := space.ParseFriction(sc.Friction)
			if err != nil || f == space.FrictionNone {
				return nil, fmt.Errorf("spaces.%s.friction: want low, medium, or high", name)
			}
			p.Friction = f
		}
		if sc.GatedOps != nil {
			ops := make([]space.Op, 0, len(sc.GatedOps))
			for _, o := range sc.GatedOps {
				op, err := space.ParseOp(o)
				if err != nil {
					return nil, fmt.Errorf("spaces.%s.gated_ops: %w", name, err)
				}
				ops = append(ops, op)
			}
			p.GatedOps = ops
		}
		if sc.AllowOnce != nil {
			p.AllowOnce = *sc.AllowOnce
		}
		if sc.GrantOnLaunch != nil {
			p.GrantOnLaunch = *sc.GrantOnLaunch
		}
		out[sp] = p
	}
	return out, nil
}

// DNSLocal reports whether port-53 traffic is treated as local.
func (c Config) DNSLocal() bool { return c.Network.DNSIsLocal == nil || *c.Network.DNSIsLocal }

// BlockNamespaces reports whether namespace creation is refused in sessions.
func (c Config) BlockNamespaces() bool {
	return c.Sandbox.BlockNamespaces == nil || *c.Sandbox.BlockNamespaces
}

// Template is a commented example config written by `reclaim init`.
const Template = `# Reclaim configuration. Every key is optional; defaults follow the PRD.
# Durations use Go syntax: 90s, 15m, 48h.

[prompt]
timeout = "60s"          # paused operation fails with EACCES if unanswered
desktop_notify = true    # desktop notification for each new prompt
dialog = "auto"          # auto: zenity dialog when no 'reclaim ui' console is attached | always | never
deny_cooldown = "30s"    # identical requests are auto-denied this long after you deny one

# Per-Space lease policy. lease = "sliding" (idle timeout) or "fixed" (hard expiry).
[spaces.project]
lease = "sliding"
ttl = "48h"
grant_on_launch = true   # 'reclaim run' opens Project Space for the launch project

[spaces.remote]
lease = "sliding"
ttl = "15m"

[spaces.vault]
lease = "fixed"
ttl = "2m"

[spaces.home]
lease = "sliding"
ttl = "10m"

[spaces.system]
lease = "fixed"
ttl = "5m"

[spaces.device]
lease = "fixed"
ttl = "10m"

[network]
control_plane_ports = [443]   # the agent's own process may reach its model API
# control_plane_hosts = ["api.anthropic.com", "api.openai.com"]
local_cidrs = []              # e.g. ["192.168.1.0/24"] to treat your LAN as local
dns_is_local = true

[sandbox]
block_namespaces = true

# Extra state directories an agent may always use (globs).
# [agents.myagent]
# state = ["~/.myagent/**"]

# Your own classification rules run before the built-in ones.
# [[rules]]
# space = "vault"
# label = "Data lake credentials"
# paths = ["~/.config/datalake/**"]
`
