// Package policy classifies filesystem paths and socket addresses into
// Spaces using an ordered rule list (see ARCHITECTURE.md §3).
package policy

import (
	"errors"
	"net"

	"reclaim/internal/space"
)

// Env is the per-session context the classifier needs.
type Env struct {
	Home          string   // user home directory (absolute)
	RuntimeDir    string   // $XDG_RUNTIME_DIR (NOT the reclaim subdir); "" if unknown → patterns using it are skipped
	Projects      []string // absolute project roots for "{project}" patterns
	Agent         string   // agent name for agent-scoped rules (Rule.Agents)
	ControlPaths  []string // Reclaim's own dirs/files (config dir, state dir, runtime dir, executable) → space.Control (dir entries also cover everything below)
	ControlSocket string   // the daemon socket path → space.Control (also matched by device+inode, see SockTarget.Ino)
	SSHAuthSock   string   // $SSH_AUTH_SOCK of the session, if any → treated like vault.ssh-agent
}

// Network configures socket classification.
type Network struct {
	ControlPlanePorts []int        // root agent process → these ports are Ambient ("agent control plane")
	LocalCIDRs        []*net.IPNet // extra networks treated as local (Ambient)
	DNSIsLocal        bool         // port 53 is Ambient
}

// PathTarget is a filesystem target resolved by the supervisor.
type PathTarget struct {
	Lexical  string // absolute, cleaned; /proc/self & /proc/thread-self already rewritten to /proc/<SelfPID>
	Resolved string // symlink-resolved (best effort); "" or == Lexical when not resolvable
	SelfPID  int    // tgid of the requesting process: /proc/<SelfPID>/... is always Ambient
}

// SockTarget is a socket address target.
type SockTarget struct {
	Family   string // "inet" | "inet6" | "unix" | "abstract" | "other"
	IP       net.IP // inet/inet6
	Port     int    // inet/inet6
	Path     string // unix: socket path as given (absolute after resolution against cwd); abstract: name without '@'
	Resolved string // unix: symlink-resolved path (best effort)
	Dev, Ino uint64 // unix: device and inode of the socket file (0 if unknown), used to detect hard links to the daemon socket
}

// Result is a classification.
type Result struct {
	Space    space.Space
	RuleID   string         // e.g. "vault.ssh-keys", "user.0", "agent.claude", "control", "net.loopback", "net.remote", "ambient"
	Label    string         // human description, e.g. "SSH private key"
	Display  string         // human target: "~/.ssh/id_ed25519", "10.0.0.5:22", "@/tmp/.X11-unix/X0"
	Key      string         // canonical identity: resolved path, "tcp:10.0.0.5:22", "unix:/run/user/1000/bus", "abstract:/tmp/.X11-unix/X0"
	Detail   string         // optional extra context, e.g. "SSH (port 22)"
	Friction space.Friction // rule-level override (FrictionNone = use the Space policy)
}

// Classifier is immutable after New and safe for concurrent use.
type Classifier struct {
	impl *classifierImpl
}

// New compiles rules for env. Evaluation order: Control (from env), userRules,
// agentState (only rules whose Agents include env.Agent, or have no Agents),
// DefaultRules(), then the Ambient fallback. Rules whose patterns need an
// unknown expansion ($XDG_RUNTIME_DIR == "" or no projects for {project})
// simply drop those patterns.
func New(env Env, userRules, agentState []Rule, netcfg Network) (*Classifier, error) {
	impl, err := newClassifierImpl(env, userRules, agentState, netcfg)
	if err != nil {
		return nil, err
	}
	return &Classifier{impl: impl}, nil
}

// ClassifyPath classifies a filesystem target. Lexical and Resolved are
// classified independently and the higher space.Rank wins (ties prefer
// Resolved). Display uses "~" for the home directory; Key is the resolved
// absolute path (or lexical if unresolved).
func (c *Classifier) ClassifyPath(t PathTarget) Result { return c.impl.classifyPath(t) }

// ClassifySocket classifies a socket target for op (space.OpConnect for
// connect/sendto, space.OpListen for bind). fromRoot reports whether the
// requesting process is the agent's root process; controlPlane (may be nil)
// reports whether ip:443 belongs to a resolved control-plane host and returns
// that host name. See ARCHITECTURE.md §3 "Network".
func (c *Classifier) ClassifySocket(op space.Op, t SockTarget, fromRoot bool, controlPlane func(net.IP) (string, bool)) Result {
	return c.impl.classifySocket(op, t, fromRoot, controlPlane)
}

// Rules returns the effective ordered rule list (after agent filtering and
// expansion of ~, $XDG_RUNTIME_DIR, {project}) for display by `reclaim policy`.
func (c *Classifier) Rules() []Rule { return c.impl.rules() }

// Pretty renders an absolute path with the home directory shown as "~".
func Pretty(home, p string) string { return pretty(home, p) }

// ErrNotImplemented is returned by stubs during development.
var ErrNotImplemented = errors.New("not implemented")
