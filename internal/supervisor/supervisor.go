// Package supervisor implements `reclaim run`: it launches an agent under the
// seccomp user-notification filter and enforces Space leases on every trapped
// syscall, asking the daemon (and through it, the user) when no lease is
// open. See ARCHITECTURE.md §4.
package supervisor

import (
	"context"
	"io"

	"reclaim/internal/config"
)

// ShimArg is argv[1] of the re-exec'd shim process.
const ShimArg = "__reclaim_shim"

// MaybeShim must be called at the very start of main(). If os.Args[1] is
// ShimArg it becomes the shim: lock the OS thread, install the filter, hand
// the notify fd to the launcher over fd 3, wait for the ack, and exec the
// agent. It never returns in that case (exit status 127 on failure, with a
// message on stderr). Otherwise it returns immediately.
func MaybeShim() { maybeShim() }

// Options configures a supervised session.
type Options struct {
	Paths    config.Paths
	Config   config.Config
	Agent    string    // display name; default basename(Command[0])
	Projects []string  // absolute project roots; default DefaultProjects(cwd)
	Command  []string  // agent argv; Command[0] resolved via PATH
	Exe      string    // reclaim executable (for daemon auto-start and Control classification)
	Stderr   io.Writer // launcher messages (default os.Stderr)
	Quiet    bool      // suppress informational launcher messages
	// Observe runs the session in observe mode: everything is classified and
	// gated accesses without an open lease are reported to the daemon as
	// "observed" events (deduplicated per space+target) but always allowed.
	// No prompts are shown. Used to tune policy and to audit an agent.
	Observe bool
}

// Run supervises one agent session and returns the agent's exit code
// (128+signal if it was killed). err is non-nil only if the session could not
// be started (daemon unavailable, filter install failed, command not found).
func Run(ctx context.Context, opts Options) (exitCode int, err error) { return run(ctx, opts) }

// DefaultProjects returns the git top-level of cwd (walking up for a .git
// entry), or cwd itself.
func DefaultProjects(cwd string) []string { return defaultProjects(cwd) }

// AgentID returns the lease identity for an agent and its project roots:
// agent + "@" + projects[0].
func AgentID(agent string, projects []string) string { return agentID(agent, projects) }
