// Package daemon is the Reclaim daemon (the policy decision point): it owns
// the lease table, brokers pause-and-ask prompts, sweeps expired leases,
// writes the audit log, persists state, and serves the control API over a
// Unix socket. See ARCHITECTURE.md §5.
package daemon

import (
	"context"
	"time"

	"reclaim/internal/config"
	"reclaim/internal/protocol"
)

// Notifier delivers prompts outside the console. The default implementation
// wraps package notify and honours Config.Prompt.
type Notifier interface {
	// Notify announces a new prompt (desktop notification). Must not block.
	Notify(p protocol.PromptInfo)
	// DialogAvailable reports whether Dialog can be shown.
	DialogAvailable() bool
	// Dialog shows a modal prompt and blocks until answered or ctx is done.
	Dialog(ctx context.Context, p protocol.PromptInfo) (action, challenge string, err error)
}

// Options configures the daemon.
type Options struct {
	Paths    config.Paths
	Config   config.Config
	Now      func() time.Time     // nil → time.Now
	Notifier Notifier             // nil → default (package notify)
	Logf     func(string, ...any) // nil → log.Printf
}

// Run acquires the single-instance lock (returns ErrAlreadyRunning if another
// daemon holds it), listens on Paths.Socket, and serves until ctx is done or a
// shutdown request arrives. It removes the socket on exit.
func Run(ctx context.Context, opts Options) error { return run(ctx, opts) }

// ErrAlreadyRunning is returned by Run when another daemon holds the lock.
var ErrAlreadyRunning = errAlreadyRunning
