// Package ui is the interactive console (`reclaim ui`): live Spaces with
// countdowns, pending prompts with proportional friction, and the audit tail.
package ui

import (
	"context"

	"reclaim/internal/config"
)

// Run connects to the daemon (paths.Socket, role "ui"), subscribes to state,
// and runs the full-screen console until the user quits or ctx is done.
func Run(ctx context.Context, paths config.Paths) error { return run(ctx, paths) }
