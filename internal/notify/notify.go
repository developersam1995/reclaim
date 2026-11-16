// Package notify delivers prompts outside the console: desktop notifications
// (notify-send) and modal zenity dialogs that mirror the friction rules.
// All functions are best effort and must never block the caller longer than
// documented.
package notify

import (
	"context"

	"reclaim/internal/protocol"
)

// DisplayAvailable reports whether a graphical session is reachable
// (DISPLAY or WAYLAND_DISPLAY set).
func DisplayAvailable() bool { return displayAvailable() }

// Desktop shows a desktop notification via notify-send without waiting for it
// (critical → urgency critical). Returns an error only if notify-send could
// not be started.
func Desktop(title, body string, critical bool) error { return desktop(title, body, critical) }

// DialogAvailable reports whether zenity dialogs can be shown.
func DialogAvailable() bool { return dialogAvailable() }

// Dialog shows a modal prompt for p and blocks until the user answers, the
// dialog is closed (→ action "deny"), or ctx is done (the dialog process is
// killed; returns ctx.Err()). Friction mapping:
//   - low:    question dialog, "Allow" / "Deny"
//   - medium: question dialog with Deny as the default button
//   - high:   entry dialog asking the user to type p.Challenge; empty or
//     cancelled → deny
//
// When p.AllowOnce, the user is also offered "Allow once" (action "once").
// The dialog text includes the Space title, label, target, Why, the agent and
// the requesting command, and the time left before the prompt times out.
// Returns action ∈ {protocol.ActionAllow, ActionOnce, ActionDeny} and the
// typed challenge (high friction).
func Dialog(ctx context.Context, p protocol.PromptInfo) (action, challenge string, err error) {
	return dialog(ctx, p)
}

// Summary renders a short two-line summary of p for notification bodies.
func Summary(p protocol.PromptInfo) (title, body string) { return summary(p) }
