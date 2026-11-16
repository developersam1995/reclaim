package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"reclaim/internal/audit"
	"reclaim/internal/config"
	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

// RenderStatus renders a State as the `reclaim status` text.
func RenderStatus(st protocol.State, color bool) string {
	var b strings.Builder
	dim := func(s string) string {
		if color {
			return "\x1b[2m" + s + "\x1b[0m"
		}
		return s
	}
	bold := func(s string) string {
		if color {
			return "\x1b[1m" + s + "\x1b[0m"
		}
		return s
	}
	fmt.Fprintf(&b, "%s  daemon pid %d, up %s\n\n", bold("Reclaim"), st.DaemonPID, space.HumanDuration(st.Now.Sub(st.StartedAt)))
	fmt.Fprintln(&b, bold("Sessions"))
	if len(st.Sessions) == 0 {
		fmt.Fprintln(&b, dim("  none"))
	}
	for _, s := range st.Sessions {
		cur := s.CurrentSpace
		if cur == "" {
			cur = "-"
		}
		mode := ""
		if s.Observe {
			mode = " (observe)"
		}
		fmt.Fprintf(&b, "  %-8s %-28s pid %-7d in %-8s since %s%s\n", s.Agent, trunc(strings.Join(s.Projects, ","), 28), s.AgentPID, cur, s.StartedAt.Local().Format("15:04"), mode)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, bold("Open Spaces"))
	if len(st.Leases) == 0 {
		fmt.Fprintln(&b, dim("  none — everything is reclaimed"))
	}
	for _, l := range st.Leases {
		fmt.Fprintf(&b, "  %s\n", LeaseLine(l, st.Now))
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, bold("Pending prompts"))
	if len(st.Prompts) == 0 {
		fmt.Fprintln(&b, dim("  none"))
	}
	for _, p := range st.Prompts {
		fmt.Fprintf(&b, "  %s\n", PromptLine(p, st.Now))
	}
	return b.String()
}

// LeaseLine renders one open lease with its countdown.
func LeaseLine(l protocol.LeaseInfo, now time.Time) string {
	left := l.ExpiresAt.Sub(now)
	kind := "idle"
	if l.Kind == string(space.Fixed) {
		kind = "fixed"
	}
	hold := ""
	if !l.HoldUntil.IsZero() && l.HoldUntil.After(now) {
		hold = " · held"
	}
	return fmt.Sprintf("%-8s %-24s reclaims in %-7s (%s %s%s)", spaceTitleShort(l.Space), trunc(agentCol(l.Agent, l.AgentID), 24),
		space.HumanDuration(left), kind, space.HumanDuration(l.TTL.D()), hold)
}

// PromptLine renders one pending prompt.
func PromptLine(p protocol.PromptInfo, now time.Time) string {
	left := p.Deadline.Sub(now)
	extra := ""
	if p.Challenge != "" {
		extra = fmt.Sprintf(" · type %q", p.Challenge)
	}
	if n := len(p.MoreTargets); n > 0 {
		extra += fmt.Sprintf(" · +%d more", n)
	}
	return fmt.Sprintf("[%s] %s → %s: %s %s (%s) · %s friction · %s left%s\n       %s\n       approve: reclaim approve %s%s   deny: reclaim deny %s",
		p.ID, p.Agent, spaceTitleShort(p.Space), space.Op(p.Op).Verb(), p.Target, p.Label, p.Friction, space.HumanDuration(left), extra,
		p.Why, p.ID, challengeArg(p), p.ID)
}

func challengeArg(p protocol.PromptInfo) string {
	if p.Challenge != "" {
		return " --word " + p.Challenge
	}
	return ""
}

func spaceTitleShort(name string) string {
	if s, err := space.Parse(name); err == nil {
		return strings.TrimSuffix(s.Title(), " Space")
	}
	return name
}

func agentCol(agent, agentID string) string {
	_, proj, ok := strings.Cut(agentID, "@")
	if !ok {
		return agent
	}
	parts := strings.Split(proj, "/")
	return agent + "·" + parts[len(parts)-1]
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// PrintLog implements `reclaim log`.
func PrintLog(paths config.Paths, q protocol.AuditQuery, follow, asJSON, color bool) {
	print := func(ev protocol.AuditEvent) {
		if asJSON {
			b, _ := json.Marshal(ev)
			fmt.Println(string(b))
			return
		}
		fmt.Println(audit.Format(ev, color))
	}
	evs, err := audit.Query(paths.AuditFile, q)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reclaim:", err)
		os.Exit(1)
	}
	for _, ev := range evs {
		print(ev)
	}
	if !follow {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	audit.Follow(ctx, paths.AuditFile, func(ev protocol.AuditEvent) {
		if (q.Agent == "" || ev.Agent == q.Agent) && (q.Space == "" || ev.Space == q.Space) {
			print(ev)
		}
	})
}

func sortLeases(ls []protocol.LeaseInfo) {
	sort.Slice(ls, func(i, j int) bool { return ls[i].ExpiresAt.Before(ls[j].ExpiresAt) })
}
