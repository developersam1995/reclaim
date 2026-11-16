package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"reclaim/internal/audit"
	"reclaim/internal/client"
	"reclaim/internal/config"
	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

var (
	styTitle  = lipgloss.NewStyle().Bold(true)
	styDim    = lipgloss.NewStyle().Faint(true)
	styWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	styDanger = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styBox    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	styHot    = lipgloss.NewStyle().Border(lipgloss.ThickBorder()).BorderForeground(lipgloss.Color("214")).Padding(0, 1)
	stySel    = lipgloss.NewStyle().Reverse(true)
)

type stateMsg protocol.State
type pushMsg protocol.Envelope
type disconnectMsg struct{ err error }
type tickMsg time.Time
type answerMsg struct{ err error }

type model struct {
	paths   config.Paths
	conn    *client.Conn
	st      protocol.State
	sel     int
	typing  bool   // entering a challenge word
	action  string // pending action while typing
	input   string
	status  string
	statusT time.Time
	width   int
	height  int
	err     error
	now     time.Time
}

func run(ctx context.Context, paths config.Paths) error {
	exe, _ := os.Executable()
	if _, err := client.EnsureDaemon(paths, exe, 5*time.Second); err != nil {
		return err
	}
	conn, _, err := client.Dial(paths.Socket, protocol.Hello{Role: protocol.RoleUI, Version: protocol.Version})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Call(ctx, protocol.TypeSubscribe, nil, nil); err != nil {
		return err
	}
	m := model{paths: paths, conn: conn, now: time.Now()}
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx))
	_, err = p.Run()
	return err
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.waitPush(), tick())
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) waitPush() tea.Cmd {
	return func() tea.Msg {
		e, ok := <-m.conn.Pushes()
		if !ok {
			return disconnectMsg{err: m.conn.Err()}
		}
		return pushMsg(e)
	}
}

func (m model) answer(id, action, word string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return answerMsg{err: m.conn.Call(ctx, protocol.TypeAnswer, protocol.Answer{PromptID: id, Action: action, Challenge: word, Via: "console"}, nil)}
	}
}

func (m model) reclaimAll() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var r protocol.ReclaimResult
		err := m.conn.Call(ctx, protocol.TypeReclaim, protocol.ReclaimRequest{}, &r)
		if err == nil {
			err = fmt.Errorf("reclaimed %d lease(s)", r.Revoked)
		}
		return answerMsg{err: err}
	}
}

func (m *model) setStatus(s string) {
	m.status = s
	m.statusT = time.Now()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		m.now = time.Time(msg)
		return m, tick()
	case pushMsg:
		if msg.Type == protocol.TypeState {
			if st, err := protocol.Decode[protocol.State](protocol.Envelope(msg)); err == nil {
				m.st = st
				if m.sel >= len(st.Prompts) {
					m.sel = max(0, len(st.Prompts)-1)
				}
			}
		}
		if msg.Type == protocol.TypeStopping {
			m.setStatus("daemon stopping")
		}
		return m, m.waitPush()
	case disconnectMsg:
		m.err = msg.err
		if m.err == nil {
			m.err = errors.New("disconnected from the daemon")
		}
		return m, tea.Quit
	case answerMsg:
		if msg.err != nil {
			m.setStatus(msg.err.Error())
		} else {
			m.setStatus("done")
		}
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m model) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.typing {
		switch k.Type {
		case tea.KeyEnter:
			m.typing = false
			word := strings.TrimSpace(m.input)
			m.input = ""
			if m.sel < len(m.st.Prompts) {
				return m, m.answer(m.st.Prompts[m.sel].ID, m.action, word)
			}
		case tea.KeyEsc, tea.KeyCtrlC:
			m.typing, m.input = false, ""
		case tea.KeyBackspace:
			if len(m.input) > 0 {
				m.input = m.input[:len(m.input)-1]
			}
		case tea.KeyRunes:
			m.input += string(k.Runes)
		}
		return m, nil
	}
	switch k.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "j", "down":
		if m.sel < len(m.st.Prompts)-1 {
			m.sel++
		}
	case "k", "up":
		if m.sel > 0 {
			m.sel--
		}
	case "a", "o", "d":
		if m.sel >= len(m.st.Prompts) {
			return m, nil
		}
		p := m.st.Prompts[m.sel]
		action := map[string]string{"a": protocol.ActionAllow, "o": protocol.ActionOnce, "d": protocol.ActionDeny}[k.String()]
		if action == protocol.ActionOnce && !p.AllowOnce {
			m.setStatus("this space has no allow-once; use a (allow) or d (deny)")
			return m, nil
		}
		if action != protocol.ActionDeny {
			if left := p.CreatedAt.Add(p.ArmDelay.D()).Sub(m.now); left > 0 {
				m.setStatus(fmt.Sprintf("read the prompt first — answers accepted in %ds", int(left.Seconds())+1))
				return m, nil
			}
			if p.Challenge != "" {
				m.typing, m.action, m.input = true, action, ""
				return m, nil
			}
			if p.Friction == space.FrictionMedium.String() && k.String() == "a" && !strings.HasPrefix(m.status, "press a again") {
				m.setStatus("press a again to allow (" + p.LeaseText + ")")
				return m, nil
			}
		}
		m.status = ""
		return m, m.answer(p.ID, action, "")
	case "r":
		return m, m.reclaimAll()
	}
	return m, nil
}

func (m model) View() string {
	if m.err != nil {
		return "reclaim ui: " + m.err.Error() + "\n"
	}
	now := m.now
	if !m.st.Now.IsZero() && m.st.Now.After(now) {
		now = m.st.Now
	}
	w := m.width
	if w < 60 {
		w = 100
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", styTitle.Render("Reclaim"), styDim.Render(fmt.Sprintf("daemon pid %d · %d session(s) · a allow · o once · d deny · r reclaim all · q quit", m.st.DaemonPID, len(m.st.Sessions))))

	// Prompts.
	if len(m.st.Prompts) == 0 {
		b.WriteString(styBox.Width(w - 2).Render(styDim.Render("No pending prompts — the agent is working inside its open Spaces.")))
	} else {
		var lines []string
		for i, p := range m.st.Prompts {
			lines = append(lines, m.renderPrompt(p, i == m.sel, now))
		}
		b.WriteString(styHot.Width(w - 2).Render(strings.Join(lines, "\n\n")))
	}
	b.WriteString("\n")
	if m.typing {
		fmt.Fprintf(&b, "%s %s▏\n", styWarn.Render("Type the word shown above and press Enter (Esc cancels):"), m.input)
	}
	if m.status != "" && time.Since(m.statusT) < 8*time.Second {
		b.WriteString(styWarn.Render(m.status) + "\n")
	}

	// Spaces.
	b.WriteString(styTitle.Render("Open Spaces") + "\n")
	if len(m.st.Leases) == 0 {
		b.WriteString(styDim.Render("  none — everything is reclaimed") + "\n")
	}
	for _, l := range m.st.Leases {
		line := LeaseLine(l, now)
		if l.ExpiresAt.Sub(now) < time.Minute {
			line = styWarn.Render(line)
		}
		b.WriteString("  " + line + "\n")
	}
	// Sessions.
	b.WriteString(styTitle.Render("Sessions") + "\n")
	if len(m.st.Sessions) == 0 {
		b.WriteString(styDim.Render("  none — start one with: reclaim run -- claude") + "\n")
	}
	for _, s := range m.st.Sessions {
		cur := s.CurrentSpace
		if cur == "" {
			cur = "-"
		}
		mode := ""
		if s.Observe {
			mode = styDim.Render(" observe")
		}
		fmt.Fprintf(&b, "  %-8s %-30s pid %-7d in %-8s%s\n", s.Agent, trunc(strings.Join(s.Projects, ","), 30), s.AgentPID, cur, mode)
	}
	// Audit tail.
	b.WriteString(styTitle.Render("Recent") + "\n")
	n := m.height - strings.Count(b.String(), "\n") - 2
	if n < 3 {
		n = 3
	}
	ev := m.st.Recent
	if len(ev) > n {
		ev = ev[len(ev)-n:]
	}
	for _, e := range ev {
		b.WriteString("  " + trunc(audit.Format(e, true), w-4) + "\n")
	}
	return b.String()
}

func (m model) renderPrompt(p protocol.PromptInfo, selected bool, now time.Time) string {
	left := p.Deadline.Sub(now)
	head := fmt.Sprintf("[%s] %s is in %s and wants to enter %s", p.ID, p.Agent, fromTitle(p.FromSpace), styDanger.Render(space.MustTitle(p.Space)))
	if selected {
		head = stySel.Render(head)
	}
	var lines []string
	lines = append(lines, head)
	lines = append(lines, fmt.Sprintf("  %s %s  %s", styTitle.Render(space.Op(p.Op).Verb()), p.Target, styDim.Render("("+p.Label+")")))
	if p.Detail != "" {
		lines = append(lines, "  "+styDim.Render(p.Detail))
	}
	lines = append(lines, "  "+styWarn.Render(p.Why))
	if n := len(p.Chain); n > 0 {
		lines = append(lines, "  "+styDim.Render("command: "+trunc(p.Chain[n-1].Cmdline, 90)))
	}
	if p.Unexpected {
		lines = append(lines, "  "+styDanger.Render("Unexpected: this remote target was never approved before."))
	}
	for i, w := range p.MoreTargets {
		if i == 3 {
			lines = append(lines, styDim.Render(fmt.Sprintf("  … and %d more", len(p.MoreTargets)-3)))
			break
		}
		lines = append(lines, styDim.Render(fmt.Sprintf("  also waiting: %s %s", space.Op(w.Op).Verb(), w.Target)))
	}
	armed := now.After(p.CreatedAt.Add(p.ArmDelay.D()))
	var act string
	switch {
	case !armed:
		act = styDim.Render(fmt.Sprintf("reading time… answers in %ds", int(p.CreatedAt.Add(p.ArmDelay.D()).Sub(now).Seconds())+1))
	case p.Challenge != "":
		act = fmt.Sprintf("a allow %s · type %s to confirm", p.LeaseText, styDanger.Render(strings.ToUpper(p.Challenge)))
	default:
		act = "a allow " + p.LeaseText
	}
	if p.AllowOnce {
		act += " · o once"
	}
	act += " · d deny"
	lines = append(lines, fmt.Sprintf("  %s   %s · %s", act, styDim.Render(p.Friction+" friction"), styDim.Render(space.HumanDuration(left)+" left")))
	return strings.Join(lines, "\n")
}

func fromTitle(name string) string {
	if name == "" {
		return "Ambient"
	}
	return space.MustTitle(name)
}
