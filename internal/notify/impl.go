package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"reclaim/internal/protocol"
	"reclaim/internal/space"
)

func displayAvailable() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

func desktop(title, body string, critical bool) error {
	exe, err := exec.LookPath("notify-send")
	if err != nil {
		return fmt.Errorf("notify-send not found: %w", err)
	}
	urgency := "normal"
	if critical {
		urgency = "critical"
	}
	cmd := exec.Command(exe, "--app-name=Reclaim", "--urgency="+urgency, "--icon=dialog-warning", title, body)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("notify-send: %w", err)
	}
	go func() {
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}()
	return nil
}

func dialogAvailable() bool {
	if !displayAvailable() {
		return false
	}
	_, err := exec.LookPath("zenity")
	return err == nil
}

func summary(p protocol.PromptInfo) (string, string) {
	sp := spaceTitle(p.Space)
	title := fmt.Sprintf("Reclaim: %s → %s", p.Agent, sp)
	body := fmt.Sprintf("%s: %s\n%s · answer with 'reclaim ui'", p.Label, p.Target, p.Why)
	return title, body
}

func spaceTitle(name string) string {
	if s, err := space.Parse(name); err == nil {
		return s.Title()
	}
	return name
}

// dialogKind distinguishes question dialogs from the typed-challenge form.
type dialogKind int

const (
	kindQuestion dialogKind = iota
	kindForm
)

// buildDialog is the pure part of Dialog: the zenity argv for p at time now.
func buildDialog(p protocol.PromptInfo, now time.Time) ([]string, dialogKind) {
	esc := html.EscapeString
	sp := spaceTitle(p.Space)
	from := spaceTitle(p.FromSpace)
	if p.FromSpace == "" {
		from = "Ambient"
	}
	cmd := ""
	if n := len(p.Chain); n > 0 {
		cmd = p.Chain[n-1].Cmdline
	}
	secs := int(p.Deadline.Sub(now).Seconds())
	if secs < 1 {
		secs = 1
	}
	var text strings.Builder
	fmt.Fprintf(&text, "<b>%s wants to %s %s</b>\n%s\n\nSpace: <b>%s</b> (currently in %s)\nWhy: %s\nCommand: %s\n",
		esc(p.Agent), esc(space.Op(p.Op).Verb()), esc(p.Target), esc(p.Label), esc(sp), esc(from), esc(p.Why), esc(cmd))
	if len(p.MoreTargets) > 0 {
		text.WriteString("Also waiting: ")
		for i, w := range p.MoreTargets {
			if i == 3 {
				text.WriteString("…")
				break
			}
			if i > 0 {
				text.WriteString(", ")
			}
			text.WriteString(esc(space.Op(w.Op).Verb() + " " + w.Target))
		}
		text.WriteString("\n")
	}
	fmt.Fprintf(&text, "Times out in %ds", secs)
	common := []string{"--title", "Reclaim — " + sp, "--width", "560", "--timeout", fmt.Sprint(secs)}
	if p.Friction == space.FrictionHigh.String() {
		fmt.Fprintf(&text, "\nType <b>%s</b> to allow", esc(p.Challenge))
		args := append([]string{"--forms", "--text", text.String()}, common...)
		args = append(args, "--add-entry", "Type "+p.Challenge)
		if p.AllowOnce {
			args = append(args, "--add-combo", "Scope", "--combo-values", p.LeaseText+"|Allow once only")
		}
		args = append(args, "--ok-label", "Allow", "--cancel-label", "Deny")
		return args, kindForm
	}
	args := append([]string{"--question", "--text", text.String()}, common...)
	args = append(args, "--ok-label", "Allow", "--cancel-label", "Deny")
	if p.AllowOnce {
		args = append(args, "--extra-button", "Allow once")
	}
	if p.Friction == space.FrictionMedium.String() {
		args = append(args, "--default-cancel")
	}
	return args, kindQuestion
}

// parseResult maps zenity's exit code and stdout to an action.
func parseResult(kind dialogKind, code int, stdout string) (action, challenge string, err error) {
	stdout = strings.TrimRight(stdout, "\n")
	switch code {
	case 0:
		if kind == kindForm {
			entry, combo, _ := strings.Cut(stdout, "|")
			if strings.HasPrefix(combo, "Allow once") {
				return protocol.ActionOnce, entry, nil
			}
			return protocol.ActionAllow, entry, nil
		}
		return protocol.ActionAllow, "", nil
	case 1:
		if stdout == "Allow once" {
			return protocol.ActionOnce, "", nil
		}
		return protocol.ActionDeny, "", nil
	case 5:
		return protocol.ActionDeny, "", nil
	}
	return "", "", fmt.Errorf("zenity exited with code %d", code)
}

func dialog(ctx context.Context, p protocol.PromptInfo) (string, string, error) {
	exe, err := exec.LookPath("zenity")
	if err != nil {
		return "", "", fmt.Errorf("zenity not found: %w", err)
	}
	args, kind := buildDialog(p, time.Now())
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("zenity: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-ctx.Done():
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return "", "", ctx.Err()
	case err := <-done:
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			return "", "", fmt.Errorf("zenity: %w", err)
		}
		return parseResult(kind, code, out.String())
	}
}
