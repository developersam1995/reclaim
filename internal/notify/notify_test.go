package notify

import (
	"slices"
	"strings"
	"testing"
	"time"

	"reclaim/internal/protocol"
)

func prompt(friction string, once bool) protocol.PromptInfo {
	return protocol.PromptInfo{Agent: "claude", Space: "vault", FromSpace: "project", Op: "read",
		Target: "~/.ssh/id_ed25519", Label: "SSH private key <x>", Why: "First time claude enters Vault Space.",
		Friction: friction, Challenge: "amber", AllowOnce: once, LeaseText: "for 2m (fixed)",
		Deadline:    time.Unix(1000, 0).Add(42 * time.Second),
		Chain:       []protocol.ProcInfo{{Cmdline: "ssh prod & echo"}},
		MoreTargets: []protocol.Waiter{{Op: "read", Target: "~/.ssh/id_rsa"}}}
}

func TestBuildDialog(t *testing.T) {
	args, kind := buildDialog(prompt("low", true), time.Unix(1000, 0))
	if kind != kindQuestion || args[0] != "--question" || !slices.Contains(args, "--extra-button") || slices.Contains(args, "--default-cancel") {
		t.Fatalf("low args = %v", args)
	}
	text := args[2]
	for _, want := range []string{"SSH private key &lt;x&gt;", "ssh prod &amp; echo", "Times out in 42s", "Also waiting: read ~/.ssh/id_rsa", "(currently in Project Space)"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
	if i := slices.Index(args, "--timeout"); i < 0 || args[i+1] != "42" {
		t.Fatalf("timeout arg wrong: %v", args)
	}
	args, _ = buildDialog(prompt("medium", false), time.Unix(1000, 0))
	if !slices.Contains(args, "--default-cancel") || slices.Contains(args, "--extra-button") {
		t.Fatalf("medium args = %v", args)
	}
	args, kind = buildDialog(prompt("high", true), time.Unix(1000, 0))
	if kind != kindForm || args[0] != "--forms" || !slices.Contains(args, "--add-combo") || !strings.Contains(args[2], "Type <b>amber</b>") {
		t.Fatalf("high args = %v", args)
	}
	args, _ = buildDialog(prompt("high", false), time.Unix(1000, 0))
	if slices.Contains(args, "--add-combo") {
		t.Fatal("combo offered without AllowOnce")
	}
}

func TestParseResult(t *testing.T) {
	cases := []struct {
		kind   dialogKind
		code   int
		out    string
		action string
		chal   string
		err    bool
	}{
		{kindQuestion, 0, "", protocol.ActionAllow, "", false},
		{kindQuestion, 1, "Allow once\n", protocol.ActionOnce, "", false},
		{kindQuestion, 1, "", protocol.ActionDeny, "", false},
		{kindQuestion, 5, "", protocol.ActionDeny, "", false},
		{kindForm, 0, "amber|for 2m (fixed)\n", protocol.ActionAllow, "amber", false},
		{kindForm, 0, "amber|Allow once only\n", protocol.ActionOnce, "amber", false},
		{kindForm, 0, "amber\n", protocol.ActionAllow, "amber", false},
		{kindForm, 1, "", protocol.ActionDeny, "", false},
		{kindQuestion, 255, "", "", "", true},
	}
	for _, c := range cases {
		a, ch, err := parseResult(c.kind, c.code, c.out)
		if (err != nil) != c.err || a != c.action || ch != c.chal {
			t.Errorf("parseResult(%v,%d,%q) = %q %q %v", c.kind, c.code, c.out, a, ch, err)
		}
	}
}

func TestSummary(t *testing.T) {
	title, body := Summary(prompt("low", false))
	if title != "Reclaim: claude → Vault Space" || !strings.Contains(body, "SSH private key <x>: ~/.ssh/id_ed25519") {
		t.Fatalf("summary = %q / %q", title, body)
	}
}
