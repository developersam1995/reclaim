package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"reclaim/internal/config"
	"reclaim/internal/notify"
	"reclaim/internal/policy"
	"reclaim/internal/space"
	"reclaim/internal/supervisor"
	"reclaim/internal/supervisor/seccomp"
)

func jsonIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

func cmdExplain(paths config.Paths, cfg config.Config, args []string) {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	agent := fs.String("agent", "claude", "agent name (agent-specific rules)")
	var projects multiFlag
	fs.Var(&projects, "project", "project root (repeatable; default: git top-level of cwd)")
	rest, flags := splitFlags(args)
	fs.Parse(flags)
	if len(rest) != 1 {
		die(errors.New("usage: reclaim explain PATH | HOST:PORT"))
	}
	cwd, _ := os.Getwd()
	if len(projects) == 0 {
		projects = supervisor.DefaultProjects(cwd)
	}
	for i := range projects {
		projects[i] = projectArg(projects[i])
	}
	exe, _ := os.Executable()
	c, err := policy.ForSession(paths, cfg, *agent, projects, exe)
	if err != nil {
		die(err)
	}
	pols, _ := cfg.Policies()
	target := rest[0]
	var res policy.Result
	if host, port, err := net.SplitHostPort(target); err == nil {
		p, err := strconv.Atoi(port)
		if err != nil {
			die(fmt.Errorf("bad port %q", port))
		}
		ip := net.ParseIP(host)
		if ip == nil {
			addrs, err := net.LookupIP(host)
			if err != nil || len(addrs) == 0 {
				die(fmt.Errorf("cannot resolve %s", host))
			}
			ip = addrs[0]
			fmt.Printf("%s resolves to %s\n", host, ip)
		}
		fam := "inet"
		if ip.To4() == nil {
			fam = "inet6"
		}
		res = c.ClassifySocket(space.OpConnect, policy.SockTarget{Family: fam, IP: ip, Port: p}, false, nil)
		fmt.Printf("%-10s %s\n%-10s %s (%s)\n", "target:", res.Display, "space:", res.Space.Title(), res.RuleID)
		if res.Detail != "" {
			fmt.Printf("%-10s %s\n", "detail:", res.Detail)
		}
		fmt.Println("note:      connections from the agent's own process to port 443 count as its control plane (see config network.control_plane_ports)")
	} else {
		if strings.HasPrefix(target, "~/") {
			target = filepath.Join(paths.Home, target[2:])
		}
		abs, err := filepath.Abs(target)
		if err != nil {
			die(err)
		}
		resolved := abs
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			resolved = r
		}
		res = c.ClassifyPath(policy.PathTarget{Lexical: abs, Resolved: resolved})
		fmt.Printf("%-10s %s\n%-10s %s (%s)\n%-10s %s\n", "target:", res.Display, "space:", res.Space.Title(), res.RuleID, "label:", res.Label)
	}
	if res.Space.UserFacing() {
		p := pols[res.Space]
		ops := make([]string, len(p.GatedOps))
		for i, o := range p.GatedOps {
			ops[i] = string(o)
		}
		fr := p.Friction
		if res.Friction != space.FrictionNone {
			fr = res.Friction
		}
		fmt.Printf("%-10s %s\n%-10s %s lease, %s; friction %s\n", "gated ops:", strings.Join(ops, ", "), "policy:", p.Kind, space.HumanDuration(p.TTL), fr)
	} else {
		fmt.Printf("%-10s never prompted\n", "gated ops:")
	}
}

func cmdPolicy(paths config.Paths, cfg config.Config, args []string) {
	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	agent := fs.String("agent", "claude", "agent name")
	showRules := fs.Bool("rules", false, "also list every classification rule")
	fs.Parse(args)
	pols, err := cfg.Policies()
	if err != nil {
		die(err)
	}
	fmt.Printf("config: %s\n\n", paths.ConfigFile)
	fmt.Printf("%-9s %-8s %-6s %-9s %-6s %s\n", "SPACE", "LEASE", "TTL", "FRICTION", "ONCE", "GATED OPS")
	for _, sp := range space.All {
		p := pols[sp]
		ops := make([]string, len(p.GatedOps))
		for i, o := range p.GatedOps {
			ops[i] = string(o)
		}
		once := "no"
		if p.AllowOnce {
			once = "yes"
		}
		fmt.Printf("%-9s %-8s %-6s %-9s %-6s %s\n", sp, p.Kind, space.HumanDuration(p.TTL), p.Friction, once, strings.Join(ops, ","))
	}
	fmt.Printf("\nprompt timeout %s · deny cooldown %s · dialog %s · desktop notifications %v\n",
		cfg.Prompt.Timeout, cfg.Prompt.DenyCooldown, cfg.Prompt.Dialog, cfg.Prompt.DesktopNotify)
	if !*showRules {
		fmt.Println("\nuse --rules to list classification rules; 'reclaim explain PATH' to test one path")
		return
	}
	cwd, _ := os.Getwd()
	exe, _ := os.Executable()
	c, err := policy.ForSession(paths, cfg, *agent, supervisor.DefaultProjects(cwd), exe)
	if err != nil {
		die(err)
	}
	fmt.Println()
	for _, r := range c.Rules() {
		fmt.Printf("%-28s %-8s %s\n", r.ID, r.Space, r.Label)
		for _, p := range r.Paths {
			fmt.Printf("%-28s   path    %s\n", "", policy.Pretty(paths.Home, p))
		}
		for _, p := range r.Except {
			fmt.Printf("%-28s   except  %s\n", "", policy.Pretty(paths.Home, p))
		}
		for _, p := range r.Sockets {
			fmt.Printf("%-28s   socket  %s\n", "", policy.Pretty(paths.Home, p))
		}
		for _, p := range r.Abstract {
			fmt.Printf("%-28s   abstract @%s\n", "", p)
		}
	}
}

func cmdDoctor(paths config.Paths, cfg config.Config) {
	ok := func(good bool, what, detail string) {
		mark := "✔"
		if !good {
			mark = "✘"
		}
		fmt.Printf("%s %-34s %s\n", mark, what, detail)
	}
	var uts unix.Utsname
	unix.Uname(&uts)
	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	ok(true, "kernel", release)
	// seccomp user notification availability.
	avail := false
	act := uint32(unix.SECCOMP_RET_USER_NOTIF)
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_ACTION_AVAIL, 0, uintptrOf(&act)); errno == 0 {
		avail = true
	}
	ok(avail, "seccomp user notification", map[bool]string{true: "available", false: "NOT available (kernel too old or seccomp disabled)"}[avail])
	if _, err := seccomp.BuildFilter(seccomp.FilterOptions{BlockNamespaces: cfg.BlockNamespaces()}); err != nil {
		ok(false, "filter", err.Error())
	} else {
		ok(true, "filter", fmt.Sprintf("%d trapped syscalls", len(seccomp.TrappedSyscalls())))
	}
	yama, _ := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	y := strings.TrimSpace(string(yama))
	ok(y == "" || y == "0" || y == "1", "yama ptrace_scope", y+" (0 or 1 needed to read agent memory)")
	_, err := os.Stat(paths.Socket)
	ok(err == nil, "daemon", map[bool]string{true: "socket present at " + paths.Socket, false: "not running (starts automatically with 'reclaim run')"}[err == nil])
	_, cfgErr := os.Stat(paths.ConfigFile)
	ok(true, "config", map[bool]string{true: paths.ConfigFile, false: "defaults ('reclaim init' writes a template)"}[cfgErr == nil])
	ok(true, "state", paths.StateDir)
	ok(notify.DisplayAvailable(), "graphical session", map[bool]string{true: "yes", false: "no (prompts only via 'reclaim ui' and the CLI)"}[notify.DisplayAvailable()])
	_, nsErr := exec.LookPath("notify-send")
	ok(nsErr == nil, "notify-send", map[bool]string{true: "found", false: "missing: apt install libnotify-bin"}[nsErr == nil])
	ok(notify.DialogAvailable(), "zenity dialogs", map[bool]string{true: "found", false: "missing: apt install zenity (needed when no console is open)"}[notify.DialogAvailable()])
	var snaps []string
	for _, cmd := range []string{"docker", "uv", "code", "firefox", "chromium", "kubectl", "aws", "gh", "node", "go"} {
		if p, err := exec.LookPath(cmd); err == nil && strings.HasPrefix(p, "/snap/") {
			snaps = append(snaps, cmd)
		}
	}
	ok(len(snaps) == 0, "snap tools on PATH", map[bool]string{true: "none", false: strings.Join(snaps, ", ") + " cannot run inside sessions (setuid snap-confine)"}[len(snaps) == 0])
	if p, err := exec.LookPath("claude"); err == nil {
		fmt.Printf("\nVS Code: set \"claudeCode.claudeProcessWrapper\" to this binary to supervise the extension's Claude Code.\nTerminal: reclaim run -- %s\n", p)
	}
}

func uintptrOf(p *uint32) uintptr { return uintptr(unsafePointer(p)) }
