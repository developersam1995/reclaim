// Command reclaim is the Reclaim CLI: a permission garbage collector for AI agents.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"reclaim/internal/client"
	"reclaim/internal/config"
	"reclaim/internal/daemon"
	"reclaim/internal/protocol"
	"reclaim/internal/supervisor"
	"reclaim/internal/ui"
)

const usage = `reclaim — let agents keep their knowledge; reclaim your system.

Usage:
  reclaim run [--agent NAME] [--project DIR]... [--observe] [--quiet] -- COMMAND [ARGS...]
  reclaim /abs/path/to/agent [ARGS...]        wrapper mode (editor integrations)
  reclaim ui                                  live console: spaces, prompts, audit
  reclaim status [--json]                     open spaces, countdowns, sessions, prompts
  reclaim now [--agent A] [--space S]         reclaim now: revoke leases immediately
  reclaim hold SPACE DURATION [--agent A]     hold a space open (e.g. hold remote 2h)
  reclaim ttl SPACE DURATION|default          tune a space's lease duration
  reclaim log [-n N] [-f] [--agent A] [--space S] [--json]
  reclaim approve ID [--once] [--word WORD]   answer a prompt from a shell
  reclaim deny ID
  reclaim explain PATH | HOST:PORT [--agent A] [--project DIR]
  reclaim policy                              effective policies and rules
  reclaim doctor                              check this machine
  reclaim init                                write a commented config file
  reclaim daemon [--foreground] | daemon stop
  reclaim version

Spaces: project, remote, vault, home, system, device.
`

const version = "0.1.0"

func main() {
	supervisor.MaybeShim()
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	paths, err := config.DefaultPaths()
	if err != nil {
		die(err)
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		die(err)
	}
	cmd, args := os.Args[1], os.Args[2:]
	// Wrapper mode: argv[1] is an executable path.
	if strings.Contains(cmd, "/") {
		if fi, err := os.Stat(cmd); err == nil && !fi.IsDir() {
			os.Exit(runSession(paths, cfg, append([]string{"--quiet", "--"}, os.Args[1:]...)))
		}
	}
	switch cmd {
	case "run":
		os.Exit(runSession(paths, cfg, args))
	case "daemon":
		cmdDaemon(paths, cfg, args)
	case "ui":
		if err := ui.Run(context.Background(), paths); err != nil {
			die(err)
		}
	case "status":
		cmdStatus(paths, args)
	case "now":
		cmdNow(paths, args)
	case "hold":
		cmdHold(paths, args)
	case "ttl":
		cmdTTL(paths, args)
	case "log":
		cmdLog(paths, args)
	case "approve", "deny":
		cmdAnswer(paths, cmd, args)
	case "explain":
		cmdExplain(paths, cfg, args)
	case "policy":
		cmdPolicy(paths, cfg, args)
	case "doctor":
		cmdDoctor(paths, cfg)
	case "init":
		cmdInit(paths)
	case "version", "--version", "-v":
		fmt.Println("reclaim", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "reclaim: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "reclaim:", err)
	os.Exit(1)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func runSession(paths config.Paths, cfg config.Config, args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	agent := fs.String("agent", "", "agent name (default: basename of COMMAND)")
	var projects multiFlag
	fs.Var(&projects, "project", "project root (repeatable; default: git top-level of cwd)")
	observe := fs.Bool("observe", false, "report would-be prompts without blocking")
	quiet := fs.Bool("quiet", false, "suppress informational messages")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	command := fs.Args()
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "reclaim run: COMMAND is required")
		return 2
	}
	exe, _ := os.Executable()
	// The supervisor owns signal handling (SIGINT goes to the agent via the
	// tty; SIGTERM/SIGHUP end the session tree).
	code, err := supervisor.Run(context.Background(), supervisor.Options{Paths: paths, Config: cfg, Agent: *agent, Projects: projects,
		Command: command, Exe: exe, Observe: *observe, Quiet: *quiet})
	if err != nil {
		fmt.Fprintln(os.Stderr, "reclaim:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func cmdDaemon(paths config.Paths, cfg config.Config, args []string) {
	if len(args) > 0 && args[0] == "stop" {
		c := dial(paths, false)
		var ok protocol.OK
		if err := c.Call(context.Background(), protocol.TypeShutdown, nil, &ok); err != nil {
			die(err)
		}
		fmt.Println("reclaim daemon stopping")
		return
	}
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	fg := fs.Bool("foreground", false, "run in the foreground (default when started by hand)")
	fs.Parse(args)
	_ = fg
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := daemon.Run(ctx, daemon.Options{Paths: paths, Config: cfg})
	if errors.Is(err, daemon.ErrAlreadyRunning) {
		fmt.Fprintln(os.Stderr, "reclaim: daemon already running")
		os.Exit(0)
	}
	if err != nil {
		die(err)
	}
}

// dial connects as a CLI client, auto-starting the daemon unless noStart.
func dial(paths config.Paths, autostart bool) *client.Conn {
	if autostart {
		exe, _ := os.Executable()
		if _, err := client.EnsureDaemon(paths, exe, 5*time.Second); err != nil {
			die(err)
		}
	}
	c, _, err := client.Dial(paths.Socket, protocol.Hello{Role: protocol.RoleCLI, Version: protocol.Version})
	if err != nil {
		die(fmt.Errorf("%v (is the daemon running? start an agent with 'reclaim run' or run 'reclaim daemon')", err))
	}
	return c
}

func cmdStatus(paths config.Paths, args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	fs.Parse(args)
	c := dial(paths, false)
	defer c.Close()
	var st protocol.State
	if err := c.Call(context.Background(), protocol.TypeStatus, nil, &st); err != nil {
		die(err)
	}
	if *asJSON {
		printJSON(st)
		return
	}
	fmt.Print(ui.RenderStatus(st, isTerminal()))
}

func cmdNow(paths config.Paths, args []string) {
	fs := flag.NewFlagSet("now", flag.ExitOnError)
	agent := fs.String("agent", "", "agent name or id (default: all)")
	sp := fs.String("space", "", "space (default: all)")
	fs.Parse(args)
	c := dial(paths, false)
	defer c.Close()
	var r protocol.ReclaimResult
	if err := c.Call(context.Background(), protocol.TypeReclaim, protocol.ReclaimRequest{Agent: *agent, Space: *sp}, &r); err != nil {
		die(err)
	}
	fmt.Printf("reclaimed %d lease(s)\n", r.Revoked)
}

func cmdHold(paths config.Paths, args []string) {
	fs := flag.NewFlagSet("hold", flag.ExitOnError)
	agent := fs.String("agent", "", "agent name or id (default: all live agents)")
	rest, flags := splitFlags(args)
	fs.Parse(flags)
	if len(rest) != 2 {
		die(errors.New("usage: reclaim hold SPACE DURATION [--agent A]"))
	}
	d, err := time.ParseDuration(rest[1])
	if err != nil {
		die(err)
	}
	c := dial(paths, false)
	defer c.Close()
	var ok protocol.OK
	if err := c.Call(context.Background(), protocol.TypeHold, protocol.HoldRequest{Agent: *agent, Space: rest[0], Duration: protocol.Duration(d)}, &ok); err != nil {
		die(err)
	}
	fmt.Println(ok.Message)
}

func cmdTTL(paths config.Paths, args []string) {
	if len(args) != 2 {
		die(errors.New("usage: reclaim ttl SPACE DURATION|default"))
	}
	req := protocol.SetTTLRequest{Space: args[0]}
	if args[1] == "default" {
		req.Reset = true
	} else {
		d, err := time.ParseDuration(args[1])
		if err != nil {
			die(err)
		}
		req.TTL = protocol.Duration(d)
	}
	c := dial(paths, false)
	defer c.Close()
	var ok protocol.OK
	if err := c.Call(context.Background(), protocol.TypeSetTTL, req, &ok); err != nil {
		die(err)
	}
	fmt.Println(ok.Message)
}

func cmdLog(paths config.Paths, args []string) {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	n := fs.Int("n", 50, "number of events")
	follow := fs.Bool("f", false, "follow new events")
	agent := fs.String("agent", "", "agent name filter")
	sp := fs.String("space", "", "space filter")
	asJSON := fs.Bool("json", false, "JSON lines")
	fs.Parse(args)
	ui.PrintLog(paths, protocol.AuditQuery{Limit: *n, Agent: *agent, Space: *sp}, *follow, *asJSON, isTerminal())
}

func cmdAnswer(paths config.Paths, cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	once := fs.Bool("once", false, "allow this single operation only")
	word := fs.String("word", "", "challenge word shown in the prompt (high friction)")
	rest, flags := splitFlags(args)
	fs.Parse(flags)
	if len(rest) != 1 {
		die(fmt.Errorf("usage: reclaim %s PROMPT-ID", cmd))
	}
	action := protocol.ActionDeny
	if cmd == "approve" {
		action = protocol.ActionAllow
		if *once {
			action = protocol.ActionOnce
		}
	}
	c := dial(paths, false)
	defer c.Close()
	var ok protocol.OK
	if err := c.Call(context.Background(), protocol.TypeAnswer, protocol.Answer{PromptID: rest[0], Action: action, Challenge: *word, Via: "cli"}, &ok); err != nil {
		die(err)
	}
	fmt.Println(cmd + "d")
}

func cmdInit(paths config.Paths) {
	if _, err := os.Stat(paths.ConfigFile); err == nil {
		die(fmt.Errorf("%s already exists", paths.ConfigFile))
	}
	if err := os.MkdirAll(paths.ConfigDir, 0o700); err != nil {
		die(err)
	}
	if err := os.WriteFile(paths.ConfigFile, []byte(config.Template), 0o600); err != nil {
		die(err)
	}
	fmt.Println("wrote", paths.ConfigFile)
}

// splitFlags separates positional arguments from --flags so flags may follow
// positionals (reclaim hold remote 2h --agent claude).
func splitFlags(args []string) (positional, flags []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	return
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func printJSON(v any) {
	b, err := jsonIndent(v)
	if err != nil {
		die(err)
	}
	os.Stdout.Write(b)
	fmt.Println()
}

func projectArg(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	return abs
}
