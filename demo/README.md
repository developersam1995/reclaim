# Reclaim demo

A hands-on tour of Reclaim in a throwaway sandbox. You play the human; a
scripted agent plays the agent. About 10–15 minutes.

```sh
demo/demo.sh
```

That builds `bin/reclaim` if needed, creates `/tmp/reclaim-demo` (a fake
home with fake secrets, a fake project with a git repo, a demo config, and
its own daemon), and opens a tmux window: the tour on the left, the Reclaim
console (`reclaim ui`) on the right. Nothing touches your real
`~/.config/reclaim`, your real state, or the daemon serving your real agents.

Keys in the tour: **Enter** next · **s** skip the scene · **q** quit.
Keys in the console: **a** allow · **o** allow once · **d** deny ·
**r** reclaim everything · **q** close the console.

## What you will see

| Scene | The agent… | You learn |
|---|---|---|
| 1 | reads, edits, tests and commits in its project; lists `~/.ssh` | Project work never prompts; listing is not reading |
| 2 | reads `~/Documents/notes.txt` | Home Space, medium friction; a sliding lease with a countdown |
| 3 | reads `~/.ssh/id_ed25519`, then retries | Vault, high friction: deny it; EACCES, not a crash; denials stick for a while |
| 4 | reads `~/.aws/credentials`, then the SSH key | Typed-word approval; a fixed lease is per Space, not per file |
| 5 | connects to `1.1.1.1:80` twice | Remote Space; a never-seen target is "unexpected" |
| 6 | reads `~/.bashrc`, then appends to it | System Space: reads free, modifications gated |
| 7 | reads notes again after `reclaim now` | Leases expire; `now`, `hold`, `ttl`; the prompt's Why line; anti-autopilot |
| 8 | reads the SSH key with the console closed | Desktop notification and dialog (what VS Code users get) |
| 9 | runs with `--observe` | Audit without blocking; `explain`, `policy` |

Leases are shortened in the demo config (Home 90s, Vault 60s, Remote 90s,
System 60s) so you can watch Spaces close; the prompt timeout is 2 minutes
so you have time to read.

## Free play

```sh
demo/shell.sh
```

Opens the console next to a bash shell supervised by Reclaim inside the
sandbox project. You are the agent: try `cat ~/.ssh/id_ed25519`, `curl`
something, `echo x >> ~/.bashrc`, `reclaim status` (blocked: agents cannot
touch Reclaim itself), and answer your own prompts in the console.

## Other ways to run it

- `demo/demo.sh --auto` runs the tour unattended; it answers its own prompts
  after the reading delay. Useful to see the whole flow in under a minute.
- No tmux: `demo/demo.sh` tells you to open `reclaim ui` in a second
  terminal (`source demo/env.sh && reclaim ui`) and runs the tour inline.
- `RECLAIM_DEMO_QUIET=1 demo/demo.sh` turns off desktop toasts and dialogs
  (headless machines, or when you just do not want the pop-ups).
- `source demo/env.sh` in any shell points `reclaim` at the sandbox:
  `reclaim status`, `reclaim log -f`, `reclaim explain ~/.ssh/config`.

## Where things are

```
/tmp/reclaim-demo/
  home/                 the fake $HOME
    proj/               the agent's project (Project Space)
    Documents/notes.txt Home Space
    .ssh/, .aws/        Vault Space (fake keys)
    .bashrc             System Space
  cfg/reclaim/config.toml   demo config (short leases)
  state/reclaim/        state.json, audit.jsonl, daemon.log
  rt/reclaim/           the demo daemon's socket
  scenes/               the per-scene agent scripts the tour generated
```

## Afterwards

The tour stops the demo daemon when it ends. `demo/demo.sh` rebuilds the
sandbox from scratch every time; `rm -rf /tmp/reclaim-demo` removes it.

If something is stuck (a tour was killed mid-prompt): `source demo/env.sh;
reclaim daemon stop; tmux kill-session -t reclaim-demo`, then run the demo
again.
