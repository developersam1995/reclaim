# Reclaim

*Let agents keep their knowledge. Reclaim your system.*

Reclaim is a permission garbage collector for AI coding agents on Linux. An
agent runs inside a **session**; everything it touches is sorted into six
human-level **Spaces** (Project, Remote, Vault, Home, System, Device). Each
Space is governed by a **lease** that closes after inactivity (or a fixed
time). When the agent next crosses into a reclaimed Space, the operation is
**paused** — not failed — until you approve or deny it, with friction
proportional to the sensitivity of what it is reaching for.

No root, no kernel modules: Reclaim uses seccomp user notification, so only
the agent's own thread waits while you read the prompt. The agent keeps
everything it learned; only its access is reclaimed.

## Requirements

- Linux x86_64 or arm64, kernel ≥ 5.19 (tested on Ubuntu 24.04 / 6.8)
- Go 1.27 toolchain to build (`go.mod` pins it; any Go ≥ 1.21 bootstraps it)
- Optional: `notify-send` (desktop notifications), `zenity` (approval dialogs
  when no console is open)

## Build

```sh
cd ~/projects/reclaim
go build -o bin/reclaim ./cmd/reclaim
bin/reclaim doctor          # checks kernel support, tools, snaps on PATH
```

## Use

First time? `demo/demo.sh` runs a guided tour in a throwaway sandbox (see
[demo/README.md](demo/README.md)).

```sh
# Supervise an agent in a terminal (the daemon starts automatically)
reclaim run -- claude
reclaim run --agent codex --project ~/work/api -- codex

# See what is open, what is pending, and what is about to be reclaimed
reclaim ui                      # live console: answer prompts with a / o / d
reclaim status

# Answer a prompt from any shell
reclaim approve k3f9 --word mango     # high friction: type the word shown
reclaim approve k3f9 --once
reclaim deny k3f9

# Controls
reclaim now                      # reclaim everything, immediately
reclaim now --agent claude --space remote
reclaim hold remote 2h           # keep Remote open while debugging
reclaim ttl home 30m             # tune a Space's lease (ttl home default resets)
reclaim log -n 50 -f             # human-readable audit history
reclaim explain ~/.aws/credentials   # which Space, which rule, which policy
reclaim run --observe -- claude  # audit an agent: log would-be prompts, block nothing
```

### VS Code (Claude Code extension)

Set the extension's **`claudeCode.claudeProcessWrapper`** setting to the
`reclaim` binary. The extension then runs `reclaim <claude-path> <args>`, which
is Reclaim's wrapper mode: silent, stdout untouched, prompts delivered as
desktop notifications and dialogs (or in `reclaim ui` if it is open).

## The six Spaces (defaults)

| Space | What lives here | Gated ops | Lease | Friction |
|---|---|---|---|---|
| Project | the project repo, build dirs, toolchains, `/tmp` | read write list exec | sliding 48h, opened at launch | low |
| Remote | SSH, databases, cloud CLIs, any non-local network | connect listen write | sliding 15m | medium; **high** for a never-seen target |
| Vault | SSH/GPG keys & agents, keyrings, cloud/DB creds, browser profiles, `.env` outside the project | read write exec connect | **fixed** 2m or allow-once | high (medium once a target is known) |
| Home | personal files outside the project | read write list exec | sliding 10m | medium |
| System | shell startup, autostart, installed software, `/etc`, D-Bus, docker, tmux | write connect (reads are free) | **fixed** 5m or allow-once | high |
| Device | camera, mic, keyboard input, screen, display server | read write connect | **fixed** 10m or allow-once | high |

Run `reclaim policy --rules` for the full rule list, or `reclaim explain PATH`
for one path. Override anything in `~/.config/reclaim/config.toml`
(`reclaim init` writes a commented template).

## How prompts work

- **Spatial framing**: "claude is in Project Space and wants to enter Vault
  Space: read ~/.ssh/id_ed25519 (SSH private key)", with the command that
  triggered it.
- **Why**: first time / reclaimed 2h ago after 10m of inactivity / fixed lease
  ended / you reclaimed it manually / you denied it 3m ago.
- **Friction**: low = one key; medium = a short reading delay, then a
  deliberate key; high = a longer delay, then type a random word shown in the
  prompt (never the same word twice, so it can't become muscle memory).
- Unanswered prompts fail the operation with `EACCES` after the timeout
  (default 60s). A denial auto-denies identical requests for 30s.

## Limits you should know

- **Snaps**: seccomp without root requires `no_new_privs`, which disables
  setuid — snap-packaged tools (`docker`, `uv`, `firefox` on this machine)
  cannot run inside a session. Use non-snap builds.
- **Not a sandbox for hostile code**: Reclaim guards against overreaching
  agents, not adversarial ones (seccomp CONTINUE has TOCTOU limits; signals
  and already-open connections are not mediated).
- Connections through an SSH tunnel's local port are loopback and therefore
  not Remote; the tunnel itself is, and Remote stays open while it is
  connected.

## Layout

```
cmd/reclaim            CLI, wrapper mode, shim entry
internal/space         Spaces, ops, policies
internal/policy        classification rules & glob engine
internal/supervisor    `reclaim run`: seccomp filter, /proc decoding, lease cache
internal/daemon        leases, prompts, friction, audit, persistence
internal/ui            console (reclaim ui) and status rendering
internal/{lease,friction,audit,notify,client,protocol,config}
docs/ARCHITECTURE.md   design and contracts
test/e2e               real sessions against a real daemon
```

```sh
go test ./...          # unit + end-to-end (needs seccomp user-notif)
```
