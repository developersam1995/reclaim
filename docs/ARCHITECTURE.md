# Reclaim — Architecture

> *Let agents keep their knowledge. Reclaim your system.*

This document is the architecture plan that accompanies the PRD
("Reclaim: Product Requirements & Architecture Plan"). It is also the
implementation contract: package boundaries, data flow, and invariants that
every package must honour.

Target platform for v1: **Linux x86_64** (aarch64 syscall tables included),
kernel ≥ 5.19 (tested on Ubuntu 24.04, kernel 6.8). Unprivileged — no root.
Language: Go (toolchain pinned in `go.mod`).

---

## 1. Key decision: how Reclaim intercepts

| Option | Pause-and-ask? | Session attribution | Root? | Can freeze the OS? | Network | Verdict |
|---|---|---|---|---|---|---|
| fanotify permission events | yes (files only) | must reconstruct from pid ancestry | yes | **yes** — every `open()` on the box waits on our daemon | no | rejected |
| eBPF LSM | no (deny only) | via cgroups | yes | no | yes | rejected (no pause) |
| Landlock | no (static) | per process tree | no | no | TCP ports only | rejected (no dynamic leases) |
| LD_PRELOAD shim | yes | per tree | no | no | yes | rejected (static binaries / raw syscalls bypass it) |
| ptrace | yes | per tree | no | no | yes | rejected (slow, fragile) |
| **seccomp user-notification** | **yes** | **inherited by every child — exact** | **no** | **no — only the agent's own thread waits** | **yes** | **chosen** |

`reclaim run -- <agent>` launches the agent under a seccomp filter whose
interesting syscalls return `SECCOMP_RET_USER_NOTIF`. The kernel parks the
calling thread and hands the syscall to Reclaim's supervisor, which decides
and either lets it proceed (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) or fails it
with `EACCES`. The filter is inherited across `fork`/`clone`/`execve` and
cannot be removed, so **the logical Agent Session is exactly the process tree
under the filter** (PRD 4.2). Unrelated processes are never affected.

Why this satisfies PRD 4.1:
- *Pause rather than fail*: the thread blocks in the kernel until we answer.
- *Seamless resume*: CONTINUE executes the original syscall unchanged.
- *Clean failure*: deny/timeout returns `EACCES` ("Permission denied").
- *Never hangs the host*: only the agent's calling thread waits; every prompt
  has a deadline; if the supervisor dies the kernel fails pending and future
  trapped syscalls (fail-closed) instead of hanging.
- `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` keeps a paused syscall from being
  restarted by stray signals while the user reads the prompt (fatal signals
  still kill it).

### Known limitation: setuid and snap tools
Unprivileged seccomp requires `PR_SET_NO_NEW_PRIVS` on the session, which
disables setuid/file-capability execs. Snap-packaged tools (`snap-confine` is
setuid) therefore cannot run inside a session; on this machine that includes
`docker`, `uv` and `firefox` from `/snap/bin`. `reclaim run` warns at launch
about snap commands found on PATH, and a trapped exec of `/snap/bin/*` fails
with a clear message instead of snap-confine's. Install the non-snap builds
(apt docker-ce, the `uv` installer) to use them under Reclaim.

### Why the supervisor is the launcher, not the daemon
Reading a syscall's path argument requires `/proc/<pid>/mem`. Ubuntu ships
Yama `ptrace_scope=1`: only an **ancestor** may read a process's memory. So
the `reclaim run` launcher (the agent's parent, also a child subreaper so
orphans stay its descendants) is the enforcement point. The daemon is the
decision point.

```
 ┌──────────────── agent session (seccomp filter, inherited) ───────────────┐
 │  claude ─┬─ bash -c "ssh prod-db" ── ssh                                 │
 │          └─ node mcp-server                                              │
 └──────────────┬───────────────────────────────────────────────────────────┘
                │ trapped syscalls (openat, connect, execve, rename, …)
                ▼
 ┌─────────── reclaim run (launcher = supervisor, PEP) ────────────┐
 │ decode args via /proc/pid/mem → resolve path/sockaddr           │
 │ classify → Space (policy) → gated? → local lease cache          │
 │ hit: CONTINUE + touch      miss: ask daemon, wait, respond      │
 └──────────────┬──────────────────────────────────────────────────┘
                │ JSON lines over $XDG_RUNTIME_DIR/reclaim/reclaimd.sock
                ▼
 ┌─────────── reclaim daemon (PDP, auto-started) ──────────────────┐
 │ lease table (sliding / fixed / hold) + 1s sweeper → reclaims    │
 │ prompt broker (coalesce, friction, challenge, timeout, cooldown)│
 │ audit log (JSONL)   state.json (leases, history, TTL overrides) │
 └───────┬──────────────────────┬──────────────────────┬───────────┘
         ▼                      ▼                      ▼
   reclaim ui (TUI)      desktop notification     zenity dialog
   status/prompts/log    (notify-send)            (fallback when no console)
```

---

## 2. Domain model (package `space`)

Six user-facing Spaces plus two internal classes:

| Space | Gated ops (others are free) | Lease | Base friction |
|---|---|---|---|
| Project | read, write, list, exec | sliding 48h idle, opened at launch | low |
| Remote | connect, listen, write | sliding 15m idle | medium → **high if target never approved before** |
| Vault | read, write, exec, connect | **fixed** 2m, or *allow once* | high |
| Home | read, write, list, exec | sliding 10m idle | medium |
| System | write, connect | **fixed** 5m, or *allow once* | high (reads are free: modification gate) |
| Device | read, write, connect | **fixed** 10m, or *allow once* | high |
| Ambient | — never gated (system runtime reads, /proc, loopback, DNS, agent's own state) | — | — |
| Control | always denied inside sessions (Reclaim's socket/config/state/binary) | — | — |

Leases are keyed by **(AgentID, Space)**. `AgentID = <agent name>@<primary
project root>` (e.g. `claude@/home/u/projects/reclaim`), so concurrent or
successive sessions of the same agent on the same project share leases, while
other agents/projects and all non-session processes are unaffected.

Lease kinds:
- **Sliding**: expires at `LastUsed + TTL`; any gated use refreshes it.
- **Fixed**: expires at `GrantedAt + TTL` no matter how often it is used
  (prevents keeping Vault open by polling, PRD 4.3).
- **Hold** (manual override) is a layer on a lease: `HoldUntil` keeps it open
  until then, after which normal decay resumes.
- **Once** is not a lease: it allows the single paused operation (and other
  operations paused on the *same target*), nothing more.

Every open/close bumps a daemon-wide, persisted **Gen** counter carried in
`LeaseInfo`. Sessions ignore stale pushes by Gen; a touch on a closed lease is
answered with `lease{open:false}`; a session whose push queue overflows
reconnects (`Hello.Resume`) and the welcome replaces its whole cache. All
lease timestamps are wall-clock (`time.Now().Round(0)`), so suspend counts as
elapsed time; the sweeper runs immediately after a clock jump.

**Remote activity**: trapped syscalls alone would miss a long-lived tunnel
or psql session (all traffic is read/write on a connected fd). Every 20s the
supervisor scans `/proc/<pid>/fd` of session processes for socket inodes,
matches them against ESTABLISHED entries in `/proc/net/tcp{,6}`, and touches
Remote while a non-local peer is connected. Loopback connects to an in-session
tunnel's forwarded port are still Ambient (documented limit).

**Decisions the kernel would make anyway are not prompted**: ops that touch
nothing on a missing target (read, list, exec, unix connect, unlink, rmdir,
chmod, truncate, rename source) and creates on a target that already exists
(mkdir, symlink, link, O_CREAT|O_EXCL), plus writes the user cannot perform
(no W_OK). This keeps `#!/usr/bin/env` PATH probing and `spawn()` silent.

**Known targets de-escalate**: a Vault/System target the user approved before
prompts at medium friction (deliberate key, no typed word); a Remote target
never approved before escalates to high. High-friction challenges are random
words from a fixed vocabulary, shown in the prompt, different every time.

---

## 3. Classification (package `policy`)

Input: a resolved filesystem target (lexical path + symlink-resolved path) or
a socket address. Output: `Result{Space, RuleID, Label, Display, Key, Detail}`.

Rule layers, evaluated in order; first match wins within the ordered list:
0. **Control** — Reclaim's config/state/runtime dirs, daemon socket, binary.
1. **User rules** from `config.toml` (`[[rules]]`).
2. **Agent self-state** (Ambient, scoped to that agent name): `~/.claude/**`,
   `~/.codex/**`, … plus `[agents.<name>].state`.
3. **Device** — `/dev/video*`, `/dev/snd/**`, `/dev/input/**`, display &
   audio sockets (X11 incl. abstract, Wayland, PipeWire, PulseAudio), Xauthority.
4. **Vault** — SSH/GPG keys and agents, keyrings, password stores, cloud /
   DB / registry credentials, browser profiles, messaging apps, `.env` files.
5. **Remote** — SSH client config & ControlMaster sockets, cloud CLI config.
6. **System** — shell startup files, autostart/systemd units, user-level
   installed software (`~/.local/bin`, site-packages, …), tool configs that
   execute code (`~/.gitconfig`, editor configs), system dirs, and control
   sockets of out-of-session daemons (D-Bus, systemd, Docker, tmux/screen,
   editor IPC) — connecting to them lets an agent act outside its session.
7. **Project** — project roots, developer toolchains & caches, `/tmp`.
8. **Home** — everything else under `$HOME`, plus `/media`, `/mnt`.
9. **Ambient** — everything else.

Lexical and resolved paths are classified independently; the more sensitive
result wins (`space.Rank`), so a symlink inside the project pointing at
`~/.ssh/id_ed25519` is Vault, and `/proc/self/root/home/u/.ssh/...` is too.

Network (`connect`, `sendto` with an address, `bind`):
- loopback / unspecified-connect → Ambient; port 53 → Ambient (configurable);
  `local_cidrs` → Ambient.
- agent root process → `control_plane_ports` (443) → Ambient ("agent control
  plane": the agent talking to its own model API must not hold Remote open).
- any session process → resolved `control_plane_hosts`:443 → Ambient.
- everything else → Remote, displayed as `ip:port`, with service name and
  reverse DNS when cheap, plus the command line that made the connection.
- `bind` to a non-loopback address with a non-zero port → Remote ("accept
  connections from the network").
- AF_UNIX → socket rules by path (resolved); abstract → abstract rules.

Glob syntax: absolute after expansion; `~` → home, `$XDG_RUNTIME_DIR`,
`{project}` → each project root; `*`, `?`, `[…]` within a segment; `**` as a
whole segment spans zero or more segments; a leading `**/` matches at any
depth; `dir/**` also matches `dir` itself.

---

## 4. Supervisor (package `supervisor`, `supervisor/seccomp`, `supervisor/procfs`)

`reclaim run [--agent NAME] [--project DIR]... -- CMD ARGS...`

1. Load config; resolve agent name (default `basename(CMD)`) and project roots
   (default: git toplevel of cwd, else cwd). Warn if a project root is `$HOME`.
2. Connect to the daemon (auto-start `reclaim daemon` detached if needed).
   If the daemon is unavailable, refuse to start the agent (fail closed).
3. `prctl(PR_SET_CHILD_SUBREAPER)`; create a socketpair; start
   `/proc/self/exe __reclaim_shim CMD…` with the child end as fd 3. The shim
   (fresh Go process): `LockOSThread`, resolve CMD via PATH,
   `PR_SET_NO_NEW_PRIVS`, install the filter with
   `NEW_LISTENER | WAIT_KILLABLE_RECV` (fallback without WAIT_KILLABLE_RECV on
   EINVAL), send the notify fd via `SCM_RIGHTS`, wait for a 1-byte ack, then
   `execve(CMD)` on the same locked thread.
4. Send `hello{role:session}` (AgentPID = shim pid), receive the welcome
   (session id, open leases, policies), ack the shim.
5. One SIGCHLD-driven `wait4(-1, WNOHANG)` reaper owns all reaping (no
   `exec.Cmd.Wait`); it records the root's exit status. The launcher ignores
   SIGINT/SIGQUIT while the root is alive (the tty delivers them to the agent
   already). Serve notifications until the root has been reaped AND the
   notify fd reports POLLHUP (every task holding the filter is gone). When the
   root exits while descendants remain, print a notice and keep supervising;
   SIGTERM to the launcher (or ctx cancellation) then SIGTERMs the remaining
   session processes, SIGKILLs after 5s, and keeps answering notifications
   (EACCES) until POLLHUP.
6. Exit with the agent's exit status (128+signal if killed).

**Wrapper mode**: when invoked as `reclaim <absolute-path> [args...]` (argv[1]
is an existing executable path rather than a subcommand) it behaves as
`reclaim run --quiet -- <path> [args...]`. This is how the VS Code Claude Code
extension uses it (`claudeCode.claudeProcessWrapper`); in that mode nothing is
ever written to stdout, and prompts reach the user via desktop notifications
and dialogs because no console is attached. Policies come from the daemon's
welcome (the daemon is the single source of policy); the shim receives
filter options via the `RECLAIM_SHIM_OPTS` environment variable.

### Filter (x86_64)
- Non-native arch (i386 `int 0x80`) and x32 syscalls → `ERRNO(ENOSYS)`.
- `io_uring_setup/enter/register` → `ERRNO(ENOSYS)` (io_uring bypasses seccomp).
- `seccomp(SET_MODE_FILTER, flags & NEW_LISTENER)` → `ERRNO(EPERM)` (a nested
  listener would take precedence over ours and could self-approve).
- If `block_namespaces`: `unshare`/`clone` with `CLONE_NEWUSER|CLONE_NEWNS` →
  `EPERM`; `setns` → `EPERM`; `clone3` → `ENOSYS` (libc falls back to clone).
- `openat`/`open` with `O_PATH` → ALLOW in-kernel (no content access).
- `sendto` with a NULL destination → ALLOW in-kernel.
- `prctl(PR_SET_DUMPABLE, 0)` → `ERRNO(0)` (reports success, does nothing):
  a non-dumpable process is unreadable through `/proc/pid/mem` even by its
  ancestor, which would otherwise be a one-line bypass. If arguments still
  cannot be read, the syscall fails with EACCES and an `unreadable` audit
  event (fail closed, no prompt).
- USER_NOTIF: `open, openat, openat2, creat, execve, execveat, connect,
  sendto(addr≠NULL), bind, rename, renameat, renameat2, unlink, unlinkat,
  rmdir, mkdir, mkdirat, symlink, symlinkat, link, linkat, truncate, chmod,
  fchmodat, fchmodat2`. (aarch64 has only the *at variants.)
- Everything else → ALLOW.

### Per-notification flow
```
recv → decode (op, targets[]) from nr/args, reading strings/sockaddrs from /proc/pid/mem
     → resolve each path: relative to /proc/pid/cwd or /proc/pid/fd/dirfd;
       /proc/self→/proc/<tgid>; best-effort symlink resolution incl. /proc magic links
     → classify each target; skip non-gated ops, ENOENT reads, unwritable writes
     → pick the most sensitive gated target
     → Control? → EACCES + "blocked" event
     → open lease in local cache? → CONTINUE, record touch (+ "entered" event on first use / new target)
     → else send `access` to daemon; poll ID_VALID every 500ms while waiting
       (process died → send `cancel`); daemon decision → respond
     → before responding: ID_VALID; respond CONTINUE or ERROR(-EACCES)
```
Concurrency: one goroutine blocks in `NOTIF_RECV`; each notification is
handled in its own goroutine so a pending prompt never blocks unrelated
syscalls. Identical in-flight requests (same space+target) share one daemon
request. Handler panics are recovered and answered with EACCES.

Lease cache: seeded from the welcome, updated by `lease` pushes. Sliding
leases are considered open until `localLastUsed + TTL`; fixed/hold until
`ExpiresAt`. Touches are batched and flushed every 500ms. If the daemon
connection drops, cached leases stay usable until they expire locally; any
new gated access is denied (fail closed) while reconnecting with backoff.

**Threat model.** Reclaim is a guardrail against well-intentioned but
overreaching agents (privilege creep, unprompted boundary crossings, lingering
access). It is not a sandbox for adversarial code: seccomp CONTINUE is subject
to TOCTOU (a hostile multithreaded process can swap a path after the check),
signals to other same-uid processes are not mediated, and processes outside
the session acting on the agent's behalf are mediated only at their control
sockets. These limits are documented for users.

---

## 5. Daemon (package `daemon`)

Single instance per user (flock on `reclaimd.lock`), socket `0600` in a
`0700` runtime dir; peers must have our uid (`SO_PEERCRED`). Control commands
that widen access (`answer`, `hold`, `set_ttl`) are rejected when the peer
process descends from a session launcher (it is inside an agent session).

State: sessions; lease table (`lease` package); prompts; history per
(AgentID, Space) (first entry, last reclaim + idle duration + cause, last
denial, known remote targets); TTL overrides. Persisted to `state.json`
(atomic rename) on change; reloaded on start (expired leases are reclaimed
immediately and audited).

Prompt broker:
- An `access` with an open lease (race) → immediate allow.
- Cooldown: same (AgentID, Space, TargetKey) denied within `deny_cooldown`
  → `cooldown` deny without prompting.
- Coalescing: pending prompts are keyed by (AgentID, Space); new requests
  attach as waiters (distinct targets listed in `MoreTargets`).
- Friction: base from policy (or the rule's override); Remote target unseen
  for this agent → high ("unexpected"); known Vault/System target → medium;
  ≥3 approvals in the last 60s → bump one level (anti-autopilot). High
  friction requires typing the prompt's random challenge word; every level
  has an arming delay during which answers are rejected with "too fast"
  (low 0, medium 0.8s, high 2.5s). A dialog answered too fast is shown again.
- Why text (PRD 4.4 reclamation context): first time / reclaimed N ago after
  M of inactivity / fixed lease expired N ago / you reclaimed it manually N
  ago / you denied it N ago.
- On allow: open lease per policy (or once), answer all matching waiters,
  push `lease` to the agent's sessions, audit `approved`. On deny: answer all
  waiters, record cooldown, audit `denied`. On deadline: `timeout` deny.
- Notifications: desktop notification per new prompt (if enabled); when no
  console is subscribed and `dialog=auto` (or `always`), a zenity dialog that
  mirrors the friction rules; it is closed when the prompt resolves elsewhere.

Sweeper (every second and at the next expiry): close expired leases, audit
`reclaimed` with cause and idle duration, push `lease{open:false}`.

---

## 6. User surfaces (PRD 4.5)

| Command | Purpose |
|---|---|
| `reclaim run [--agent N] [--project D]… [--observe] -- CMD…` | supervise an agent session (`--observe`: report, never prompt) |
| `reclaim /abs/path/to/agent args…` | wrapper mode (editor integrations) |
| `reclaim ui` | live console: open Spaces & countdowns, pending prompts, audit tail |
| `reclaim status [--json]` | open Spaces, holders, remaining countdowns, sessions, pending prompts |
| `reclaim now [--agent A] [--space S]` | immediate global reclaim ("reclaim now"); A is an agent name or AgentID |
| `reclaim hold SPACE DURATION [--agent A]` | hold a Space open (manual override) |
| `reclaim ttl SPACE DURATION\|default` | tune a Space's lease duration (overrides config until `default`) |
| `reclaim doctor` | check kernel support, daemon, snap/setuid tools on PATH, desktop notification path |
| `reclaim log [-n N] [-f] [--agent A] [--space S] [--json]` | human-readable audit history |
| `reclaim approve ID [--once] [--challenge WORD]` / `reclaim deny ID` | answer a prompt from a shell |
| `reclaim explain PATH \| HOST:PORT [--agent A] [--project D]` | which Space and rule, and why |
| `reclaim policy` | effective policies and rules |
| `reclaim init` | write a commented config template |
| `reclaim daemon [--foreground]` / `reclaim daemon stop` | manage the daemon |

---

## 7. Package map

```
cmd/reclaim            CLI entry; dispatches to packages; shim entry
internal/space         Space, Op, LeaseKind, Friction, Policy, defaults
internal/protocol      wire protocol (JSON lines) + Codec
internal/config        XDG paths, TOML config, policy overrides
internal/policy        rules, glob engine, path/socket classifier
internal/lease         lease table: grant/touch/hold/revoke/sweep, history, persistence
internal/friction      friction levels, challenges, arming delays, lease text
internal/audit         JSONL audit log, tail/follow, human formatting
internal/notify        desktop notifications, zenity dialogs
internal/client        daemon client: dial, autostart, request/response, pushes
internal/daemon        the daemon: sessions, prompts, sweeper, persistence, control API
internal/supervisor    launcher + notification handling + lease cache
  ├─ seccomp           BPF filter, install, notify ioctls, syscall tables
  └─ procfs            /proc/pid/mem reads, sockaddr parsing, path resolution, process chains
internal/ui            interactive console (bubbletea)
test/e2e               end-to-end tests running real sessions
```
