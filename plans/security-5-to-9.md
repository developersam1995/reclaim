# Reclaim security plan: from 5 to 9

Status: proposed, not started.
Written 2026-11-12 against the code as it stood that day. The project is not in git yet, so every `file:line` below refers to that snapshot.

## 1. What a 9 means

The README says Reclaim "guards against overreaching agents, not adversarial ones". That sentence is the gap between 5 and 9. The target is:

> An agent that is actively trying to get out (prompt-injected, running any code it likes as your user inside the session) cannot read, change, or contact anything outside its floor without an approval that accurately described what was being granted. It cannot forge an approval, hide what it did from the audit log, or keep access after it has been reclaimed.

Three terms used throughout:

- **Floor**: what a session may touch with no decision at all. System runtime files (read-only), the project, the session's private temp directory, the agent's own data.
- **CONTINUE**: the seccomp reply that lets the kernel run the paused syscall itself. The kernel re-reads the path or address from the agent's memory at that point, after Reclaim has already checked it.
- **Broker**: instead of CONTINUE, the supervisor performs the operation itself (opens the file, makes the connection) and hands the result back to the agent. What was checked is exactly what was done.

### Exit criteria

1. Every finding in section 2 has a test in `test/adversarial/` that failed before its fix and passes after. The suite gates CI.
2. No operation outside the floor is ever answered with CONTINUE. One function owns that reply and a test enforces it.
3. An unknown path, socket, address family or port is gated or denied, never free. A property test checks this.
4. The kernel floor (Landlock) is on by default wherever the kernel supports it, and `reclaim doctor` prints the hardening level.
5. A time-boxed red-team pass by someone who did not write the fixes finds no boundary bypass.
6. README and `docs/ARCHITECTURE.md` state the new threat model and list the residual risks in section 6.

## 2. Findings: why it is a 5 today

Status key:

- **Confirmed**: reproduced on 2026-11-12 with dummy data in a throwaway HOME/XDG environment. Commands are in the appendix.
- **Read**: found by reading the code, not run.

| # | Finding | Status | Where | Phase |
|---|---|---|---|---|
| F1 | `..` is collapsed as text before symlinks are resolved, so the classifier and the kernel disagree. `ln -s ~/.ssh p; cat p/../.aws/credentials` reads a Vault file with no prompt and no audit entry. | Confirmed | `internal/supervisor/procfs/resolve.go:56,71` | 1 |
| F2 | `sendmsg` and `sendmmsg` are not trapped. UDP to any host goes out unprompted while the same `sendto` is denied. | Confirmed | `internal/supervisor/seccomp/syscalls_amd64.go` | 1 |
| F3 | Any unix socket not on the built-in list is Ambient. The agent can connect to any service outside the session that Reclaim has not heard of. | Confirmed | `internal/policy/engine.go:234` | 2 |
| F4 | With only a Home lease, the agent can rewrite Reclaim's own config: `mv ~/.config ~/c2`, edit `~/c2/reclaim/config.toml`, move it back. Control protection is per path, not per subtree. The audit log shows only "modify ~/.config". | Confirmed | `internal/policy/engine.go:30-36` | 2 |
| F5 | Any filesystem location no rule matches is Ambient: free to read and write. Examples: `/data/**`, `/run/user/<uid>/containers/auth.json` (registry credentials), `/run/user/<uid>/gvfs/**` (mounted network shares). | Confirmed | `internal/policy/engine.go:146` | 2 |
| F6 | Writes to toolchain executables are free under the launch lease (`~/.nvm/**/bin/node`, `~/miniconda3/bin/python`). The agent can replace a binary you later run outside any session. | Confirmed | `internal/policy/rules.go:189-200` | 2 |
| F7 | The agent's "own state" is free to write even where it is code that runs outside the session: `~/.vscode/extensions/anthropic.claude-code-*/**`, `~/.local/bin/claude`. | Confirmed | `internal/policy/rules.go:32-35` | 2 |
| F8 | Project files that other tools execute on their own are ordinary Project files: `.git/hooks/**`, `.vscode/settings.json`, `.vscode/tasks.json`, `.envrc`. | Confirmed | `internal/policy/rules.go:170-171` | 2 |
| F9 | All of `/tmp` and `/dev/shm` is Project, including other programs' files such as `/tmp/krb5cc_<uid>`. | Confirmed | `internal/policy/rules.go:209-210` | 2 |
| F10 | `/dev/pts/*` is Ambient. The agent can write to other terminals, including the one showing `reclaim ui`, and paint a misleading screen. | Confirmed | no rule | 2 |
| F11 | Strings the agent controls (paths, command lines) are shown raw. A multi-line command line produced multi-line entries in `reclaim log`; the same strings reach prompts, the TUI, dialogs and notifications. | Confirmed | daemon ingest, `internal/audit`, `internal/ui`, `internal/notify` | 1 |
| F12 | Every CONTINUE can be raced: a second thread swaps the path or address after the check. The README documents this. It is the structural limit of the current design. | Read | `internal/supervisor/handler.go` (all `s.cont`) | 3 |
| F13 | The agent's root process may connect to any host on port 443 unprompted. Control-plane hosts are matched by IP, so anything sharing a CDN address with them also passes. | Read | `internal/policy/engine.go:307-318`, `internal/config/config.go:205` | 2, 5 |
| F14 | Loopback is always Ambient: tunnels and proxies you opened in another terminal, Jupyter, debug ports, local databases. | Read | `internal/policy/engine.go:297` | 2 |
| F15 | Address families other than inet and unix are Ambient, and `socket()` is not filtered. | Read | `internal/policy/engine.go:216` | 1 |
| F16 | Allow-once matches the target but not the operation. Approving "read X once" also releases a write on X that was paused at the same time. | Read | `internal/daemon/prompt.go:248-258` | 1 |
| F17 | While the daemon is down, cached sliding leases keep extending locally. Signals are not mediated, so the agent can kill the daemon to freeze its leases open and stop `reclaim now` and the audit log. | Read | `internal/supervisor/cache.go:99-132` | 1 |
| F18 | Not mediated at all: signals to processes outside the session, `ptrace`, `process_vm_readv/writev`, `pidfd_getfd`, `keyctl`, `TIOCSTI`, `mknod`, `chown`, `utimensat`, `setxattr`, `fchmod` on a read-only handle. Only Yama `ptrace_scope=1` stands between the agent and the launcher, and `reclaim doctor` reports `ptrace_scope=0` as fine. | Read | filter table; `cmd/reclaim/inspect.go:184-186` | 1 |
| F19 | The launcher and daemon are ordinary dumpable processes, readable and attachable by same-user processes when Yama is off. | Read | no `PR_SET_DUMPABLE` on self | 1 |
| F20 | Two fail-open paths: a call the decoder does not recognise, and a path the resolver cannot resolve, are both let through. | Read | `internal/supervisor/handler.go:47-51,172-176` | 1 |
| F21 | A Remote lease covers every host and renews itself as long as the agent keeps using it. Connections already open survive `reclaim now`. | Read | lease model; README "Limits" | 5 |
| F22 | Approving the session bus, X11, docker, tmux or an editor socket ends containment, but the prompt presents it as an ordinary 5 to 10 minute lease. | Read | `internal/policy/rules.go:175-186` | 5 |
| F23 | The runtime directory fallback `/tmp/reclaim-<uid>` is checked for mode but not ownership, although the comment says it is. | Read | `internal/config/config.go:82-98` | 1 |
| F24 | A project root equal to `$HOME` only prints a warning. | Read | `internal/supervisor/run.go:122-124` | 1 |
| F25 | Nothing bounds prompt floods, the denial-cooldown map, or the number of concurrent notification handlers. | Read | `internal/daemon/prompt.go:262`, `internal/supervisor/run.go:374` | 1 |
| F26 | No version control, no CI, no fuzzing, and the supervisor package (the enforcement point) has no unit tests. | Confirmed | repo | 0, 6 |

## 3. Design principles

Each phase applies one or more of these. When a new case comes up that this plan did not foresee, decide it by these.

1. **Ask the kernel, do not imitate it.** Classify the object the kernel actually resolved (open it with `O_PATH`, read back its real path), never a string Reclaim cleaned up itself. F1 exists because Reclaim re-implemented path resolution.
2. **Broker, do not bless.** Outside the floor, the supervisor does the operation and returns the result. CONTINUE is only for targets inside the floor.
3. **Default deny.** Ambient is an allowlist. Anything unrecognised is gated.
4. **A kernel floor under the policy.** Landlock makes everything outside the floor unreachable by the agent's own syscalls, so a supervisor bug or a lost race lands on a kernel refusal instead of a secret.
5. **An approval grants what the prompt showed.** Same target, same operation, bounded time. Approvals that end containment say so.
6. **Reclaim protects itself.** Its files by subtree and by inode, its processes from signals and inspection, its approval screens from spoofing.
7. **No fix without a test that failed first.**

## 4. Phases

Sizes are rough estimates for focused work: S is up to a day, M is two to five days, L is one to three weeks.

### Phase 0: safety net (S)

- `git init`, commit the current tree, ignore `bin/`. Run `go mod tidy` (all dependencies are currently marked indirect).
- Create `test/adversarial/` on top of the isolated environment in `test/e2e/e2e_test.go` (`newEnv`). One test per finding, named `TestF01_SymlinkDotDot` and so on. Each asserts the operation is denied or prompted and that the audit log records it.
- Keep a list of tests expected to fail. CI fails if a fixed finding regresses or if an expected failure starts passing without the list being updated.
- One `make check` target, also run in CI: build, `go vet`, `staticcheck`, `govulncheck`, `go test -race ./...`, the adversarial suite.

### Phase 1: close the holes that need only small changes (M)

Estimated score after: 6.5.

1. **F1, kernel-true resolution.** Rewrite `procfs.Resolve` to open the target through the caller's own directory handle (`/proc/<tid>/cwd` or `/proc/<tid>/fd/<n>`) using `openat2` with `O_PATH`, then read the real path from `/proc/self/fd/<n>`. For a final component that does not exist yet, resolve the parent this way and append the name. Keep the `/proc/self` to `/proc/<tgid>` rewrite, and handle symlinks that land in `/proc/self`. Detect deleted files with `fstat` (link count zero), not by the " (deleted)" suffix. Remove the `systemPrefixes` shortcut. Add a differential test: random trees of symlinks and `..`, compare against what a child process actually opens. The one-line alternative (stop calling `path.Clean` before the walk) fixes F1 but Phase 3 needs the handle-based resolver anyway.
2. **F2.** Trap `sendmsg` and `sendmmsg`. Read the message header, and when it carries a destination, classify it as `sendto` does.
3. **F15.** Filter `socket` and `socketpair` in the BPF program: allow `AF_UNIX`, `AF_INET`, `AF_INET6`, and `AF_NETLINK` with `NETLINK_ROUTE`; stream and datagram types only; TCP, UDP, ICMP only. Everything else returns `EAFNOSUPPORT`.
4. **F18, process boundary.** Send these to the supervisor and allow them only when the target process is inside the session: `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `pidfd_send_signal`, `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp`, `process_madvise`. Debuggers keep working on session processes. Deny outright in BPF: `keyctl`, `add_key`, `request_key`, `userfaultfd`, `open_by_handle_at`, the mount family, and the `TIOCSTI`, `TIOCLINUX`, `TIOCCONS` ioctls.
5. **F19.** The launcher and the daemon call `prctl(PR_SET_DUMPABLE, 0)` on themselves at startup. `reclaim doctor` marks `ptrace_scope=0` as a failure with an explanation.
6. **F16.** Allow-once must match target and operation.
7. **F17.** While disconnected from the daemon, a cached lease is valid only until the expiry the daemon last confirmed. No local extension.
8. **F20.** Separate "deliberately not inspected" from "could not decode". The second is denied. A resolver error returns the error the kernel would have given (`ENOENT`, `ENOTDIR`, `EBADF`) instead of CONTINUE.
9. **F11.** One sanitiser applied where the daemon receives session data: strip control characters, ANSI sequences, bidirectional and zero-width characters; shorten long strings from the middle so the end of a path stays visible. The JSON audit record keeps the raw value, escaped. Prompts show the executable path the kernel reports (`/proc/<pid>/exe`) beside the command line, and label the command line as the process's own claim.
10. **F23, F24.** Check the runtime directory with `Lstat`: a real directory, owned by the user, mode 0700, or refuse. Refuse a project root that is `/`, `$HOME`, `/tmp`, or an ancestor of the home or config directory unless an explicit override flag is given.
11. **F25.** Expire cooldown entries. Cap concurrent handlers and deny on overflow. Rate-limit prompts per agent; beyond the limit, deny automatically and record it.

### Phase 2: default-deny classification (M, plus a soak period)

Estimated score after: 7.5.

Roll this out observe-first: add a "would gate" audit event, run normal work for a week with the new rules in report-only mode, tune the allowlists, then enforce.

1. **F5, Ambient becomes an allowlist.** List what is free: system runtime trees read-only (`/usr`, `/lib*`, `/bin`, `/sbin`, `/etc`, `/opt`, `/snap`, `/nix`, `/sys`), a curated part of `/proc` and `/run`, a short list of devices (`null`, `zero`, `full`, `random`, `urandom`, `tty`, `ptmx`, the session's own terminals), and the session's own `/proc/<pid>` entries. Any other unmatched path is gated at Home level with the label "Unclassified location".
2. **F3, F14, sockets and loopback.** An unknown unix socket (path or abstract) is gated as System, "Unknown local service". Free: a short list of harmless services (name service cache, resolver, logging) and any socket this session itself bound, which the supervisor records when it sees the `bind`. A loopback connection is free only when a session process holds the listening socket; otherwise it is gated as "Local service outside the session, port N". Only the resolvers named in `/etc/resolv.conf` count as DNS.
3. **F4, protect by subtree and by inode.** For operations that move or remove a directory, the effective Space is the most sensitive rule that could match anything beneath it. An ancestor of a Control path is denied. Separately, record the device and inode of the config, state and binary at launch, and treat any path that reaches them as Control. The daemon pins the config's hash at start and records an audit event if the file changes underneath it.
4. **F7, split agent state.** Data stays free. Code that runs outside the session (`~/.local/bin/claude`, the editor extension directories) is free to read and execute but gated as System, medium friction, to write.
5. **F6, toolchains.** Split `project.toolchains` into caches (free) and installed executables, shims and interpreter trees (free to read and execute, System-gated to write). `nvm install` or `rustup update` then costs one prompt.
6. **F8, project automation.** Add a rule attribute meaning "always ask, never leased". Apply it to writes on `.git/hooks/**`, `.vscode/settings.json`, `.vscode/tasks.json`, `.envrc`, `.devcontainer/**`, `.idea/**`. `.git/config` is written by ordinary git commands, so gate nothing there; instead snapshot it at session start and raise a notification and audit event when a key that runs commands appears (`core.fsmonitor`, `core.sshCommand`, `core.hooksPath`, `core.pager`, `alias.*`, `credential.helper`, `filter.*`).
7. **F9, temp files.** The launcher creates a private directory per agent identity, exports it as `TMPDIR`, and only that is free. The rest of `/tmp` and `/var/tmp` is gated as "Other programs' temporary files". `/dev/shm` handling moves to Phase 3, where the supervisor knows which files the session created.
8. **F10.** Terminals other than the session's own are Device.
9. **Other processes' internals.** For processes outside the session, `/proc/<pid>/mem`, `maps`, `fd/**`, `cwd`, `root`, `map_files/**` join `environ` in Vault. Core dumps under `/var/lib/systemd/coredump` and the user journal are Vault to read.
10. **F13, first half.** Default `control_plane_ports` to empty. The root process loses its blanket pass on 443; the named control-plane hosts remain.

### Phase 3: broker every crossing (L)

Estimated score after: 8. This is the phase that changes the threat-model sentence. It removes F12.

Until Phase 4 exists, every trapped syscall except `execve` is brokered, including those on Project and Ambient targets. Brokering only the gated Spaces would not be sound: an agent could present a Project path for the check and swap in a Vault path for the kernel.

1. **Plumbing.** Add fd injection (`SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`, kernel 5.14 or later) and "return this value" to the `seccomp` package. Route every reply through one function that refuses CONTINUE unless the caller proves the target is in the floor.
2. **Open family.** The supervisor resolves to an `O_PATH` handle (the Phase 1 resolver), classifies that object, decides, then reopens that same handle with the caller's flags and injects it. For creation it opens relative to the resolved parent handle with symlinks disallowed, applying the caller's umask (read from `/proc/<pid>/status`; the supervisor runs with umask 0). Special cases to implement and test: `/dev/tty` (map to the caller's controlling terminal from its `stat`), FIFOs (non-blocking open, then emulate the wait), always add `O_NOCTTY`, `O_TMPFILE`, close-on-exec mapping.
3. **Path changes.** `rename*`, `unlink*`, `rmdir`, `mkdir*`, `symlink*`, `link*`, `chmod`, `fchmodat*`, `truncate`, plus newly trapped `mknod*`, `chown*`, `utimensat`, `setxattr*`: resolve the parent directories to handles, classify, perform the `...at` call on those handles, return the result.
4. **Sockets.** `connect`, `bind`, `sendto` with an address, `sendmsg`/`sendmmsg` with a destination: copy the address once, classify, then make the call on a duplicate of the caller's socket obtained with `pidfd_getfd`. A send with no destination on an already-connected stream socket may CONTINUE, since the destination cannot be changed.
5. **Handle-based changes.** Trap `fchmod`, `fchown`, `fsetxattr` and `futimens`, map the handle to its path, and classify as a write. This closes "open read-only where reads are free, then change the file through the handle".
6. **`/dev/shm`.** Creating a new file is free; opening a file this session did not create is gated. The supervisor now performs the creation, so it knows.
7. **`execve` stays CONTINUE.** It cannot be brokered. A raced exec yields execution of a different file, not its contents, and the new process is still inside the filter. Phase 4 bounds where it can land.
8. **Cost.** Today each open already pays a notification plus an `lstat` per path component. Brokering replaces that with roughly four syscalls. Measure `git status` on a large repository, `go build ./...` and `npm ci` before and after, and hold to the budget agreed in section 7.

### Phase 4: kernel floor (M to L)

Estimated score after: 8.5.

1. **Apply Landlock in the shim** before `execve` (it already sets no-new-privileges, which Landlock needs). Filesystem rules: read and execute on the system runtime trees; read and write on project roots, the private temp directory, caches and agent data; execute-only on `$HOME` so approved executions still work; nothing else. Network rules (Landlock ABI 4 and later): handle TCP connect and bind and allow no ports, so every TCP connection has to come through the broker.
2. **One source of truth.** Compile the floor from the same rule table the classifier uses. A tree goes into the floor only if no more sensitive rule can match inside it; otherwise split it and add its safe children at launch. Whatever cannot be expressed stays broker-only, which is slower but correct.
3. **Fast path returns.** A target inside the floor with an allow decision gets CONTINUE again: native speed, native semantics, and a lost race can only land inside the floor. While the Project lease is closed, the session stays fully brokered.
4. **Hardening levels**, printed by `reclaim doctor` and enforceable with a `--require-level` flag:

   | Level | Kernel | What the kernel enforces |
   |---|---|---|
   | 3 | Landlock ABI 6+ (6.12 and later) | files, TCP, abstract unix sockets, signals |
   | 2 | ABI 4 to 5 (6.7 and later) | files, TCP. The development machine is here: kernel 6.8, ABI 4, measured. |
   | 1 | ABI 1 to 3 (5.13 and later) | files only |
   | 0 | no Landlock | nothing; full brokering only, with a warning |

5. **Race tests.** A harness with threads flipping a path buffer between a harmless file and a secret, and another flipping a symlink, for a million iterations. The secret must never be read. Run it once with the floor disabled to prove brokering holds alone, and once with brokering deliberately weakened to prove the floor holds alone.
6. **Compatibility.** Check agents that sandbox themselves. Stacked Landlock is fine; anything needing user namespaces is already blocked.

### Phase 5: approvals mean what they say (M)

Estimated score after: 9, pending the review in Phase 6.

1. **F21, scoped grants.** A Remote prompt offers "this host and port", "this host", or "all of Remote for N minutes" (high friction). Leases gain a scope. A new target outside the scope prompts. Sliding leases get a hard lifetime cap.
2. **F21, revocation that bites.** When Remote closes or `reclaim now` runs, the supervisor shuts down the session's sockets that have non-local peers. The periodic scan in `internal/supervisor/netscan.go` already finds them.
3. **F22, name the escape hatches.** A rule attribute for targets that end containment: session bus, systemd, container engines, terminal multiplexers, editor sockets, X11. These are once-only and high friction, the prompt says "after this, Reclaim can no longer contain this agent", and the session shows as uncontained in status and audit until it exits.
4. **F13, second half: real hostnames.** A small CONNECT proxy inside the supervisor, exported to the agent as `HTTPS_PROXY`. It resolves names itself, checks that the TLS server name matches the requested host, allows the control plane by name, and turns other hosts into Remote prompts that show a hostname. A direct connection by IP is then plain Remote.
5. **Approval surface.** Do not use the zenity dialog for a session that has been granted the display. Chain the audit log (each record carries the hash of the previous one) and add `reclaim log --verify`. A changed config is not reloaded until accepted from outside a session.

### Phase 6: assurance (ongoing from Phase 1)

- Fuzz with `go test -fuzz`: the syscall decoder, the `/proc` and sockaddr parsers, the glob matcher, the protocol codec, the sanitiser.
- Unit-test the supervisor's decision logic behind fake seccomp and procfs interfaces.
- Rewrite the threat model in README and ARCHITECTURE; add `SECURITY.md` with section 6.
- Red-team pass: a person or a fresh session given only the binary and the documentation, time-boxed. Every finding becomes a test before it is fixed.
- Tagged releases built with `-trimpath`, with published checksums.

## 5. Sequence and what each step buys

| Phase | Size | Needs | Estimated score | What still holds it back |
|---|---|---|---|---|
| 0 | S | nothing | 5 | everything in section 2 |
| 1 | M | 0 | 6.5 | default-allow classification; races |
| 2 | M + soak | 1 | 7.5 | races (F12) |
| 3 | L | 1 (resolver) | 8 | one layer only; approval scope |
| 4 | M to L | 3 | 8.5 | approvals grant more than shown |
| 5 | M | 2, 3 | 9 | needs independent confirmation |
| 6 | ongoing | 0 | holds 9 | residual risks below |

The scores are my judgement, not a measurement. Phases 1 and 2 are independent of the redesign and worth shipping on their own. Phase 3 is the largest and the one that cannot be skipped.

## 6. What remains at 9

These are the reasons it would not be a 10. They belong in `SECURITY.md`.

- You approve a prompt you should not have. The agent can still argue its case in its own output.
- The model API is itself a way out: anything the agent may read, it can send to its provider.
- Slow covert channels, such as DNS lookups through the system resolver.
- Project files you later run yourself (`Makefile`, package scripts, tests). Phase 2 detects the automatic ones; it cannot stop you running code the agent wrote.
- Poisoned entries in shared package caches.
- A raced `execve` runs a different file (execution, not contents). File existence and sizes are visible through `stat`.
- File handles already granted outlive a reclaim. Sockets are cut; files are not.
- Kernel bugs in seccomp or Landlock. Kernels older than 5.14 cannot run the hardened mode.
- Other processes of yours outside the session are trusted. If one is compromised, that is outside Reclaim's reach.

## 7. Decisions needed from the owner

Each has a recommendation. None blocks Phases 0 and 1.

1. **Gate loopback (F14)?** Recommended: yes. Listeners started by the session stay free. A tunnel or database you started elsewhere prompts once per port, medium friction, lower once the target is known.
2. **Remove the root process's free pass on 443 (F13)?** Recommended: yes, with the name-based proxy in Phase 5 to keep prompts readable. Expect more prompts from the agent's own web fetches until hosts are allowlisted.
3. **Prompt on toolchain installs (F6)?** Recommended: yes, as a System-style fixed lease so one install is one prompt.
4. **Scoped Remote grants (F21)?** Recommended: yes, with "this host" as the default answer. This changes the PRD's lease key of agent plus Space.
5. **Minimum kernel for hardened mode?** Recommended: require 5.14, recommend 6.7. Below 5.14, run today's behaviour only behind an explicit legacy flag.
6. **Performance budget for brokered I/O?** Recommended: at most 10% wall-clock on the three benchmarks in Phase 3.

## 8. Check before relying on it

Claims in this plan that have not been tested. Each should be settled with a small experiment at the start of the phase that depends on it.

| # | Claim | Needed by |
|---|---|---|
| V1 | Landlock's TCP connect rule also covers TCP Fast Open (a `sendto`/`sendmsg` with `MSG_FASTOPEN` on an unconnected socket). If not, the broker must own that case. | Phase 4 |
| V2 | A workspace `.vscode/settings.json` can override `claudeCode.claudeProcessWrapper`. If it can, F8 is an escape from supervision, not just persistence. | Phase 2 |
| V3 | The seccomp listener cannot be reopened by the agent through `/proc/<launcher pid>/fd/<n>`. | Phase 1 |
| V4 | `golang.org/x/sys/unix` exposes the fd-injection ioctl and flags at the pinned version. | Phase 3 |
| V5 | Brokered opens cost about the same as today's path walk. | Phase 3 |
| V6 | `pidfd_getfd` from the launcher passes Yama at `ptrace_scope=1` for every session process, including reparented orphans. | Phase 3 |

## Appendix: reproducing the confirmed findings

Run these only inside an isolated environment like `newEnv` in `test/e2e/e2e_test.go`: a throwaway `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME` and `XDG_RUNTIME_DIR`, with `dialog = "never"` and `desktop_notify = false` in the config, and dummy files standing in for secrets. The runtime directory path must be short, because unix socket paths are limited to 108 bytes.

```sh
# F1: Vault file read with no prompt (the direct path is paused and denied)
reclaim run --agent claude -- sh -c 'ln -s "$HOME/.ssh" p && cat p/../.aws/credentials'

# F2: UDP with sendmsg goes out; the same send with sendto is denied
reclaim run --agent claude -- python3 -c \
  "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendmsg([b'x'],[],0,('192.0.2.1',9))"

# F3: connect to a unix socket that a process outside the session is listening on
reclaim run --agent claude -- python3 -c \
  "import socket;s=socket.socket(socket.AF_UNIX);s.connect('$XDG_RUNTIME_DIR/fake-service.sock')"

# F4: approve the single Home prompt ("modify ~/.config") from another shell, then check the config
reclaim run --agent claude -- sh -c \
  'mv ~/.config ~/c2 && echo "# injected" >> ~/c2/reclaim/config.toml && mv ~/c2 ~/.config'

# F5 to F10: classification only, no session needed
reclaim explain --agent claude /data/warehouse/x.parquet
reclaim explain --agent claude "/run/user/$(id -u)/containers/auth.json"
reclaim explain --agent claude ~/.nvm/versions/node/v20/bin/node
reclaim explain --agent claude ~/.vscode/extensions/anthropic.claude-code-2.0/extension.js
reclaim explain --agent claude /tmp/krb5cc_1000
reclaim explain --agent claude /dev/pts/7
```

`192.0.2.1` is a documentation-only address (RFC 5737) and is not routed.
