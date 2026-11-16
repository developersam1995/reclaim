#!/usr/bin/env bash
# (Re)creates the demo sandbox: a fake home with fake secrets and personal
# files, a fake project with a git repo, a demo config with short leases, and
# a fresh demo daemon. Safe to run again: it only ever wipes a directory it
# created itself (marked with .reclaim-demo).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

root="$RECLAIM_DEMO_ROOT"
if [ -e "$root" ] && [ ! -f "$root/.reclaim-demo" ]; then
  echo "setup: $root exists but was not created by this demo; refusing to wipe it" >&2
  echo "       remove it yourself or set RECLAIM_DEMO_ROOT to another path" >&2
  exit 1
fi

# A previous demo daemon may still be running on the old sandbox socket.
reclaim daemon stop >/dev/null 2>&1 || true
sleep 0.3

rm -rf "$root"
mkdir -p "$HOME"/{.ssh,.aws,Documents,proj} "$XDG_CONFIG_HOME/reclaim" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
touch "$root/.reclaim-demo"
touch "$HOME/.sudo_as_admin_successful"   # keeps Ubuntu's /etc/bash.bashrc from printing its sudo hint in the fake home

# --- fake secrets (Vault Space) ---------------------------------------------
cat > "$HOME/.ssh/id_ed25519" <<'KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
VGhpcyBpcyBOT1QgYSByZWFsIGtleS4gSXQgaXMgYSBwcm9wIGZvciB0aGUgUmVjbGFpbSBkZW1v
Lg== (fake key for the Reclaim demo)
-----END OPENSSH PRIVATE KEY-----
KEY
chmod 600 "$HOME/.ssh/id_ed25519"
cat > "$HOME/.aws/credentials" <<'AWS'
[default]
aws_access_key_id = AKIADEMODEMODEMODEMO
aws_secret_access_key = this-is-a-fake-secret-for-the-reclaim-demo
AWS
chmod 600 "$HOME/.aws/credentials"

# --- personal files (Home Space) --------------------------------------------
cat > "$HOME/Documents/notes.txt" <<'NOTES'
Personal notes (not part of any project)
- dentist Tuesday 4pm
- call the landlord about the deposit
NOTES

# --- shell startup (System Space: reads free, writes gated) -----------------
cat > "$HOME/.bashrc" <<'RC'
# ~/.bashrc — runs at the start of every interactive shell
export EDITOR=vim
alias ll='ls -la'
RC
cat > "$HOME/.gitconfig" <<'GC'
[user]
	name = Demo Agent
	email = agent@example.com
[init]
	defaultBranch = main
GC

# --- the project the agent is allowed to work in (Project Space) ------------
cat > "$HOME/proj/README.md" <<'MD'
# shop-api

A tiny service the demo agent is working on.
MD
cat > "$HOME/proj/main.py" <<'PY'
def price(items):
    return sum(i["price"] for i in items)
PY
cat > "$HOME/proj/run_tests.sh" <<'SH'
#!/usr/bin/env bash
echo "test_price ... ok"
echo "test_empty ... ok"
echo "2 passed"
SH
chmod +x "$HOME/proj/run_tests.sh"
( cd "$HOME/proj" && git init -q && git add -A && git commit -q -m "initial" )

# --- demo config: shorter leases so you can watch them expire ---------------
cat > "$XDG_CONFIG_HOME/reclaim/config.toml" <<'TOML'
# Reclaim DEMO config. The real defaults are: vault 2m, home 10m, remote 15m,
# system 5m, device 10m, project 48h, prompt timeout 60s, deny cooldown 30s.
# The demo shortens leases so you can watch Spaces close during the tour,
# and lengthens the prompt timeout so you have time to read.

[prompt]
timeout = "120s"         # an unanswered prompt fails the operation after this
desktop_notify = true    # a desktop toast for every new prompt
dialog = "auto"          # a zenity dialog when no 'reclaim ui' console is open
deny_cooldown = "15s"    # after a denial, the same request is auto-denied for 15s

[spaces.home]
ttl = "90s"              # sliding: closes after 90s without use

[spaces.vault]
ttl = "60s"              # fixed: closes 60s after approval, however often it is used

[spaces.remote]
ttl = "90s"

[spaces.system]
ttl = "60s"
TOML
if [ -n "${RECLAIM_DEMO_QUIET:-}" ]; then
  # headless / unattended: no desktop toasts, no dialogs
  sed -i 's/^desktop_notify = true/desktop_notify = false/; s/^dialog = "auto"/dialog = "never"/' "$XDG_CONFIG_HOME/reclaim/config.toml"
fi

# --- rc file for the free-play shell (lives in the sandbox, so reading it is free)
cat > "$root/agent-rc.sh" <<'RC'
PS1='\[\e[1;35m\]agent\[\e[0m\] \W $ '
unset HISTFILE   # or bash would write ~/.bash_history at exit: a Vault Space prompt (shell history) after you typed 'exit'
cat <<'HINT'
You are now the agent: a bash shell supervised by Reclaim, inside the fake
home /tmp/reclaim-demo/home. Project Space is already open for ~/proj.
Things to try (answer the prompts in the Reclaim console next to you):

  cat README.md; ./run_tests.sh          project work: never prompts
  cat ~/Documents/notes.txt              Home Space: medium friction
  cat ~/.ssh/id_ed25519                  Vault Space: type the word shown
  cat ~/.aws/credentials                 Vault again: free while the lease is open
  echo 'alias x=1' >> ~/.bashrc          System Space: writes are gated, reads are not
  curl -sS --max-time 5 http://1.1.1.1/  Remote Space: a never-seen target
  reclaim status                         blocked: agents cannot touch Reclaim itself
  exit                                   end the session
HINT
RC

# --- start the demo daemon detached, logging into the sandbox ---------------
log="$XDG_STATE_HOME/reclaim/daemon.log"
mkdir -p "$(dirname "$log")"
setsid -f reclaim daemon >>"$log" 2>&1
for _ in $(seq 1 50); do
  [ -S "$XDG_RUNTIME_DIR/reclaim/reclaimd.sock" ] && break
  sleep 0.1
done
[ -S "$XDG_RUNTIME_DIR/reclaim/reclaimd.sock" ] || { echo "setup: demo daemon did not start; see $log" >&2; exit 1; }
echo "sandbox ready at $root (daemon log: $log)"
