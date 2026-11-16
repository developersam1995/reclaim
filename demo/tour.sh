#!/usr/bin/env bash
# The guided tour. Start it with demo/demo.sh (which builds the tmux layout);
# this script runs OUTSIDE any agent session so it can call reclaim status,
# log and now, launches a scripted "agent" for each scene, and tells you what
# to look at and which key to press in the console.
#
#   tour.sh [UI_PANE] [--auto]
#     UI_PANE   tmux pane id of the console (demo.sh passes it)
#     --auto    unattended: no pauses, prompts answered by the tour itself
set -u
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

UI_PANE="" AUTO=0
for a in "$@"; do case "$a" in --auto) AUTO=1 ;; %*) UI_PANE=$a ;; esac; done
[ -n "${TMUX:-}" ] || UI_PANE=""
cd "$HOME/proj" || { echo "tour: sandbox missing; run demo/setup.sh" >&2; exit 1; }
SCENES="$RECLAIM_DEMO_ROOT/scenes"
mkdir -p "$SCENES"

# ---- looks -----------------------------------------------------------------
if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  B=$(tput bold) D=$(tput dim) N=$(tput sgr0)
  Y=$(tput setaf 3) G=$(tput setaf 2) R=$(tput setaf 1) C=$(tput setaf 6) M=$(tput setaf 5)
else
  B= D= N= Y= G= R= C= M=
fi
W=$(tput cols 2>/dev/null || echo 80); [ "$W" -gt 80 ] && W=80; W=$((W - 2))

say()   { printf '%s\n' "$*" | fmt -w "$W"; }
line()  { printf '%s\n' "$*"; }
blank() { printf '\n'; }
rule()  { printf '%s' "$D"; printf '%*s' "$W" '' | sed 's/ /─/g'; printf '%s\n' "$N"; }
title() { blank; line "${B}${C}$1${N}"; rule; }
hint()  { line "${Y}${B}▶ $*${N}"; }
cmd()   { line "${D}\$ ${N}${B}$*${N}"; "$@" 2>&1 | sed 's/^/  /'; }

AGENT_PID=
finish() {
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null
  reclaim daemon stop >/dev/null 2>&1
  if [ -n "$UI_PANE" ]; then
    tmux kill-session -t "${RECLAIM_DEMO_TMUX_SESSION:-reclaim-demo}" 2>/dev/null
  fi
  exit 0
}
trap finish INT TERM

# step: Enter continues, s skips the rest of the scene, q quits.
step() {
  if [ "$AUTO" = 1 ]; then sleep 0.8; return 0; fi
  printf '%s' "${D}[Enter] continue · [s] skip scene · [q] quit${N} "
  local k=""
  IFS= read -rsn1 k
  printf '\r%*s\r' "$((W + 2))" ''
  case "$k" in q | Q) finish ;; s | S) return 1 ;; esac
  return 0
}

# agent NAME [reclaim run flags...] -- <<'EOF' script EOF
# Writes the scene script into the sandbox and runs it under reclaim run in
# the background, prefixing its output. The agent's lines start with "→".
agent() {
  local name=$1; shift
  local flags=()
  while [ "$1" != "--" ]; do flags+=("$1"); shift; done; shift
  local f="$SCENES/$name.sh"
  {
    echo '#!/usr/bin/env bash'
    echo 'say() { printf "→ %s\n" "$*"; sleep 0.3; }; note() { printf "   %s\n" "$*"; }; sleep 0.3'
    cat
  } >"$f"
  chmod +x "$f"
  (reclaim run --agent agent --project "$HOME/proj" "${flags[@]}" -- bash --norc "$f" 2>&1 |
    sed -u "s/^/${M}  agent │${N} /") &
  AGENT_PID=$!
}
wait_agent() { wait "$AGENT_PID" 2>/dev/null; AGENT_PID=; blank; }

# wait_prompt: polls the daemon until a prompt is pending (or 10s pass) and
# fills P_ID, P_WORD, P_FRICTION, P_SPACE, P_ARM, P_WHY.
P_ID= P_WORD= P_FRICTION= P_SPACE= P_ARM= P_WHY=
first_prompt() {
  reclaim status --json 2>/dev/null | python3 -I -c '
import json, sys
try:
    st = json.load(sys.stdin)
except Exception:
    sys.exit(0)
ps = st.get("prompts") or []
if ps:
    p = ps[0]
    print("\x1f".join(str(p.get(k) or "") for k in ("id", "challenge", "friction", "space", "arm_delay", "why")))
'
}
wait_prompt() {
  local i out
  for i in $(seq 1 40); do
    out=$(first_prompt)
    if [ -n "$out" ]; then
      IFS=$'\x1f' read -r P_ID P_WORD P_FRICTION P_SPACE P_ARM P_WHY <<<"$out"
      return 0
    fi
    sleep 0.25
  done
  return 1
}
space_title() {
  case "$1" in
    project) echo "Project Space" ;; remote) echo "Remote Space" ;; vault) echo "Vault Space" ;;
    home) echo "Home Space" ;; system) echo "System Space" ;; device) echo "Device Space" ;; *) echo "$1" ;;
  esac
}

# ask SUGGESTION TEXT — waits for the prompt, prints what to do, and in
# --auto mode answers it after the arming delay.
ask() {
  local suggest=$1 why=$2
  if ! wait_prompt; then
    line "${D}  (no prompt appeared: that Space is still open from earlier — which is exactly what a lease is for)${N}"
    return 1
  fi
  blank
  hint "The agent is paused. In the console: prompt [$P_ID] → $(space_title "$P_SPACE"), $P_FRICTION friction"
  local wordflag=""
  [ -n "$P_WORD" ] && wordflag=" --word $P_WORD"
  case "$P_FRICTION" in
    low)    line "  ${B}a${N} allow · ${B}o${N} once · ${B}d${N} deny — one key, no delay" ;;
    medium) line "  wait $P_ARM (reading time), then ${B}a${N} twice to allow · ${B}o${N} allow once · ${B}d${N} deny" ;;
    high)   line "  wait $P_ARM, then ${B}a${N} (or ${B}o${N} for once) and type ${R}${B}${P_WORD^^}${N} + Enter · ${B}d${N} deny" ;;
  esac
  line "  ${D}from any shell:  reclaim approve $P_ID$wordflag   |   reclaim deny $P_ID${N}"
  line "  ${G}suggested: $suggest${N} — $why"
  if [ "$AUTO" = 1 ]; then
    sleep 3
    case "$suggest" in
      deny) reclaim deny "$P_ID" ;;
      once) reclaim approve "$P_ID" --once ${P_WORD:+--word "$P_WORD"} ;;
      *)    reclaim approve "$P_ID" ${P_WORD:+--word "$P_WORD"} ;;
    esac 2>&1 | sed 's/^/  auto: /'
  fi
  return 0
}

# ============================================================================
title "Reclaim — guided tour"
say "You are the human. The other pane is the Reclaim console (reclaim ui): open Spaces with countdowns, pending prompts, and the audit trail. In this pane a scripted agent will try things, and the tour tells you what to watch and which key to press."
blank
say "Everything happens in a throwaway home at $HOME with fake keys and fake notes. Your real files, config and daemon are untouched."
blank
line "  ${B}Project${N}  ~/proj                     the agent's job: a tiny Python service"
line "  ${B}Home${N}     ~/Documents/notes.txt      personal, not the agent's business"
line "  ${B}Vault${N}    ~/.ssh/id_ed25519, ~/.aws/credentials      (fake secrets)"
line "  ${B}System${N}   ~/.bashrc                  what runs at every login"
line "  ${B}Remote${N}   anything on the network that is not loopback or DNS"
blank
say "Leases are shortened for the tour (Home 90s, Vault 60s, Remote 90s; the defaults are 10m, 2m, 15m) so you can watch Spaces close. Prompts wait 2 minutes for your answer."
step

# ---------------------------------------------------------------------------
scene1() {
  title "1 · Project work never prompts"
  say "At launch Reclaim opens Project Space for the agent's project. Reading, writing, running and committing inside it is free. Watch the console: apart from GRANTED Project in Recent, nothing should happen."
  step || return
  agent s1 -- <<'EOF'
say "reading README.md";      cat README.md
say "running the tests";      ./run_tests.sh
say "adding a function";      printf '\ndef total(items):\n    return price(items)\n' >> main.py
say "committing";             git add -A && git commit -qm "add total()" && git log --oneline | head -1
say "listing ~/.ssh";         ls ~/.ssh
note "(a listing is free; reading the key would not be)"
EOF
  wait_agent
  say "The first two lines came from Reclaim itself, at launch (later scenes use --quiet). The agent saw that a key exists but read nothing outside the project."
  cmd reclaim status
  step
}

scene2() {
  title "2 · Home Space: medium friction"
  say "Now the agent reaches for a personal file outside the project. Reclaim pauses the read — it does not fail it — and asks you. Medium friction: a short reading delay, then a deliberate key."
  step || return
  agent s2 --quiet -- <<'EOF'
say "reading ~/Documents/notes.txt"
cat ~/Documents/notes.txt || exit 0
say "reading it again"
cat ~/Documents/notes.txt >/dev/null && note "no prompt this time: Home Space is open"
EOF
  ask allow "the agent resumes where it stopped, and a Home lease appears with a 90s countdown"
  wait_agent
  say "The second read did not prompt: Home is open. Its lease is sliding — every use pushes the deadline out 90s; leave it alone and it closes by itself."
  cmd reclaim status
  step
}

scene3() {
  title "3 · Vault Space: say no"
  say "The agent wants your SSH private key. Vault is high friction: a longer reading delay and a word to type — a different random word every time, so approving can never become muscle memory. This time, deny it."
  step || return
  agent s3 --quiet -- <<'EOF'
say "reading ~/.ssh/id_ed25519"
cat ~/.ssh/id_ed25519 || note "denied — fine, I can work without it"
say "trying once more"
cat ~/.ssh/id_ed25519 || note "denied again, instantly"
EOF
  ask deny "the read fails with 'Permission denied' and the agent carries on"
  wait_agent
  say "A denial is not a crash: the agent gets EACCES and keeps running. It also sticks: for 15s (30s by default) the same request is auto-denied without bothering you — AUTO-DENIED in the log."
  cmd reclaim log -n 4
  step
}

scene4() {
  title "4 · Vault Space: say yes, deliberately"
  say "Different secret, same Space. This time approve it: wait out the reading delay, press a, type the word the prompt shows, Enter. (o would allow this one read only, with no lease.)"
  step || return
  agent s4 --quiet -- <<'EOF'
say "reading ~/.aws/credentials"
cat ~/.aws/credentials || exit 0
say "and the SSH key, while Vault is open"
head -1 ~/.ssh/id_ed25519
EOF
  ask allow "Vault opens for 60s"
  wait_agent
  say "The key you denied a minute ago is readable now: a lease is per Space, not per file. Vault leases are fixed: 60s after approval the Space closes however busy the agent is — polling cannot keep it open. Watch the countdown."
  cmd reclaim status
  step
}

scene5() {
  title "5 · Remote Space: a target never seen before"
  say "The agent makes a network connection. Loopback and DNS are free; anything else is Remote. A host this agent has never been allowed to reach is 'unexpected': friction goes to high and the prompt says so. (The agent's own model API on port 443 is exempt, or every agent would hold Remote open forever.)"
  step || return
  agent s5 --quiet -- <<'EOF'
say "fetching http://1.1.1.1/"
curl -sS -o /dev/null --max-time 5 -w "   HTTP %{http_code}\n" http://1.1.1.1/ || exit 0
say "fetching it again"
curl -sS -o /dev/null --max-time 5 -w "   HTTP %{http_code} — no prompt, Remote is open\n" http://1.1.1.1/
EOF
  ask allow "the prompt shows ip:port, the service, and the exact command that connected"
  wait_agent
  say "Once a target is known, later prompts for it drop to medium. Remote also stays open while a long-lived connection (an ssh tunnel, a psql session) is alive, even with no new syscalls."
  step
}

scene6() {
  title "6 · System Space: reads are free, changes are not"
  say "Shell startup files, autostart entries, installed software, /etc: an agent may read them freely, but a change there outlives the session. Writes are gated at high friction. The agent reads ~/.bashrc, then tries to append an alias to it."
  step || return
  agent s6 --quiet -- <<'EOF'
say "reading ~/.bashrc"
head -2 ~/.bashrc
say "appending an alias to ~/.bashrc"
echo "alias ll='ls -la'" | tee -a ~/.bashrc >/dev/null || note "denied — I'll leave your shell alone"
EOF
  ask deny "nothing is written; the agent keeps going"
  wait_agent
  cmd reclaim log -n 3
  step
}

scene7() {
  title "7 · Leases close by themselves — or when you say so"
  say "Look at Open Spaces and the countdowns. Vault closes 60s after you approved it (it may be gone already); Home closes 90s after the agent last used it. That is the garbage collection — access decays, what the agent learned stays."
  cmd reclaim status
  step || return
  say "You can also take everything back right now:"
  cmd reclaim now
  say "…and the next request explains why it is asking again. Read the Why line in the prompt. If you approved three things in the last minute, the friction is also one notch higher than usual — approvals should never become a reflex."
  agent s7 --quiet -- <<'EOF'
say "reading ~/Documents/notes.txt again"
cat ~/Documents/notes.txt >/dev/null && note "ok"
EOF
  ask allow "note the Why line"
  wait_agent
  say "Two more controls: hold a Space open while you debug, and tune a lease length."
  cmd reclaim hold home 1h
  cmd reclaim ttl vault 5m
  cmd reclaim status
  cmd reclaim ttl vault default
  step
}

scene8() {
  title "8 · No console open? The prompt finds you anyway"
  if [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] || ! command -v zenity >/dev/null 2>&1; then
    say "(skipped: this needs a graphical session and zenity)"
    return
  fi
  say "Inside an editor there is no console: VS Code runs Claude Code through Reclaim's wrapper mode. Then a prompt is a desktop notification plus a dialog. Let's close the console for a moment and let the agent try the SSH key again."
  [ -z "$UI_PANE" ] && say "(Not in tmux: press q in your 'reclaim ui' terminal now, then Enter here.)"
  step || return
  [ -n "$UI_PANE" ] && tmux send-keys -t "$UI_PANE" q
  sleep 0.5
  agent s8 --quiet -- <<'EOF'
say "reading ~/.ssh/id_ed25519"
cat ~/.ssh/id_ed25519 >/dev/null && note "got it" || note "denied"
EOF
  if wait_prompt; then
    hint "A dialog should be on your screen (and a notification). Answer it there — it wants the word ${P_WORD^^}."
    [ "$AUTO" = 1 ] && { sleep 3; reclaim deny "$P_ID" 2>&1 | sed 's/^/  auto: /'; }
  fi
  wait_agent
  [ -n "$UI_PANE" ] && tmux send-keys -t "$UI_PANE" Enter
  say "The console is back. Reclaim prefers a console when one is open and falls back to dialogs when none is."
  step
}

scene9() {
  title "9 · Observe mode, and asking before it happens"
  say "Not sure what an agent will touch? Run it with --observe: nothing is blocked, nothing prompts, and every would-be prompt is logged. A good first run for an unfamiliar tool."
  step || return
  agent s9 --quiet --observe -- <<'EOF'
say "reading ~/.ssh/id_ed25519   (observe mode)"
head -1 ~/.ssh/id_ed25519
say "appending to ~/.bashrc      (observe mode)"
echo "# added by the agent" | tee -a ~/.bashrc >/dev/null && note "written"
EOF
  wait_agent
  cmd reclaim log -n 3
  say "And before running anything, ask which Space a path or an address lands in, and under which rule:"
  cmd reclaim explain '~/.aws/credentials'
  cmd reclaim explain 10.0.0.5:5432
  cmd reclaim policy
  step
}

scene1; scene2; scene3; scene4; scene5; scene6; scene7; scene8; scene9

title "That's the tour"
say "To supervise a real agent, from a normal terminal (not this sandbox):"
line "  ${B}reclaim run -- $(command -v claude 2>/dev/null || echo claude)${N}"
line "  ${B}reclaim ui${N}        in another terminal, or answer notifications and dialogs"
blank
say "VS Code: set claudeCode.claudeProcessWrapper to $RECLAIM_DEMO_PROJECT_DIR/bin/reclaim and the extension's Claude Code runs supervised, with prompts as notifications and dialogs."
blank
say "To be the agent yourself in this sandbox: demo/shell.sh gives you a supervised shell next to the console."
blank
say "Worth judging now that you have seen it: did each prompt tell you enough to decide (who, what, which Space, why now)? Did the friction feel proportional, or in the way? Were the countdowns and Why lines useful or noise? Did anything in the audit log surprise you?"
blank
line "${D}Sandbox: $RECLAIM_DEMO_ROOT — rm -rf it when done. Audit: source demo/env.sh && reclaim log${N}"
blank
if [ "$AUTO" != 1 ]; then printf '%s' "${D}[Enter] finish${N} "; IFS= read -rsn1 _; fi
finish
