#!/usr/bin/env bash
# Reclaim guided tour: builds the binary if needed, creates a throwaway
# sandbox (fake home, fake secrets, own daemon), and opens a tmux window with
# the Reclaim console on one side and the tour on the other.
#
#   demo/demo.sh            interactive tour (10–15 minutes)
#   demo/demo.sh --auto     unattended run: the tour answers its own prompts
#   demo/shell.sh           free play: you are the agent
#
# Nothing touches your real ~/.config/reclaim, state, or running daemon.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
proj=$(cd "$here/.." && pwd)
bin="$proj/bin/reclaim"

# 1. a binary that matches the sources
if command -v go >/dev/null 2>&1; then
  if [ ! -x "$bin" ] || [ -n "$(find "$proj/cmd" "$proj/internal" -name '*.go' -newer "$bin" -print -quit)" ]; then
    echo "building bin/reclaim ..."
    (cd "$proj" && go build -o bin/reclaim ./cmd/reclaim)
  fi
elif [ ! -x "$bin" ]; then
  echo "demo: bin/reclaim is missing and go is not installed to build it" >&2
  exit 1
fi

# 2. can this machine run a session at all?
doctor=$("$bin" doctor 2>&1 || true)   # doctor exits non-zero on any ✘ (e.g. snap tools), which is fine here
if ! grep -q 'seccomp user notification *available' <<<"$doctor"; then
  printf '%s\n' "$doctor"
  echo "demo: seccomp user notification is not available on this kernel" >&2
  exit 1
fi
for tool in python3 fmt; do
  command -v "$tool" >/dev/null 2>&1 || { echo "demo: needs $tool" >&2; exit 1; }
done

# 3. a fresh sandbox and daemon
"$here/setup.sh"

# 4. layout
if ! command -v tmux >/dev/null 2>&1; then
  cat <<MSG
tmux is not installed, so the console and the tour cannot share a window.
Open a second terminal and run:

    source $here/env.sh && reclaim ui

then press Enter here to start the tour.
MSG
  IFS= read -r _
  exec "$here/tour.sh" "$@"
fi

session=reclaim-demo
export RECLAIM_DEMO_TMUX_SESSION=$session
tmux kill-session -t "$session" 2>/dev/null || true
cols=$(tput cols 2>/dev/null || echo 200)
lines=$(tput lines 2>/dev/null || echo 50)
tmux new-session -d -s "$session" -n reclaim -x "$cols" -y "$lines" \
  -e RECLAIM_DEMO_TMUX_SESSION="$session" "$here/ui-pane.sh"
ui=$(tmux display-message -p -t "$session:reclaim" '#{pane_id}')
split=-h; [ "$cols" -lt 150 ] && split=-v
tmux split-window "$split" -b -l 55% -t "$ui" -e RECLAIM_DEMO_TMUX_SESSION="$session" \
  "$here/tour.sh $ui $*"
tmux set-option -t "$session" mouse on >/dev/null
tmux set-option -t "$session" status-left "#[bold] Reclaim demo " >/dev/null
tmux set-option -t "$session" status-right " tour | console  (q in the tour quits) " >/dev/null

if [ -n "${RECLAIM_DEMO_DETACH:-}" ]; then
  echo "started detached: tmux attach -t $session"
elif [ -n "${TMUX:-}" ]; then
  tmux switch-client -t "$session"
else
  tmux attach -t "$session"
fi
