#!/usr/bin/env bash
# Free play: a Reclaim-supervised bash shell in the demo sandbox, next to the
# console. You are the agent; answer your own prompts in the console.
# Run demo/demo.sh first if you want the guided tour; this works on its own.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root="${RECLAIM_DEMO_ROOT:-/tmp/reclaim-demo}"
[ -f "$root/.reclaim-demo" ] || "$here/setup.sh"

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux not found. In another terminal run:  source $here/env.sh && reclaim ui"
  exec "$here/agent-shell.sh"
fi
session=reclaim-play
export RECLAIM_DEMO_TMUX_SESSION=$session
tmux kill-session -t "$session" 2>/dev/null || true
cols=$(tput cols 2>/dev/null || echo 200)
tmux new-session -d -s "$session" -n play -x "$cols" -y "$(tput lines 2>/dev/null || echo 50)" \
  -e RECLAIM_DEMO_TMUX_SESSION="$session" "$here/ui-pane.sh"
ui=$(tmux display-message -p -t "$session:play" '#{pane_id}')
split=-h; [ "$cols" -lt 150 ] && split=-v
tmux split-window "$split" -b -l 55% -t "$ui" -e RECLAIM_DEMO_TMUX_SESSION="$session" "$here/agent-shell.sh"
tmux set-option -t "$session" mouse on >/dev/null
tmux set-option -t "$session" status-left "#[bold] Reclaim free play " >/dev/null
tmux set-option -t "$session" status-right " you (agent) | console " >/dev/null
if [ -n "${RECLAIM_DEMO_DETACH:-}" ]; then echo "started detached: tmux attach -t $session"; elif [ -n "${TMUX:-}" ]; then tmux switch-client -t "$session"; else tmux attach -t "$session"; fi
