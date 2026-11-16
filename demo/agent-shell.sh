#!/usr/bin/env bash
# Free play: you are the agent. A bash shell supervised by Reclaim inside the
# sandbox project; answer the prompts in the console next to it.
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "$HOME/proj" || exit 1
reclaim run --agent agent --project "$HOME/proj" --quiet -- bash --rcfile "$RECLAIM_DEMO_ROOT/agent-rc.sh"
echo "session ended"
reclaim daemon stop >/dev/null 2>&1
[ -n "${TMUX:-}" ] && tmux kill-session -t "${RECLAIM_DEMO_TMUX_SESSION:-reclaim-play}" 2>/dev/null
