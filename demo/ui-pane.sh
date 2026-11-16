#!/usr/bin/env bash
# The console pane of the demo: runs reclaim ui and offers to reopen it when
# it is closed (q), so the tour can show what happens without a console.
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
while :; do
  reclaim ui
  printf '\n  Console closed. With no console open, prompts go to desktop dialogs.\n  Press Enter to reopen the console.\n'
  IFS= read -r _ || exit 0
done
