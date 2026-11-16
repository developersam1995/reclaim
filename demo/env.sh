#!/usr/bin/env bash
# Reclaim demo sandbox environment.
#
# Everything the demo touches lives under /tmp/reclaim-demo: a fake home with
# fake secrets, a fake project, a demo config, and its own daemon. Your real
# ~/.config/reclaim, your real state and the daemon serving your real agents
# are never touched.
#
#   source demo/env.sh        # then: reclaim ui, reclaim status, reclaim log ...
#
# Override the location with RECLAIM_DEMO_ROOT=/somewhere/short (unix socket
# paths must stay under ~100 characters).

RECLAIM_DEMO_ROOT="${RECLAIM_DEMO_ROOT:-/tmp/reclaim-demo}"
RECLAIM_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECLAIM_DEMO_PROJECT_DIR="$(cd "$RECLAIM_DEMO_DIR/.." && pwd)"
export RECLAIM_DEMO_ROOT RECLAIM_DEMO_DIR RECLAIM_DEMO_PROJECT_DIR

# Remember the real desktop session once, so notifications and dialogs still
# reach your screen after XDG_RUNTIME_DIR moves into the sandbox.
if [ -z "${RECLAIM_DEMO_REAL_HOME:-}" ]; then
  export RECLAIM_DEMO_REAL_HOME="$HOME"
  export RECLAIM_DEMO_REAL_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
fi
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -S "$RECLAIM_DEMO_REAL_RUNTIME_DIR/bus" ]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$RECLAIM_DEMO_REAL_RUNTIME_DIR/bus"
fi
case "${WAYLAND_DISPLAY:-}" in
  "" | /*) ;;
  *) export WAYLAND_DISPLAY="$RECLAIM_DEMO_REAL_RUNTIME_DIR/$WAYLAND_DISPLAY" ;;
esac

export HOME="$RECLAIM_DEMO_ROOT/home"
export XDG_CONFIG_HOME="$RECLAIM_DEMO_ROOT/cfg"
export XDG_STATE_HOME="$RECLAIM_DEMO_ROOT/state"
export XDG_RUNTIME_DIR="$RECLAIM_DEMO_ROOT/rt"
export TMPDIR=/tmp
case ":$PATH:" in
  *":$RECLAIM_DEMO_PROJECT_DIR/bin:"*) ;;
  *) export PATH="$RECLAIM_DEMO_PROJECT_DIR/bin:$PATH" ;;
esac
export PS1='(reclaim-demo) \W $ '
