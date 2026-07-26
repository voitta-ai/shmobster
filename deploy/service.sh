#!/usr/bin/env bash
# Manage the Shmobster launchd service (macOS).
# Usage: deploy/service.sh {install|update|restart|status|logs|uninstall}
#
# First time:
#   cp deploy/ai.shmobster.plist.sample deploy/ai.shmobster.plist
#   # edit deploy/ai.shmobster.plist -- replace /Users/CHANGE_ME/path/to/shmobster
#   deploy/service.sh install
#
# install  -- copy your (gitignored) deploy/ai.shmobster.plist into
#             ~/Library/LaunchAgents and start it.
# update   -- re-copy the plist (after editing it) and restart.
# restart  -- restart the service (use after `git pull` to load new code).
# status   -- pid / state.
# logs     -- tail the error log.
# uninstall-- stop and remove.
set -euo pipefail

LABEL="ai.shmobster.agent"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO/deploy/ai.shmobster.plist"
DST="$HOME/Library/LaunchAgents/$LABEL.plist"
DOMAIN="gui/$(id -u)"

need_src() {
  [ -f "$SRC" ] || {
    echo "missing $SRC"
    echo "  cp deploy/ai.shmobster.plist.sample deploy/ai.shmobster.plist"
    echo "  then edit it (replace /Users/CHANGE_ME/path/to/shmobster)"
    exit 1
  }
}

case "${1:-}" in
  install)
    need_src
    mkdir -p "$REPO/logs" "$HOME/Library/LaunchAgents"
    cp "$SRC" "$DST"
    launchctl bootstrap "$DOMAIN" "$DST"
    echo "installed + started $LABEL"
    ;;
  update)
    # Full reload, not kickstart: kickstart -k restarts the running process but
    # reuses the service definition already loaded in the domain, so a freshly
    # copied plist (new EnvironmentVariables / KeepAlive / paths) is NOT re-read.
    # bootout + bootstrap actually reloads the file. (#56)
    need_src
    cp "$SRC" "$DST"
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    launchctl bootstrap "$DOMAIN" "$DST"
    echo "re-copied plist + reloaded $LABEL"
    ;;
  restart)
    launchctl kickstart -k "$DOMAIN/$LABEL"
    echo "restarted $LABEL"
    ;;
  status)
    launchctl print "$DOMAIN/$LABEL" 2>/dev/null | grep -E "state =|pid =" || echo "$LABEL not loaded"
    ;;
  logs)
    tail -n 50 -f "$REPO/logs/shmobster.err.log"
    ;;
  uninstall)
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    rm -f "$DST"
    echo "uninstalled $LABEL"
    ;;
  *)
    echo "usage: $0 {install|update|restart|status|logs|uninstall}"
    exit 1
    ;;
esac
