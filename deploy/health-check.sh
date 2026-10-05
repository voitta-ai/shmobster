#!/bin/bash
# Out-of-process liveness check (#66 follow-up). Restarts the shmobster service
# when its heartbeat file goes stale -- which catches a whole-interpreter freeze
# the in-process watchdog cannot, because that watchdog is itself a Python thread
# that freezes with everything else (seen live 2026-10-03: 46 minutes deaf, the
# watchdog neither firing nor logging).
#
# Run it from launchd on a short interval (see ai.shmobster.healthcheck.plist.sample).
# It reads the SAME heartbeat path the agent writes (config agent.heartbeat_path,
# default $TMPDIR/shmobster-heartbeat); pass the path as $1 to override.
#
# Deliberately dumb: file mtime vs a staleness window. No parsing, no network.
set -u

HEARTBEAT="${1:-${TMPDIR:-/tmp}/shmobster-heartbeat}"
STALE_SEC="${SHMOBSTER_HEARTBEAT_STALE_SEC:-180}"
SERVICE_SH="$(cd "$(dirname "$0")" && pwd)/service.sh"

now=$(date +%s)

if [ ! -f "$HEARTBEAT" ]; then
  # No heartbeat yet: the agent may be mid-boot. Do nothing rather than fight a
  # restart loop with the supervisor; the next tick will see it.
  echo "health-check: no heartbeat at $HEARTBEAT yet; skipping"
  exit 0
fi

mtime=$(stat -f %m "$HEARTBEAT" 2>/dev/null || stat -c %Y "$HEARTBEAT" 2>/dev/null)
age=$(( now - mtime ))

if [ "$age" -gt "$STALE_SEC" ]; then
  echo "health-check: heartbeat is ${age}s old (> ${STALE_SEC}s) -- the interpreter looks frozen; restarting"
  "$SERVICE_SH" restart
else
  echo "health-check: heartbeat ${age}s old, healthy"
fi
