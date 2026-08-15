"""Liveness watchdog (#66): exit when the Socket Mode connection has gone deaf.

The failure this exists for: the builtin Socket Mode client can land in a state
where it reconnects forever without ever receiving anything. The handshake
returns 101, no `hello` and no pong ever arrive, Slack drops the TCP connection
~20s later, the write that follows raises EPIPE, and the client immediately
reconnects with no backoff. Every failure is caught and logged, so the process
never exits -- launchd `KeepAlive` sees a healthy service while the agent is
silently deaf. One instance sat like that for 13 days.

The signal is ping/pong, not delivered events. An idle bot can legitimately
receive zero events for days (quiet channels), so an events-based timer would
restart a perfectly healthy process; ping/pong keeps flowing regardless of
traffic (`SocketModeClient(ping_interval=5)` by default). A wedged connection
has neither, which is exactly what separates "deaf" from "quiet".

`last_ping_pong_time` lives on the Connection, so a reconnect resets it to None.
That is what we want: deafness accumulates across reconnects instead of being
forgiven by each new session, which is the whole shape of the wedge.

Exiting is the fix because the supervisor is the thing that can actually recover
us: KeepAlive restarts, ThrottleInterval 10 keeps that from becoming a hot loop.
A real network outage will therefore restart us every timeout until the network
returns -- noisy but harmless, and preferable to staying deaf.
"""
import logging
import os
import sys
import threading
import time

_DEFAULT_POLL_SEC = 5


def _last_pong(client):
    """Wall-clock time of the last ping/pong on the current session, or None if
    there is no session yet or it has not heard anything."""
    session = getattr(client, "current_session", None)
    if session is None:
        return None
    retval = getattr(session, "last_ping_pong_time", None)
    return retval


def _loop(client, timeout_sec, poll_sec):
    # Seeded with "now" so startup gets a full timeout to establish the first
    # connection rather than tripping immediately.
    last_ok = time.time()
    while True:
        time.sleep(poll_sec)
        pong = _last_pong(client)
        if pong is not None and pong > last_ok:
            last_ok = pong
        deaf_for = time.time() - last_ok
        if deaf_for < timeout_sec:
            continue
        logging.error(
            "watchdog: no Slack ping/pong for %ds (limit %ds, connected=%s) -- "
            "socket mode looks wedged; exiting so the supervisor restarts us (#66)",
            int(deaf_for),
            timeout_sec,
            client.is_connected(),
        )
        # Hard exit: the SDK keeps non-daemon threads that would block a clean
        # shutdown, and a wedged client is exactly the case where a graceful
        # close cannot be relied on.
        sys.stderr.flush()
        os._exit(1)


def start(client, timeout_sec, poll_sec=_DEFAULT_POLL_SEC):
    """Watch `client` in a daemon thread. timeout_sec of 0 disables the watchdog.

    Returns the thread, or None when disabled.
    """
    if not timeout_sec:
        logging.info("watchdog: disabled (watchdog_timeout_sec=0)")
        return None
    thread = threading.Thread(
        target=_loop,
        args=(client, timeout_sec, poll_sec),
        name="shmobster-watchdog",
        daemon=True,
    )
    thread.start()
    logging.info("watchdog: armed (%ds without ping/pong -> exit)", timeout_sec)
    retval = thread
    return retval
