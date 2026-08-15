"""Liveness watchdog (#66): exit when the Socket Mode connection stops working.

The failure this exists for: the builtin Socket Mode client can land in a state
where it reconnects forever without ever doing useful work. The handshake
returns 101, Slack drops the TCP connection ~21s later with no WebSocket close
frame, the write that follows raises EPIPE, and the client immediately
reconnects with no backoff. Every failure is caught and logged, so the process
never exits -- launchd `KeepAlive` sees a healthy service while the agent is
silently deaf. One instance sat like that for 13 days and 52,707 sessions.

Two signals, because either alone can be fooled:

* **Session stability** (primary). In the wedge no session ever survives ~21s;
  a healthy session lives for hours. This holds whether or not the doomed
  connections were answering pings, which the archived log cannot tell us --
  connection-scoped counters reset every reconnect, so the absence of ping/pong
  log summaries proves nothing. Stability is the signal that does not depend on
  that unknown.
* **Ping/pong freshness** (secondary). Covers the other shape: a session that
  stays up but goes quiet. `ping_interval` is 10s under
  `slack_bolt`'s `SocketModeHandler`, so pongs land every ~10s regardless of
  whether the workspace is busy. Delivered events would be the wrong signal
  here -- an idle bot in quiet channels legitimately receives none for days.

Both must look healthy. Requiring only one lets the wedge through: if the
doomed 21s connections were in fact ponging, pong freshness alone would have
called that wedge healthy for 13 days.

Reconnect logs are not a signal at all -- the wedged process emitted them
enthusiastically the whole time.

Exiting is the fix because the supervisor is the thing that can actually recover
us: KeepAlive restarts, ThrottleInterval 10 keeps that from becoming a hot loop.
A real network outage therefore restarts us every timeout until the network
returns -- noisy but harmless, and better than staying deaf.
"""
import logging
import os
import sys
import threading
import time

_DEFAULT_POLL_SEC = 5
# How long one session must survive before we count the connection as working.
# Comfortably above the ~21s wedge cycle and above the SDK's own 40s staleness
# teardown (ping_interval 10 * 4), so ordinary SDK-healed hiccups do not count
# as a wedge.
_STABLE_SEC = 60

_MISSING = object()


def _probe(client):
    """(session_id, last_ping_pong_time) for the current session.

    session_id is None when there is no session. last_ping_pong_time is None
    when this session has not heard a pong yet, or _MISSING when the SDK no
    longer exposes it (see _loop -- we disarm rather than kill a healthy bot).
    """
    session = getattr(client, "current_session", None)
    if session is None:
        return None, None
    pong = getattr(session, "last_ping_pong_time", _MISSING)
    sid = getattr(session, "session_id", _MISSING)
    retval = (sid, pong)
    return retval


def _loop(client, timeout_sec, poll_sec):
    # Elapsed time is measured with the monotonic clock so an NTP step or a
    # laptop sleep/wake cannot fake a timeout (on macOS time.monotonic() does
    # not advance while suspended, so a wake is not scored as deafness). The
    # epoch-based last_ping_pong_time is only ever used as a change detector.
    now = time.monotonic()
    pong_ok_at = now  # last time ping/pong advanced
    stable_ok_at = now  # last time a session had survived _STABLE_SEC
    session_since = None  # when the current session_id was first seen
    current_sid = None
    last_pong = None

    while True:
        time.sleep(poll_sec)
        try:
            now = time.monotonic()
            sid, pong = _probe(client)

            if pong is _MISSING or sid is _MISSING:
                # The SDK no longer exposes what we probe. Killing the process
                # every timeout on a dependency bump would be far worse than
                # not watching, so disarm loudly instead.
                logging.error(
                    "watchdog: cannot read session_id/last_ping_pong_time from the "
                    "socket mode client (slack_sdk internals changed?) -- watchdog "
                    "DISARMED, the deaf-but-alive failure in #66 is no longer detected"
                )
                return

            if sid is None:
                session_since = None
                current_sid = None
            elif sid != current_sid:
                current_sid = sid
                session_since = now
            elif session_since is not None and now - session_since >= _STABLE_SEC:
                stable_ok_at = now

            if pong is not None and pong != last_pong:
                last_pong = pong
                pong_ok_at = now

            unstable_for = now - stable_ok_at
            deaf_for = now - pong_ok_at
            if unstable_for < timeout_sec and deaf_for < timeout_sec:
                continue

            logging.error(
                "watchdog: socket mode looks wedged -- no stable session for %ds, "
                "no ping/pong for %ds (limit %ds, connected=%s); exiting so the "
                "supervisor restarts us (#66)",
                int(unstable_for),
                int(deaf_for),
                timeout_sec,
                client.is_connected(),
            )
            # Hard exit: the SDK keeps non-daemon threads that would block a
            # clean shutdown, and a wedged client is exactly the case where a
            # graceful close cannot be relied on.
            sys.stderr.flush()
            os._exit(1)
        except Exception:
            # Never let the watchdog thread die quietly -- an unwatched process
            # is the failure this module exists to prevent.
            logging.exception("watchdog: check failed; continuing")


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
    logging.info(
        "watchdog: armed (exit after %ds without a stable session or without ping/pong)",
        timeout_sec,
    )
    retval = thread
    return retval
