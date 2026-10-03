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

* **Message processing** (a third shape, found live 2026-10-03). The first two
  signals watch the *socket*; this one watches the *consumer*. In slack_sdk's
  builtin client the receive loop reads frames -- ping/pong AND events -- and
  enqueues them on `message_queue`; a separate `message_processor` thread drains
  the queue and runs the listeners. Because pong is handled in that same receive
  loop, a fresh pong proves the socket is live but says nothing about the
  processor. If the processor thread dies or wedges, the socket keeps ponging
  and the session stays stable -- both signals above read healthy -- while events
  pile up unhandled and the agent goes silent. Found after a stable, ponging
  session sat deaf for ~15 hours and the #66 watchdog never tripped. The signal:
  the processor is not alive, or the queue has not drained to empty for the whole
  timeout. An idle bot does not trip it -- its queue is empty and its processor
  alive -- so, unlike "events delivered," this is safe. It stands on its own
  (OR), because a dead consumer is a wedge no matter how healthy the socket.

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


def _probe_processing(client):
    """(processor_alive, queue_size) for the client's message-consumer side.

    Either is _MISSING when the SDK no longer exposes it -- we then skip this
    signal (keeping the two socket signals) rather than disarm the whole
    watchdog, because the socket signals are the original #66 guarantee."""
    processor = getattr(client, "message_processor", _MISSING)
    queue = getattr(client, "message_queue", _MISSING)
    alive = _MISSING
    if processor is not _MISSING:
        is_alive = getattr(processor, "is_alive", _MISSING)
        alive = bool(is_alive()) if callable(is_alive) else _MISSING
    size = _MISSING
    if queue is not _MISSING:
        qsize = getattr(queue, "qsize", _MISSING)
        try:
            size = int(qsize()) if callable(qsize) else _MISSING
        except Exception:
            size = _MISSING
    retval = (alive, size)
    return retval


def _assess(unstable_for, deaf_for, proc_dead_for, queue_stuck_for, timeout_sec):
    """Pure verdict: (should_exit, reason) from the four elapsed measures. Kept
    separate from _loop so it can be tested without threads or sleeps.

    The socket pair is an AND (#66: either alone can be fooled). The processing
    signal is independent -- a dead or stuck consumer is a wedge whatever the
    socket is doing -- so it is OR'd in."""
    socket_wedged = unstable_for >= timeout_sec and deaf_for >= timeout_sec
    processing_wedged = proc_dead_for >= timeout_sec or queue_stuck_for >= timeout_sec
    if socket_wedged:
        retval = (True, f"no stable session for {int(unstable_for)}s and no ping/pong "
                        f"for {int(deaf_for)}s")
        return retval
    if processing_wedged:
        if proc_dead_for >= timeout_sec:
            why = f"message processor not alive for {int(proc_dead_for)}s"
        else:
            why = f"message queue not drained for {int(queue_stuck_for)}s"
        retval = (True, why)
        return retval
    retval = (False, "")
    return retval


def _loop(client, timeout_sec, poll_sec):
    # Elapsed time is measured with the monotonic clock so an NTP step or a
    # laptop sleep/wake cannot fake a timeout (on macOS time.monotonic() does
    # not advance while suspended, so a wake is not scored as deafness). The
    # epoch-based last_ping_pong_time is only ever used as a change detector.
    now = time.monotonic()
    pong_ok_at = now  # last time ping/pong advanced
    stable_ok_at = now  # last time a session had survived _STABLE_SEC
    proc_ok_at = now  # last time the message processor was alive (or unknown)
    queue_ok_at = now  # last time the message queue was empty (or unknown)
    session_since = None  # when the current session_id was first seen
    current_sid = None
    last_pong = None
    _warned_processing = False

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

            # Processing side (the 2026-10-03 shape). Unknown fields keep their
            # ok_at pinned to now, so a missing attribute never trips -- it just
            # silently skips this signal, warned once.
            proc_alive, qsize = _probe_processing(client)
            if proc_alive is _MISSING or qsize is _MISSING:
                if not _warned_processing:
                    logging.warning(
                        "watchdog: cannot read message_processor/message_queue "
                        "(slack_sdk internals changed?) -- the processing-wedge "
                        "signal is skipped; the socket signals still run"
                    )
                    _warned_processing = True
                proc_ok_at = now
                queue_ok_at = now
            else:
                if proc_alive:
                    proc_ok_at = now
                if qsize == 0:
                    queue_ok_at = now

            unstable_for = now - stable_ok_at
            deaf_for = now - pong_ok_at
            proc_dead_for = now - proc_ok_at
            queue_stuck_for = now - queue_ok_at
            should_exit, reason = _assess(
                unstable_for, deaf_for, proc_dead_for, queue_stuck_for, timeout_sec)
            if not should_exit:
                continue

            logging.error(
                "watchdog: socket mode looks wedged -- %s (limit %ds, connected=%s); "
                "exiting so the supervisor restarts us (#66)",
                reason, timeout_sec, client.is_connected(),
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
        "watchdog: armed (exit after %ds without a stable session+ping/pong, or "
        "with a dead/stuck message processor)",
        timeout_sec,
    )
    retval = thread
    return retval
