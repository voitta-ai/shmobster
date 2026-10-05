"""Diagnosis and an out-of-process liveness heartbeat (#66 follow-up).

Found live 2026-10-03: the agent went deaf for 46 minutes with the process up at
0% CPU, no sleep, and the in-process watchdog neither firing nor logging -- a
whole-interpreter freeze, not the socket-level wedge the watchdog can see. Two
things come from that.

**faulthandler on a signal.** When it happens again, `kill -USR1 <pid>` dumps a
traceback for EVERY thread to stderr (the supervisor's log), turning "frozen,
cause unknown" into one command that shows exactly which thread is stuck and
where -- an SSL read, a model call, a lock. Registered at startup; costs nothing
until the signal arrives.

**A heartbeat the watchdog can't fake.** The in-process watchdog is a Python
thread, so a freeze that stops the event loop stops the watchdog too -- which is
why it did not fire. The fix is a check OUTSIDE the interpreter: a thread writes
the current time to a small file every few seconds, and an external job
(`deploy/health-check.sh` under launchd) restarts the service when that file goes
stale. A freeze that stops every Python thread also stops the heartbeat, so the
staleness is detectable from outside even when nothing inside can report it.
Unlike "agent.log went quiet", it does not false-positive on an idle bot: the
heartbeat advances on a timer, not on traffic."""
import faulthandler
import logging
import os
import signal
import tempfile
import threading
import time

_DEFAULT_HEARTBEAT_SEC = 15


def install_faulthandler():
    """Dump all thread stacks to stderr on SIGUSR1 (and on a fatal signal).
    Idempotent enough: a second call just re-registers the same handler."""
    try:
        faulthandler.enable()
        faulthandler.register(signal.SIGUSR1, all_threads=True, chain=True)
        logging.info("diag: faulthandler armed -- `kill -USR1 <pid>` dumps all thread stacks")
    except Exception:
        # Never let diagnostics stop the agent from serving.
        logging.exception("diag: could not arm faulthandler")


def heartbeat_path():
    """Where the heartbeat is written. Config-driven, with a temp-dir default so
    the feature works with no configuration; the external checker reads the same
    value."""
    from . import config
    retval = config.HEARTBEAT_PATH or os.path.join(tempfile.gettempdir(), "shmobster-heartbeat")
    return retval


def _beat(path, interval):
    while True:
        try:
            with open(path, "w") as f:
                f.write(f"{time.time():.0f}\n")
        except OSError:
            logging.exception("diag: could not write heartbeat %s", path)
        time.sleep(interval)


def start_heartbeat(interval=_DEFAULT_HEARTBEAT_SEC):
    """A daemon thread that stamps the heartbeat file every `interval` seconds.
    Its whole value is that it stops when the interpreter freezes -- so it is a
    plain thread with no cleverness, deliberately. Returns the thread."""
    path = heartbeat_path()
    thread = threading.Thread(target=_beat, args=(path, interval),
                              name="shmobster-heartbeat", daemon=True)
    thread.start()
    logging.info("diag: heartbeat every %ds -> %s", interval, path)
    retval = thread
    return retval
