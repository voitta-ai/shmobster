"""Pending mutating commands, awaiting a human okay (#48).

A command YOLT calls mutating is parked here with a short id instead of being
dropped on the floor; a trusted user then approves it by id (admin_tools
approve_command) and it runs. In-memory only: a restart clears the queue, which
is the safe direction -- a stale approval is worse than being asked again.

This module is ingest-agnostic: it holds the queue, and each ingest renders its
own approval surface over it (Slack posts Approve/Deny buttons -- #50).

Approval answers *may this run at all*; the channel policy (policy.check) still
answers *is this in scope* at exec time. The two are separate gates.

Park and claim are logged (#94). The queue lives only in this process, and the
approval card is the only other place a parked command is ever written down --
so once that card is gone, the log is the sole surviving record of what was
asked for. Commands are logged as repr: a newline in one would otherwise forge
extra lines in a line-oriented log, in the very record this exists to trust.

The command is scrubbed here, at the emission site, not left to the formatter
redact.install_logging() wraps. That formatter is installed by the Slack ingest
at import; this module is deliberately ingest-agnostic and reachable through
tools.run_shell from a script, a test, or the next ingest, none of which have
run that bootstrap. A log file is durable in a way an approval card is not, so
the one place that must not depend on who booted us is this one."""
import itertools
import logging
import threading

from . import redact

_PENDING = {}
_ids = itertools.count(1)
_MAX = 50
_CLAIMING = set()
_LOCK = threading.Lock()


def add(command, channel, reason):
    key = str(next(_ids))
    # Logged before the queue is touched, for the same reason pop logs before
    # the delete: scrub() is fail-closed, and a raise after the insert would
    # leave a request parked that no caller ever got an id for -- an orphan
    # nobody can approve, which is the shape of bug this all exists to fix.
    # The reason gets the same treatment as the command: yolt_gate renders its
    # own failures as "yolt error: <exc>", and a TimeoutExpired there carries
    # the classifier's argv -- which is the command, again, by another route.
    logging.info("approvals: parked [%s] in %s (%s): %s", key, channel,
                 repr(redact.scrub(reason)), repr(redact.scrub(command)))
    _PENDING[key] = {
        "command": command, "channel": channel, "reason": reason, "surfaced": False,
    }
    while len(_PENDING) > _MAX:
        del _PENDING[next(iter(_PENDING))]
    retval = key
    return retval


def claim_unsurfaced(channel):
    """Requests in this channel that no ingest has rendered yet, marked as
    surfaced so a second call (or a second reply in the same thread) doesn't
    post duplicate buttons. Returns [(id, request), ...]."""
    out = []
    for key, req in _PENDING.items():
        if req.get("channel") == channel and not req.get("surfaced"):
            req["surfaced"] = True
            out.append((key, req))
    retval = out
    return retval


def pop(key, channel):
    """Claim a request -- only from the channel it was raised in, so an approval
    in one channel can't release a command parked in another.

    Under the lock, because the lookup and the delete are two steps and the
    button surface and the text surface reach here on different threads (#103).
    Unlocked, both callers pass the guard, one deletes, and the other raises
    KeyError out of a button handler -- so the request that a human approved is
    consumed by one path and reported as a crash by the other."""
    with _LOCK:
        k = str(key)
        req = _PENDING.get(k)
        if req is None or req.get("channel") != channel:
            return None
        # Logged before the delete, not after: scrub() is fail-closed and raises
        # when the redactor cannot be loaded, and a raise between the delete and
        # the caller's execute() would consume the request without running it.
        # Failing here instead leaves it parked, which is the retryable direction.
        logging.info("approvals: claimed [%s] in %s: %s", key, channel, repr(redact.scrub(req["command"])))
        del _PENDING[k]
        retval = req
    return retval


def acquire(key, channel):
    """Take exclusive hold of a request before acting on it, or return None.

    Two Slack deliveries of the same button press land on two Bolt threads
    (#103). Without this, both see a pending request, both proceed, and the
    loser -- the one whose pop finds nothing -- overwrites the winner's output
    with "no pending request" for a command that did run. Hiding the buttons
    does not prevent that; only a state transition ahead of the work does.

    Returns None for a stale request too, which is the other half: a surface
    that did not acquire must not rewrite the card, because that card holds the
    only copy of the command (#94).

    Held until release(), which the caller owes in a finally. In-memory, so a
    restart clears it -- the same direction the queue itself takes."""
    with _LOCK:
        k = str(key)
        req = _PENDING.get(k)
        if req is None or req.get("channel") != channel or k in _CLAIMING:
            retval = None
        else:
            _CLAIMING.add(k)
            retval = req
    return retval


def held(key):
    """Whether some surface has this request in flight right now.

    Distinct from pending, and the distinction is the whole point: the approve
    path pops the request out of the queue and only then runs the command, so
    for the entire duration of the run _PENDING says nothing and the hold is
    the only thing that knows (#103). Inferring in-flight from "still pending"
    reports a running command as gone."""
    with _LOCK:
        retval = str(key) in _CLAIMING
    return retval


def release(key):
    """Drop the hold acquire() took. Safe to call for a key never acquired."""
    with _LOCK:
        _CLAIMING.discard(str(key))


def peek(key, channel):
    """Read a parked request without claiming it. Channel-scoped like pop, for
    the same reason. A surface that has to *name* a command -- a refused click
    saying which command it did not run (#94) -- needs this; popping there would
    be the very bug the refusal exists to prevent."""
    req = _PENDING.get(str(key))
    if req is None or req.get("channel") != channel:
        retval = None
    else:
        retval = req
    return retval


def ids(channel=None):
    """Outstanding request ids, optionally only this channel's."""
    retval = [
        k for k, v in _PENDING.items()
        if channel is None or v.get("channel") == channel
    ]
    return retval
