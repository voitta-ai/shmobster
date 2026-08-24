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
asked for. Log lines are scrubbed by redact.install_logging(), which wraps the
formatter, so a credential riding argv does not reach the file."""
import itertools
import logging

_PENDING = {}
_ids = itertools.count(1)
_MAX = 50


def add(command, channel, reason):
    key = str(next(_ids))
    _PENDING[key] = {
        "command": command, "channel": channel, "reason": reason, "surfaced": False,
    }
    while len(_PENDING) > _MAX:
        del _PENDING[next(iter(_PENDING))]
    logging.info("approvals: parked [%s] in %s (%s): %s", key, channel, reason, command)
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
    in one channel can't release a command parked in another."""
    req = _PENDING.get(str(key))
    if req is None or req.get("channel") != channel:
        return None
    del _PENDING[str(key)]
    logging.info("approvals: claimed [%s] in %s: %s", key, channel, req["command"])
    retval = req
    return retval


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
