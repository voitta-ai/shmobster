"""Pending mutating commands, awaiting a human okay (#48).

A command YOLT calls mutating is parked here with a short id instead of being
dropped on the floor; a trusted user then approves it by id (admin_tools
approve_command) and it runs. In-memory only: a restart clears the queue, which
is the safe direction -- a stale approval is worse than being asked again.

This module is ingest-agnostic: it holds the queue, and each ingest renders its
own approval surface over it (Slack posts Approve/Deny buttons -- #50).

Approval answers *may this run at all*; the channel policy (policy.check) still
answers *is this in scope* at exec time. The two are separate gates."""
import itertools

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
    retval = req
    return retval


def ids(channel=None):
    """Outstanding request ids, optionally only this channel's."""
    retval = [
        k for k, v in _PENDING.items()
        if channel is None or v.get("channel") == channel
    ]
    return retval
