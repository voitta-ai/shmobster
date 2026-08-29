"""Skill proposals awaiting a trusted user's decision (#129).

The agent flags a moment it thinks is worth a skill; the flag is parked here
under a boot-unique id, the Slack ingest renders it as a card with Open PR /
Decline (the approval-card machinery, #50/#107/#109), and a trusted user
decides. Nothing is drafted, pushed or loaded until that click.

A deliberate sibling of `approvals`, not an entry in it: an approval id names
a command that will *run* when approved, and the two queues must never share
a key space -- a proposal id handed to approve_command has to resolve to
nothing. The shape is the same on purpose (nonce-prefixed ids, one lock,
channel-scoped pop, park/claim log lines, acquire/release for the click
race), so the ingest treats both with one code path."""
import itertools
import logging
import secrets
import threading

from . import approvals, redact

_PENDING = {}
_ids = itertools.count(1)
_NONCE = secrets.token_hex(8)
_MAX = 50
_CLAIMING = {}
_LOCK = threading.Lock()

canonical = approvals.canonical


def add(name, why, channel, thread_ts, user_id):
    key = f"{_NONCE}-{next(_ids)}"
    logging.info("proposals: flagged [%s] in %s by %s (%s): %s", key, channel, user_id,
                 repr(redact.scrub(name)), repr(redact.scrub(why)))
    with _LOCK:
        _PENDING[key] = {
            "name": name, "why": why, "channel": channel, "thread_ts": thread_ts,
            "user_id": user_id, "surfaced": False,
        }
        while len(_PENDING) > _MAX:
            victim = next((k for k in _PENDING if k not in _CLAIMING and k != key), None)
            if victim is None:
                break
            del _PENDING[victim]
    retval = key
    return retval


def claim_unsurfaced(channel):
    out = []
    with _LOCK:
        for key, prop in list(_PENDING.items()):
            if prop.get("channel") == channel and not prop.get("surfaced"):
                prop["surfaced"] = True
                out.append((key, prop))
    retval = out
    return retval


def pop(key, channel):
    with _LOCK:
        k = canonical(key)
        prop = _PENDING.get(k)
        if prop is None or prop.get("channel") != channel:
            return None
        logging.info("proposals: claimed [%s] in %s: %s", k, channel, repr(redact.scrub(prop["name"])))
        del _PENDING[k]
        retval = prop
    return retval


def acquire(key, channel):
    with _LOCK:
        k = canonical(key)
        prop = _PENDING.get(k)
        if prop is None or prop.get("channel") != channel or k in _CLAIMING:
            retval = None
        else:
            _CLAIMING[k] = channel
            retval = prop
    return retval


def status(key, channel):
    with _LOCK:
        k = canonical(key)
        prop = _PENDING.get(k)
        if prop is not None and prop.get("channel") != channel:
            prop = None
        if _CLAIMING.get(k) == channel:
            retval = ("held", prop)
        elif prop is not None:
            retval = ("pending", prop)
        else:
            retval = ("absent", None)
    return retval


def release(key):
    with _LOCK:
        _CLAIMING.pop(canonical(key), None)


def peek(key, channel):
    with _LOCK:
        prop = _PENDING.get(canonical(key))
        retval = None if prop is None or prop.get("channel") != channel else prop
    return retval


def ids(channel=None):
    with _LOCK:
        retval = [k for k, v in list(_PENDING.items()) if channel is None or v.get("channel") == channel]
    return retval
