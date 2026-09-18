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
_INFLIGHT = {}  # proposal id -> the proposal dict; see approvals._INFLIGHT (#105)
_LOCK = threading.Lock()

canonical = approvals.canonical


def add(name, why, channel, thread_ts, user_id, scope="channel", scope_reason="",
        amends=None):
    key = f"{_NONCE}-{next(_ids)}"
    logging.info("proposals: flagged [%s] in %s by %s (%s, scope=%s): %s", key, channel,
                 user_id, repr(redact.scrub(name)), scope, repr(redact.scrub(why)))
    with _LOCK:
        _PENDING[key] = {
            "name": name, "why": why, "channel": channel, "thread_ts": thread_ts,
            "user_id": user_id, "surfaced": False,
            # Where this would land and why, decided at flag time so the card
            # can show it before anyone clicks (#210). `channel` is the
            # status-quo default, so an older restored proposal with neither
            # field reads as today's behaviour rather than as an error.
            "scope": scope, "scope_reason": scope_reason,
            # An existing skill this may amend instead of siblinging.
            "amends": amends,
        }
        while len(_PENDING) > _MAX:
            victim = next((k for k in _PENDING if k != key), None)
            if victim is None:
                break
            del _PENDING[victim]
    retval = key
    return retval


def restore(key, prop):
    """Put a proposal back under its ORIGINAL id, card already posted.
    A draft or a PR can fail for reasons that will not hold next time -- the
    waterfall was down, GitHub blinked -- and the card the trusted user
    clicked is the only place the id is written down. A fresh id would leave
    that card pointing at nothing. Clears any in-flight hold too (#105), so
    restore after acquire is a complete put-back."""
    with _LOCK:
        k = canonical(key)
        _INFLIGHT.pop(k, None)
        _PENDING[k] = {**prop, "surfaced": True}


def unsurface(key):
    """The ingest could not post the card: make the proposal eligible for
    another one, instead of pending forever with no surface."""
    with _LOCK:
        prop = _PENDING.get(canonical(key))
        if prop is not None:
            prop["surfaced"] = False


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
    """acquire() + finish(); None while another surface holds it (#105)."""
    prop = acquire(key, channel)
    if prop is not None:
        finish(key)
    retval = prop
    return retval


def acquire(key, channel):
    """Move the proposal out of _PENDING into the in-flight map (#105); the
    caller owes finish() or release(), same contract as approvals.acquire."""
    with _LOCK:
        k = canonical(key)
        prop = _PENDING.get(k)
        if prop is None or prop.get("channel") != channel or k in _INFLIGHT:
            retval = None
        else:
            logging.info("proposals: claimed [%s] in %s: %s", k, channel, repr(redact.scrub(prop["name"])))
            del _PENDING[k]
            _INFLIGHT[k] = prop
            retval = prop
    return retval


def finish(key):
    with _LOCK:
        _INFLIGHT.pop(canonical(key), None)


def status(key, channel):
    with _LOCK:
        k = canonical(key)
        held = _INFLIGHT.get(k)
        if held is not None and held.get("channel") == channel:
            retval = ("held", held)
            return retval
        prop = _PENDING.get(k)
        if prop is not None and prop.get("channel") != channel:
            prop = None
        if prop is not None:
            retval = ("pending", prop)
        else:
            retval = ("absent", None)
    return retval


def release(key):
    """Put a held proposal back; no-op after finish() or for a stranger."""
    with _LOCK:
        k = canonical(key)
        prop = _INFLIGHT.pop(k, None)
        if prop is not None:
            _PENDING[k] = prop


def peek(key, channel):
    with _LOCK:
        prop = _PENDING.get(canonical(key))
        retval = None if prop is None or prop.get("channel") != channel else prop
    return retval


def ids(channel=None):
    with _LOCK:
        retval = [k for k, v in list(_PENDING.items()) if channel is None or v.get("channel") == channel]
    return retval
