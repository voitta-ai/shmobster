"""Pending mutating commands, awaiting a human okay (#48).

A command YOLT calls mutating is parked here with a short id instead of being
dropped on the floor; a trusted user then approves it by id (admin_tools
approve_command) and it runs. In-memory only: a restart clears the queue, which
is the safe direction -- a stale approval is worse than being asked again.

This module is ingest-agnostic: it holds the queue, and each ingest renders its
own approval surface over it (Slack posts Approve/Deny buttons -- #50).

An id is unique to this boot, not merely to this process's counter (#109). The
counter alone restarts at 1, while an approval card is a Slack message that
outlives the process and carries the id in its button value -- so after a
restart an old card could name whatever request was handed 1 the next time
round, and a human clicking Approve on what they read would release something
else. That is the one property the gate exists to provide, and neither the
channel scope nor the trust check catches it, since both are satisfied. So the
key is `<boot nonce>-<n>` with a nonce drawn fresh at every start: a card from a
previous boot matches nothing and is reported as no longer pending. The bare
`<n>` stays what humans read and type; canonical() expands it against the
current nonce, because a short id typed now can only mean this boot's request.

Every read and write of the queue is under one lock (#103). Bolt serves mention
handlers and button handlers on different threads, so surfacing cards, parking,
acquiring and popping all overlap; unsynchronized, the cheapest symptom is a
RuntimeError from iterating a dict another thread is mutating, and the most
expensive is an approved command that never runs.

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
import secrets
import threading

from . import redact

_PENDING = {}
_ids = itertools.count(1)
# Drawn fresh on every start and mixed into every id (#109). Nothing persists
# it, deliberately: the whole point is that a previous boot's ids resolve to
# nothing rather than to whatever has since reused their number.
_NONCE = secrets.token_hex(4)
_MAX = 50
_CLAIMING = {}  # request id -> the channel holding it
_LOCK = threading.Lock()


def canonical(key):
    """The queue key for an id arriving from anywhere: a button value, a human
    typing `approve 4`, a model relaying either.

    A bare number is this boot's. It can only have been read off a card or a
    message belonging to the queue that is still this one, so it takes the
    current nonce. Anything already carrying a nonce is left as it is, which is
    what makes a stale card resolve to nothing instead of to whichever request
    inherited its number."""
    k = str(key).strip().lstrip("#")
    if k.isdigit():
        k = f"{_NONCE}-{k}"
    retval = k
    return retval


def short(key):
    """What a human reads and types: the bare counter for one of this boot's
    ids, and the whole string for anything else.

    A foreign id has no short form, and inventing one would print an id that
    means a different request now than it did on the card it came from -- which
    is the confusion the nonce exists to end, reintroduced at the surface."""
    k = str(key).strip().lstrip("#")
    prefix = f"{_NONCE}-"
    retval = k[len(prefix):] if k.startswith(prefix) else k
    return retval


def add(command, channel, reason):
    key = f"{_NONCE}-{next(_ids)}"
    # Logged before the queue is touched, for the same reason pop logs before
    # the delete: scrub() is fail-closed, and a raise after the insert would
    # leave a request parked that no caller ever got an id for -- an orphan
    # nobody can approve, which is the shape of bug this all exists to fix.
    # The reason gets the same treatment as the command: yolt_gate renders its
    # own failures as "yolt error: <exc>", and a TimeoutExpired there carries
    # the classifier's argv -- which is the command, again, by another route.
    logging.info("approvals: parked [%s] in %s (%s): %s", key, channel,
                 repr(redact.scrub(reason)), repr(redact.scrub(command)))
    with _LOCK:
        _PENDING[key] = {
            "command": command, "channel": channel, "reason": reason, "surfaced": False,
        }
        # Overflow never evicts a held request (#103). acquire() leaves it in
        # the queue until the approve path pops it, so an oldest-first eviction
        # during that window turns a trusted click into "no pending request"
        # and the command a human approved simply never runs.
        #
        # Nor the request being parked right now, which is otherwise its own
        # victim once everything older is held: add() would hand back an id for
        # a request it had just deleted. When there is nothing evictable the cap
        # is exceeded instead -- it is a safety valve on a 50-deep queue, and
        # going one over beats returning a dead id.
        while len(_PENDING) > _MAX:
            victim = next((k for k in _PENDING if k not in _CLAIMING and k != key), None)
            if victim is None:
                break
            del _PENDING[victim]
    retval = key
    return retval


def claim_unsurfaced(channel):
    """Requests in this channel that no ingest has rendered yet, marked as
    surfaced so a second call (or a second reply in the same thread) doesn't
    post duplicate buttons. Returns [(id, request), ...].

    Locked like the rest: this runs on the mention thread while button handlers
    add and pop on theirs, and iterating _PENDING unsynchronized raises
    RuntimeError: dictionary changed size during iteration -- which would take
    out the reply that was about to show the buttons. The snapshot is built and
    marked under the lock, then posted outside it."""
    out = []
    with _LOCK:
        for key, req in list(_PENDING.items()):
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
        k = canonical(key)
        req = _PENDING.get(k)
        if req is None or req.get("channel") != channel:
            return None
        # Logged before the delete, not after: scrub() is fail-closed and raises
        # when the redactor cannot be loaded, and a raise between the delete and
        # the caller's execute() would consume the request without running it.
        # Failing here instead leaves it parked, which is the retryable direction.
        logging.info("approvals: claimed [%s] in %s: %s", k, channel, repr(redact.scrub(req["command"])))
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
        k = canonical(key)
        req = _PENDING.get(k)
        if req is None or req.get("channel") != channel or k in _CLAIMING:
            retval = None
        else:
            _CLAIMING[k] = channel
            retval = req
    return retval


def status(key, channel):
    """One locked snapshot of a request: ("held"|"pending"|"absent", req|None).

    Read in a single acquisition rather than peek() and then held(), so a
    surface can never render a state that never existed -- pending according to
    one call and not held according to the next, because a click landed in
    between. It can still go stale on the way to Slack; nothing about a live
    queue is instantaneously true. What it must not be is self-contradictory.

    "held" is asked first because the queue goes quiet in the middle of a
    click: the approve path pops the request and only then runs the command, so
    for the entire duration of the run _PENDING says nothing and the hold is
    the only thing that knows (#103). Channel-scoped throughout, like pop and
    peek: an id is unique per boot now (#109), so the scope is no longer what
    keeps two channels' requests apart -- it is the separate guarantee that an
    approval raised in one channel is answerable only there (#107).
    """
    with _LOCK:
        k = canonical(key)
        req = _PENDING.get(k)
        if req is not None and req.get("channel") != channel:
            req = None
        if _CLAIMING.get(k) == channel:
            retval = ("held", req)
        elif req is not None:
            retval = ("pending", req)
        else:
            retval = ("absent", None)
    return retval


def release(key):
    """Drop the hold acquire() took. Safe to call for a key never acquired."""
    with _LOCK:
        _CLAIMING.pop(canonical(key), None)


def peek(key, channel):
    """Read a parked request without claiming it. Channel-scoped like pop, for
    the same reason. A surface that has to *name* a command -- a refused click
    saying which command it did not run (#94) -- needs this; popping there would
    be the very bug the refusal exists to prevent."""
    with _LOCK:
        req = _PENDING.get(canonical(key))
        if req is None or req.get("channel") != channel:
            retval = None
        else:
            retval = req
    return retval


def ids(channel=None):
    """Outstanding request keys, optionally only this channel's. Full keys, not
    the short form: a caller that renders them for a human owes short(), and a
    caller that puts one in a button value needs exactly what is returned."""
    with _LOCK:
        retval = [
            k for k, v in list(_PENDING.items())
            if channel is None or v.get("channel") == channel
        ]
    return retval
