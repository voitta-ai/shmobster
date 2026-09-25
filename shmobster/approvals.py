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
previous boot matches nothing and is reported as no longer pending.

The nonce is on the id every surface prints, not only on the value the button
carries. A stale card still shows its id, and typing that id is the documented
fallback for when the buttons are not available -- so a bare `<n>` completed
into "this boot's <n>" would walk straight back into the same failure by the
typed route, the human reading one command while another one runs. A bare number
therefore resolves to nothing: what a human types is the id exactly as the card
shows it. An id that resolves to nothing is answered with how many requests are
parked, never with which -- that answer goes back into the model's tool loop,
where a live id is an id it can approve without a human ever having quoted it.

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
#
# 64 bits, not the 32 that would also read as "random enough". A repeat is not a
# cosmetic clash here -- it is a card from a dead boot resolving to a live
# request again, which is the failure this exists to end, and it would be
# guarding a Slack message that can outlive many restarts. The cost of the extra
# bytes is eight more characters for whoever types an id by hand.
_NONCE = secrets.token_hex(8)
_MAX = 50
# Requests a surface has taken out of the queue and not yet finished or put
# back (#105). Ownership, not a flag: acquire() MOVES the request here, so
# there is exactly one transition and a second consumer -- another delivery of
# the same click, or a trusted user typing `approve <id>` mid-run -- can only
# ever be told "already in flight", never "no pending request" for a command
# that did run.
_INFLIGHT = {}  # request id -> the request dict
_LOCK = threading.Lock()


def canonical(key):
    """The queue key for an id arriving from anywhere: a button value, a human
    typing `approve [a1b2c3d4e5f60718-4]`, a model relaying either.

    Normalization only, and only of what a human puts around an id they are
    copying: surrounding brackets, because every surface prints the id as
    `[<id>]` and quoting a card verbatim is the obvious thing to do; a leading
    `#`; stray whitespace. Deliberately not a place where a partial id is
    completed -- a bare number is not treated as this boot's, because the
    surface it was read off may be a card from a dead one, and expanding it here
    is exactly how the id a human read and the request that runs come apart
    again. Brackets around a bare number still leave a bare number."""
    retval = str(key).strip().strip("[]").strip().lstrip("#").strip()
    return retval


def from_this_boot(key):
    """Whether this id was minted by the process reading it (#258).

    Every id carries the boot's nonce, so a card that outlived a restart is
    distinguishable from a typo -- and those deserve different answers. The
    caller must still ask the queue: a same-boot id can be absent because it
    already ran."""
    retval = canonical(key).startswith(f"{_NONCE}-")
    return retval


def add(command, channel, reason, refused=False, requester=None):
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
            # Whether the classifier refused outright rather than asked (#172).
            # Carried on the request because the card is rendered from it, and a
            # human clicking through a row of cards has no other way to tell the
            # two apart. The default under-warns rather than over-warns: a
            # caller that forgets it gets an ordinary card for a refusal, not a
            # refusal card for an ordinary park, which would cry wolf on every
            # queue. run_shell is the only caller; a second one must pass it.
            "refused": refused,
            # WHOSE task this is, as opposed to who approves it (#262). The
            # resumed turn is the answer to the original question, so it must
            # be written for the person who asked -- a designer's task approved
            # by an operator still reaches the designer, in the same thread.
            "requester": requester,
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
        # A held request is out of _PENDING entirely (#105), so overflow can
        # no longer evict it; only the request being parked right now is
        # protected here, or add() would return an id it just deleted.
        while len(_PENDING) > _MAX:
            victim = next((k for k in _PENDING if k != key), None)
            if victim is None:
                break
            del _PENDING[victim]
    retval = key
    return retval


# Threads with a resume in flight (#169 review). Not a record of which threads
# have ever resumed -- a thread resumes once per round of parks, and there are
# many rounds.
_RESUMING = set()


def begin_resume(channel, thread_ts):
    """Claim the resume for this thread, or return False (#169 review).

    pending_in() alone is not enough. Two clicks land on two Bolt worker
    threads; each pops its own request and runs it, and when both finish both
    see an empty queue for the thread -- so both resume, and one thread gets
    two turns arguing about the same outcome. The check and the claim have to
    happen under one lock, which is what this is."""
    with _LOCK:
        if (channel, thread_ts) in _RESUMING:
            retval = False
        elif any(req.get("channel") == channel and req.get("thread_ts") == thread_ts
                 for req in _PENDING.values()):
            retval = False
        else:
            _RESUMING.add((channel, thread_ts))
            retval = True
    return retval


def end_resume(channel, thread_ts):
    """Release the claim, so the next round of parks in this thread can resume."""
    with _LOCK:
        _RESUMING.discard((channel, thread_ts))


def pending_in(channel, thread_ts):
    """How many requests are still parked in this thread (#169).

    A turn can park several commands, and each gets its own card. Resuming the
    turn on the first click would start a turn per click, in the same thread,
    each one seeing a different half of the outcome -- so the ingest asks this
    and resumes only when the answer is 0. A request being run right now is
    held, which means it is out of _PENDING entirely (#105) and correctly not
    counted here: the click that is resolving it is the one asking."""
    with _LOCK:
        retval = sum(1 for req in _PENDING.values()
                     if req.get("channel") == channel and req.get("thread_ts") == thread_ts)
    return retval


def claim_unsurfaced(channel, thread_ts=None):
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
                # Where it was surfaced, so pending_in() can answer "is this
                # thread still waiting on anything?" (#169). Recorded here
                # rather than at add() because the queue is ingest-agnostic:
                # add() is called from the tool loop, which has no thread.
                req["thread_ts"] = thread_ts
                out.append((key, req))
    retval = out
    return retval


def unsurface(key):
    """The ingest could not post the card (#129 review): make the request
    eligible for another one on the next mention, rather than pending with no
    surface and no id anyone was ever shown."""
    with _LOCK:
        req = _PENDING.get(canonical(key))
        if req is not None:
            req["surfaced"] = False


def pop(key, channel):
    """Claim and consume a request in one step: acquire() then finish().

    Returns None for a request that is held by another surface (#105) exactly
    as for one that is absent -- callers that need to tell those apart ask
    status(). Kept as the composite because "take it and run it" is still the
    common shape for a caller that owns no card."""
    req = acquire(key, channel)
    if req is not None:
        finish(key)
    retval = req
    return retval


def acquire(key, channel):
    """Take ownership of a request, or return None.

    The request MOVES out of _PENDING (#105): while a surface holds it, no
    other consumer can pop it, approve it by text, or evict it on overflow --
    they see "held", not "gone", and the log cannot end up with one surface
    saying the command ran while another says there was nothing to run. That
    was #103's hold made advisory; this is it made authoritative.

    The caller owes exactly one of finish() -- the request is consumed, on the
    same pop-before-execute rule as before -- or release(), which puts it back
    pending, the retryable direction. release() after finish() is a no-op, so
    a finally: release() around a body that finishes on success is correct.

    Logged here as the claim: this is now the moment a request leaves the
    queue, and the log's job is to record that exactly once (#94). Logged
    before the move for the reason the old pop() logged before its delete:
    scrub() is fail-closed, and failing here leaves the request parked."""
    with _LOCK:
        k = canonical(key)
        req = _PENDING.get(k)
        if req is None or req.get("channel") != channel or k in _INFLIGHT:
            retval = None
        else:
            logging.info("approvals: claimed [%s] in %s: %s", k, channel, repr(redact.scrub(req["command"])))
            del _PENDING[k]
            _INFLIGHT[k] = req
            retval = req
    return retval


def finish(key):
    """Consume a held request for good. The counterpart of acquire(); called
    before the command runs, preserving the old pop-then-execute semantics."""
    with _LOCK:
        _INFLIGHT.pop(canonical(key), None)


def status(key, channel):
    """One locked snapshot of a request: ("held"|"pending"|"absent", req|None).

    Read in a single acquisition rather than peek() and then held(), so a
    surface can never render a state that never existed -- pending according to
    one call and not held according to the next, because a click landed in
    between. It can still go stale on the way to Slack; nothing about a live
    queue is instantaneously true. What it must not be is self-contradictory.

    "held" is asked first because a held request lives in _INFLIGHT, not
    _PENDING (#105), for the whole duration of the run. Unlike before, "held"
    now comes WITH the request, so a surface that must name the command -- a
    refused click during a run (#94) -- can. Channel-scoped throughout: an id
    is unique per boot (#109), so the scope is no longer what keeps two
    channels' requests apart -- it is the separate guarantee that an approval
    raised in one channel is answerable only there (#107).
    """
    with _LOCK:
        k = canonical(key)
        held = _INFLIGHT.get(k)
        if held is not None and held.get("channel") == channel:
            retval = ("held", held)
            return retval
        req = _PENDING.get(k)
        if req is not None and req.get("channel") != channel:
            req = None
        if req is not None:
            retval = ("pending", req)
        else:
            retval = ("absent", None)
    return retval


def release(key):
    """Put a held request back in the queue -- the surface could not or did
    not act on it. No-op after finish() and for a key never acquired, so a
    finally: release() is always safe. `surfaced` is left as it was: the card
    that acquired it is still standing."""
    with _LOCK:
        k = canonical(key)
        req = _INFLIGHT.pop(k, None)
        if req is not None:
            _PENDING[k] = req


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
    """Outstanding request keys, optionally only this channel's. The keys as
    they are, which is also what every surface shows a human (#109) -- there is
    no second, shorter form of an id to render or to type."""
    with _LOCK:
        retval = [
            k for k, v in list(_PENDING.items())
            if channel is None or v.get("channel") == channel
        ]
    return retval
