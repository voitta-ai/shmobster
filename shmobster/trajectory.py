"""Per-turn trajectory record (#129): what a turn asked, ran, and answered.

The capture half of the learning loop (#100, design in #52): structured
logging of the thing every other gate already sees. One JSON line per turn --
channel, user, thread, the request, every tool call with its disposition
(ran / parked / blocked / approved / ok) and the head of its result, the final
answer. propose_skill reads a thread's records back to draft a SKILL.md from
what actually happened rather than from the model's memory of it.

Every string is scrubbed here, at the emission site, for the reason approvals
gives (#94): a command line carries credentials routinely, and this file is
durable in a way the thread is not.

Lives under `trajectories/<channel>/<YYYY-MM-DD>.jsonl`, gitignored --
`workspace/` is committed, so not there. Path from SHMOBSTER_TRAJECTORIES."""
import datetime
import glob
import json
import logging
import os
import threading

from . import redact

_DIR = os.getenv("SHMOBSTER_TRAJECTORIES", "trajectories")
_LOCK = threading.Lock()
_ARGS_MAX = 1000
_RESULT_MAX = 600
_TEXT_MAX = 4000


# How a non-zero exit is spelled, in one place (#233). Three readers care -- the
# model, this module's disposition, and the resume path's "it ran" -- and three
# independent substring matches is how they stop agreeing.
#
# It lives here rather than in tools because tools already imports this module,
# and because this is where a result's text is turned into what it means.
FAILED_PREFIX = "FAILED (exit "


def failed(result):
    """Whether a run_shell result records a non-zero exit.

    A containment check rather than a prefix one, because the resume path sees
    this wrapped: `run_approved` returns "APPROVED by <@u> and ran: <cmd>\n<out>"
    and the marker sits after the command line.

    That makes a false positive possible -- output that quotes the marker
    verbatim -- and that is the direction to be wrong in. Claiming a failure
    that did not happen is visible in the next line of output and costs a
    re-read; missing one is the bug this exists to fix."""
    retval = FAILED_PREFIX in (result or "")
    return retval


def disposition(tool, result):
    """What happened to one tool call, from the text it returned. run_shell
    says so in its first words; every other tool either answered or refused."""
    head = (result or "")[:40]
    if tool == "run_shell":
        if head.startswith("NOT RUN"):
            retval = "parked"
        elif head.startswith("BLOCKED"):
            retval = "blocked"
        elif head.startswith("exec error"):
            retval = "error"
        elif failed(result):
            # Ran and exited non-zero, which used to record as "ran" like any
            # other (#233). "error" is kept for the cases where the command
            # never started -- a timeout, a sandbox that would not wrap -- so a
            # reader can still tell "we could not run it" from "it ran and
            # said no".
            retval = "failed"
        else:
            retval = "ran"
    elif head.startswith("APPROVED"):
        # Two facts, and this kept only the first. `run_approved` returns
        # "APPROVED by <@u> and ran: <cmd>\n<out>", so the marker sits where
        # the head check cannot see it -- which `failed()` already describes,
        # having been written for this wrapping. The commands that reach here
        # are the ones a human was asked about, so "it was approved" and "it
        # failed" are both worth recording (#233).
        retval = "approved-failed" if failed(result) else "approved"
    elif head.startswith("REFUSED"):
        retval = "refused"
    else:
        retval = "ok"
    return retval


def step(tool, args, result):
    """One tool call, trimmed and scrubbed, for the record."""
    try:
        args_text = json.dumps(args, ensure_ascii=False)
    except (TypeError, ValueError):
        args_text = str(args)
    retval = {
        "tool": tool,
        "args": redact.scrub(args_text)[:_ARGS_MAX],
        "disposition": disposition(tool, result),
        "result": redact.scrub(result or "")[:_RESULT_MAX],
    }
    return retval


def _path(channel, when):
    retval = os.path.join(_DIR, channel or "none", when.strftime("%Y-%m-%d") + ".jsonl")
    return retval


def record(channel, user_id, thread_ts, text, steps, answer, calls=None, flag_skill=None):
    """Append one turn. Never raises: a turn that cannot be recorded still
    happened, and the reply is on its way to the channel."""
    now = datetime.datetime.now(datetime.timezone.utc)
    rec = {
        "ts": now.isoformat(timespec="seconds"),
        "channel": channel,
        "user": user_id,
        "thread_ts": thread_ts,
        "request": redact.scrub(text if isinstance(text, str) else str(text))[:_TEXT_MAX],
        "steps": steps,
        "answer": redact.scrub(answer or "")[:_TEXT_MAX],
        # What the turn's model calls cost (#190). A turn with none -- an
        # approval resume that never reached the model -- records an empty
        # list rather than being absent, so a reader can tell "no calls" from
        # "recorded before costs existed".
        "calls": list(calls or []),
        # Whether the turn could have flagged and did not (#211). The feature
        # promises a self-check the agent runs on its own initiative, and the
        # first real run skipped the most skill-worthy turn in the thread -- a
        # correction -- flagging only when a trusted user asked. That is
        # indistinguishable from working correctly unless it is written down.
        #
        # Deliberately NOT the model's reason for declining: capturing that
        # would mean asking every turn, which costs a model call per turn to
        # answer "no" almost always. This records the auditable half instead --
        # the tool was in view, the turn did `steps` many tool calls, and no
        # card came of it. A run of those with a high step count is the shape
        # #211 was filed about, and now it is greppable rather than anecdotal.
        "flag_skill": flag_skill or "not offered",
    }
    path = _path(channel, now)
    try:
        with _LOCK:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        retval = True
    except (OSError, TypeError, ValueError):
        logging.exception("trajectory: could not record a turn in %s", channel)
        retval = False
    return retval


def prune(days):
    """Delete day files older than `days`, returning how many went (#155).

    `thread()` reads a 14-day window, so everything behind it was storage
    nobody queries -- and it is not inert storage: a record holds the request
    text, every tool call and the answer, scrubbed but durable. The filename is
    the date, so this needs no parsing of the contents and cannot be confused
    by a clock change mid-file."""
    if not days:
        return 0
    # UTC, because record() names the file in UTC (`now(timezone.utc)` above).
    # A naive local now() here would put the cutoff up to a day out of step with
    # the names it is compared against -- deleting a day early east of UTC and
    # keeping one late west of it.
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    dropped = 0
    for path in glob.glob(os.path.join(_DIR, "*", "*.jsonl")):
        if os.path.basename(path)[:10] >= cutoff:
            continue
        try:
            os.remove(path)
            dropped += 1
        except OSError as exc:
            logging.warning("trajectories: could not remove %s: %s", path, exc)
    retval = dropped
    return retval


def thread(channel, thread_ts, days=14):
    """Every record of one thread, oldest first, from the last `days` files."""
    out = []
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    for path in sorted(glob.glob(os.path.join(_DIR, channel or "none", "*.jsonl"))):
        if os.path.basename(path)[:10] < cutoff:
            continue
        try:
            with open(path, "r") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("thread_ts") == thread_ts:
                        out.append(rec)
        except OSError:
            continue
    retval = out
    return retval


def day(channel, when=None):
    """Every record for one channel on one UTC day, for a rollup (#190)."""
    when = when or datetime.datetime.now(datetime.timezone.utc)
    out = []
    try:
        with open(_path(channel, when), "r") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    retval = out
    return retval
