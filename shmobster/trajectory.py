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
import re
import threading

from . import redact

_DIR = os.getenv("SHMOBSTER_TRAJECTORIES", "trajectories")
# `tools.execute`'s marker for a non-zero exit, at the start of a line so a
# command whose own output quotes the word is not read as a failure.
_FAILED_LINE = re.compile(r"(?:^|\n)FAILED \(exit ")
_LOCK = threading.Lock()
_ARGS_MAX = 1000
_RESULT_MAX = 600
_TEXT_MAX = 4000


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
        elif head.startswith("FAILED"):
            # Ran and exited non-zero (#233). Separate from "error", which is
            # this agent failing to run it at all, and from "ran": a turn that
            # cited a failed command as its source is the thing the learning
            # loop has to be able to see afterwards.
            retval = "failed"
        else:
            retval = "ran"
    elif head.startswith("APPROVED"):
        # An approved command that then failed is two facts, and the record
        # kept only the first: `run_approved` leads with its own approval
        # header, so the failure marker sits on the next line where a head-only
        # check cannot see it. The highest-risk commands are exactly the ones
        # that reach here (#233).
        retval = "approved-failed" if _FAILED_LINE.search(result or "") else "approved"
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
