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
        else:
            retval = "ran"
    elif head.startswith("APPROVED"):
        retval = "approved"
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


def record(channel, user_id, thread_ts, text, steps, answer):
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
