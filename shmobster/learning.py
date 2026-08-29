"""Learning L0 (#129): the agent flags, a trusted user decides, a PR is the
proposal, a merge is the promotion.

Design in #100 and #52 -- learning inherits the authz spine. What that means
here:

- flag_skill is the one tool the model may call on its own initiative. It
  parks a proposal (proposals.py) and the ingest posts a card tagging the
  trusted users. Nothing is drafted or written by a flag.
- propose_skill / decline_skill act on a parked proposal and are trusted-only,
  like approve_command. propose_skill reads the thread's trajectory back
  (trajectory.py), asks the waterfall for a SKILL.md in the skillz format, and
  opens a PR against `learning.repo` under `learning.path` -- through `gh api`
  from THIS process, never from the channel's shell: the sandbox (#116)
  confines a channel to its tree, and the model must not gain a push path to
  the skills repo. The PR is the record; a human merging it is the promotion.
- One flag per thread, and a declined or proposed thread is not asked again
  (state.py, keyed on thread ts), so the card cannot become a nag.

A skill loaded later carries no authority: it is prompt text, and whatever it
does still goes through run_shell -> YOLT -> grant -> sandbox -> approval."""
import base64
import datetime
import json
import logging
import re
import subprocess

from . import config, llm, proposals, redact, skills, state, trajectory

_STATE_KEY = "skill_threads"
_STATE_MAX = 500
_SLUG = re.compile(r"[^a-z0-9-]+")

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "flag_skill",
            "description": (
                "Flag the work in THIS thread as worth turning into a reusable skill, "
                "so a trusted user can decide. Call it at most once per thread, at "
                "the end of a turn, and only when the work met the bar: it needed "
                "non-obvious investigation or debugging, a workaround found by "
                "trial and error, or a project quirk the docs do not cover -- and "
                "someone facing the same thing again would be faster for having it "
                "written down. Routine work, a documentation lookup, or an answer "
                "you already knew is not a skill. Flagging writes nothing: it posts "
                "a card tagging the trusted users, who may open the PR or decline."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Proposed skill name, kebab-case, specific (e.g. 'launchd-bootstrap-io-error-race')."},
                    "why": {"type": "string", "description": "One line: what was non-obvious and what the skill would save next time."},
                },
                "required": ["name", "why"],
            },
        },
    },
]

NAMES = {t["function"]["name"] for t in TOOLS}


def enabled():
    retval = bool(config.LEARNING_REPO)
    return retval


def _slug(text):
    retval = _SLUG.sub("-", str(text or "").strip().lower()).strip("-") or "unnamed"
    return retval


def channel_slug(channel):
    retval = _slug(config.CHANNEL_NAMES.get(channel) or channel)
    return retval


def thread_state(thread_ts):
    retval = (state.get(_STATE_KEY) or {}).get(str(thread_ts))
    return retval


def mark_thread(thread_ts, status):
    data = state.get(_STATE_KEY) or {}
    data[str(thread_ts)] = status
    while len(data) > _STATE_MAX:
        del data[next(iter(data))]
    state.put(_STATE_KEY, data)


def flag(args, ctx):
    """The model's flag. Parks a proposal for the ingest to render; refuses a
    second flag on a thread that already has one, or was declined."""
    if not enabled():
        retval = "learning is not configured on this instance (learning.repo); nothing flagged."
        return retval
    channel, thread_ts = ctx.get("channel"), ctx.get("thread_ts")
    if not (channel and thread_ts):
        retval = "flag_skill needs a channel thread; nothing flagged."
        return retval
    prior = thread_state(thread_ts)
    if prior:
        retval = f"this thread was already {prior} as a skill candidate; not asking again."
        return retval
    name = _slug(args.get("name"))
    why = " ".join(str(args.get("why") or "").split())[:300]
    key = proposals.add(name, why, channel, thread_ts, ctx.get("user_id"))
    mark_thread(thread_ts, "flagged")
    retval = (
        f"flagged [{key}] `{name}` -- a card tagging the trusted users will follow "
        f"this reply. Do not draft the skill yourself; a trusted user opens the PR or declines."
    )
    return retval


_DRAFT_SYSTEM = """You write one SKILL.md in the skillz format from the record of a
Slack agent turn. Output ONLY the file text, no code fence, no commentary.

Format:
---
name: <kebab-case name>
description: |
  <2-5 lines: exact use cases and trigger conditions -- error messages,
  symptoms, contexts -- so a search would surface it when relevant>
author: shmobster
version: 1.0.0
date: <YYYY-MM-DD>
---
# <Title>

## Problem
## Context / Trigger Conditions
## Solution
## Verification
## Notes

Rules: describe the technique, not the incident. Replace account ids, hostnames,
tokens, customer names and absolute home paths with placeholders like
<account-id>, <host>, <project>. Keep commands exactly as they were run when
they are the point. If the record does not support a reusable procedure, say so
in the Notes section rather than inventing steps."""


def draft(name, why, channel, thread_ts):
    """A SKILL.md from the thread's trajectory, via the waterfall. Returns
    (text, error)."""
    records = trajectory.thread(channel, thread_ts)
    if not records:
        retval = (None, "no trajectory records for this thread")
        return retval
    today = datetime.date.today().isoformat()
    payload = json.dumps(records, ensure_ascii=False)[:60000]
    messages = [
        {"role": "system", "content": _DRAFT_SYSTEM},
        {"role": "user", "content": (
            f"Skill name: {name}\nWhy it is worth a skill: {why}\nDate: {today}\n"
            f"Channel: {channel_slug(channel)}\n\nTurn records (JSON, oldest first):\n{payload}"
        )},
    ]
    try:
        text = (llm.complete(messages).content or "").strip()
    except Exception as exc:  # noqa: BLE001
        retval = (None, f"draft failed: {exc}")
        return retval
    text = re.sub(r"^```[a-z]*\n|\n```$", "", text).strip() + "\n"
    if not text.startswith("---"):
        retval = (None, "draft did not start with frontmatter")
        return retval
    retval = (redact.scrub(text), None)
    return retval


def _gh(method, path, payload=None):
    """One GitHub API call through gh, which holds the operator's token in the
    keychain. Raises RuntimeError with gh's (scrubbed) stderr on failure."""
    argv = ["gh", "api", "--method", method, path]
    stdin = None
    if payload is not None:
        argv += ["--input", "-"]
        stdin = json.dumps(payload)
    proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"gh api {method} {path}: {redact.scrub(proc.stderr.strip())[:300]}")
    retval = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return retval


def open_pr(name, channel, text, body, api=_gh):
    """Branch, file and PR in learning.repo. Returns the PR URL."""
    repo, base = config.LEARNING_REPO, config.LEARNING_BASE
    cslug = channel_slug(channel)
    path = config.LEARNING_PATH.format(channel=cslug, name=name)
    branch = f"skill/{cslug}/{name}-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M')}"
    sha = api("GET", f"repos/{repo}/git/ref/heads/{base}")["object"]["sha"]
    api("POST", f"repos/{repo}/git/refs", {"ref": f"refs/heads/{branch}", "sha": sha})
    api("PUT", f"repos/{repo}/contents/{path}", {
        "message": f"skill: {name} ({cslug})",
        "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
        "branch": branch,
    })
    pr = api("POST", f"repos/{repo}/pulls", {
        "title": f"skill: {name} ({cslug})", "head": branch, "base": base, "body": body,
    })
    retval = pr.get("html_url", "")
    return retval


def _permalink(ctx):
    client, channel, thread_ts = ctx.get("client"), ctx.get("channel"), ctx.get("thread_ts")
    retval = ""
    if client and channel and thread_ts:
        try:
            retval = client.chat_getPermalink(channel=channel, message_ts=thread_ts).get("permalink", "")
        except Exception:  # noqa: BLE001
            retval = ""
    return retval


def propose(key, ctx, api=_gh):
    """A trusted user said yes: draft from the trajectory and open the PR.
    Trust is the caller's check (admin_tools), the same as approve_command."""
    channel = ctx.get("channel")
    prop = proposals.pop(key, channel)
    if prop is None:
        parked = len(proposals.ids(channel))
        also = f" {parked} other proposal(s) are parked here." if parked else ""
        retval = f"no pending skill proposal '{proposals.canonical(key)}' in this channel.{also}"
        return retval
    name, why, thread_ts = prop["name"], prop["why"], prop["thread_ts"]
    text, err = draft(name, why, channel, thread_ts)
    if err:
        mark_thread(thread_ts, "declined")
        retval = f"could not draft `{name}`: {err}. Nothing was written; the thread will not be asked again."
        return retval
    meta, _body = skills._parse_text(text)
    if meta is None or not meta.get("name") or not meta.get("description"):
        mark_thread(thread_ts, "declined")
        retval = f"the draft for `{name}` had no parseable frontmatter; nothing was written."
        return retval
    link = _permalink({**ctx, "thread_ts": thread_ts})
    body = (
        f"Proposed from a shmobster turn in `#{channel_slug(channel)}`, flagged by the agent "
        f"and opened by <@{ctx.get('user_id')}>.\n\n**Why:** {why}\n\n"
        + (f"**Thread:** {link}\n\n" if link else "")
        + "Merging this PR is what makes the skill load (learning L1, #130); until then it is a proposal.\n\n"
        "Provenance: shmobster #129."
    )
    try:
        url = open_pr(name, channel, text, redact.scrub(body), api=api)
    except Exception as exc:  # noqa: BLE001
        logging.exception("learning: could not open the PR for %s", name)
        mark_thread(thread_ts, "flagged")
        proposals.add(name, why, channel, thread_ts, prop.get("user_id"))
        retval = f"could not open the PR for `{name}`: {redact.scrub(str(exc))[:300]}. The proposal is parked again."
        return retval
    mark_thread(thread_ts, "proposed")
    logging.info("learning: PR opened for %s in %s by %s: %s", name, channel, ctx.get("user_id"), url)
    retval = f"PR opened by <@{ctx.get('user_id')}> for `{name}`: {url}\nMerging it is the promotion; nothing loads until then."
    return retval


def decline(key, ctx):
    channel = ctx.get("channel")
    prop = proposals.pop(key, channel)
    if prop is None:
        retval = f"no pending skill proposal '{proposals.canonical(key)}' in this channel."
        return retval
    mark_thread(prop["thread_ts"], "declined")
    retval = f"DECLINED by <@{ctx.get('user_id')}>: `{prop['name']}` -- this thread will not be asked again."
    return retval


def dispatch(name, args, ctx):
    if name == "flag_skill":
        retval = flag(args, ctx)
    else:
        retval = f"unknown learning tool: {name}"
    return retval
