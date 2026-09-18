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

# The bar, written once (#211). It reaches the model twice -- as this tool's
# description, and as a block in the system prompt where it is in view while the
# answer is being composed. Two copies that must agree is how they stop agreeing,
# so there is one string and both readers get it verbatim.
#
# What the first real run exposed: the feature promises an end-of-turn
# self-check, and there is no such thing. `flag_skill` is a tool called during
# composition, so a judgment about the turn's conclusion is being asked for
# through a mechanism that runs before the conclusion exists. The bar cannot
# create the missing hook, but it can stop describing the wrong subject -- the
# old text named three shapes, all of them things you DO, and the turn it missed
# was one where the agent mostly read three facts and thought.
_BAR = (
    "Flag the work in THIS thread as worth turning into a reusable skill, so a "
    "trusted user can decide. At most once per thread, at the end of a turn.\n"
    "Judge the turn's CONCLUSION, not the tool calls that produced it. A turn "
    "that ran no commands and reasoned its way to a general rule can meet the "
    "bar; a turn that ran ten and answered a routine question does not.\n"
    "Shapes that meet it:\n"
    "- non-obvious investigation or debugging;\n"
    "- a workaround found by trial and error;\n"
    "- a project quirk the docs do not cover;\n"
    "- your earlier answer in this thread was wrong and you now know why. This "
    "is the STRONGEST shape, not the weakest: the thread now holds both the "
    "wrong belief and the evidence that corrected it, which is exactly what "
    "someone hitting the same thing next would need. Do not skip it because the "
    "correction came from facts a user handed you -- what is worth writing down "
    "is the rule you derived, not who supplied the input.\n"
    "Routine work, a documentation lookup, or an answer you already knew is not "
    "a skill.\n"
    "If someone asks why you did NOT flag something, answer that question. Do "
    "not flag in place of answering: a card produced on request is a card on "
    "demand, which is the one thing this must not be.\n"
    "Flagging writes nothing: it posts a card tagging the trusted users, who "
    "may open the PR or decline."
)


def prompt_block():
    """The bar, for the system prompt (#211).

    In view while the answer is being composed, rather than only in a tool
    description the model reads when it is already deciding to call something.
    Reference, not instruction to obey blindly -- and unlike the memory block
    (#140) this one is authored here, not by a channel, so it needs no
    not-instructions fence."""
    retval = "## When to flag this thread as a skill\n\n" + _BAR
    return retval


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "flag_skill",
            "description": _BAR,
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


# Scope is a property of the SKILL, not of where it was learned (#210). The
# first real run landed a generic GitHub mechanism -- nothing in it about the
# channel, the company or any private host -- under `channels/m-and-a/skills/`,
# where only that channel would ever see it and the private catalog fills up
# with things that are not private. #130 chose per-channel storage to solve
# #52's envelope leak, which is right for a skill that IS channel-scoped and
# wrong as the default for one whose content is generic.
#
# So the draft is classified and the card shows the proposed scope. The
# classifier only proposes: the trusted click is still the gate, and a trusted
# user overrides in words through propose_skill's `scope`.
SCOPES = ("channel", "shared")

# What makes a skill channel-scoped: something in it that only means anything
# here. Deliberately crude and deliberately biased towards `channel` -- a
# private skill in the private catalog is the status quo and costs a re-learn,
# while a channel-specific one proposed as shared is an envelope leak, which is
# the thing #52 was about. "Could not tell" resolves to the narrower answer.
_PRIVATE_HINTS = re.compile(
    r"""(
        \b(?:\d{1,3}\.){3}\d{1,3}\b            # an address
      | \b[A-Za-z0-9-]+\.(?:internal|local|corp|lan|priv|intranet)\b
      | \b(?:arn:aws|acct|account[-_ ]?id)\b
      | \b[0-9]{12}\b                           # an aws account id
      | \bi-[0-9a-f]{8,}\b | \bvpc-[0-9a-f]{6,}\b | \bsg-[0-9a-f]{6,}\b
      | \bU[A-Z0-9]{8,}\b | \bC[A-Z0-9]{8,}\b   # slack user / channel ids
      | /Users/[A-Za-z0-9._-]+                  # somebody's home directory
    )""",
    re.X,
)


def classify_scope(name, why, channel):
    """(scope, reason). Which catalog this belongs in, and why -- the reason is
    shown on the card, because a proposal a human cannot check is a proposal
    they have to take on faith."""
    hay = f"{name} {why}"
    hit = _PRIVATE_HINTS.search(hay)
    if hit:
        retval = ("channel", f"names something specific to here ({hit.group(0)[:40]})")
        return retval
    slug = channel_slug(channel)
    if slug and slug in hay.lower():
        retval = ("channel", f"names this channel ({slug})")
        return retval
    retval = ("shared", "nothing channel-specific found in the name or reason")
    return retval


def amend_candidate(name, why, channel):
    """An existing skill this might amend, or None (#210).

    The first real run drafted a sibling of a public skill that already covered
    the same ground, because nothing looked. This searches what this instance
    can actually see -- the loaded index -- and matches on the name's words. It
    does NOT reach the public skillz catalog: that needs a network call from the
    host process, and a missed duplicate costs a review comment while a new
    fetch path costs a review of its own."""
    words = {w for w in name.split("-") if len(w) > 3}
    if not words:
        return None
    best, score = None, 0
    for entry in skills.view(channel):
        hay = f"{entry.get('name', '')} {entry.get('summary', '')}".lower()
        n = sum(1 for w in words if w in hay)
        if n > score:
            best, score = entry, n
    # Two shared significant words is the bar. One is a coincidence ("github"),
    # and requiring the whole name back would only ever match itself.
    retval = best if score >= 2 else None
    return retval


def shared_path():
    """Where an every-channel skill lands (#210).

    Configured, not derived. The first cut of this stripped the `{channel}`
    segment out of `learning.path`, which turned
    `channels/{channel}/skills/...` into `channels/skills/...` -- keeping a
    prefix that existed only to hold the channel. The deeper problem is that
    the destination is not a function of the per-channel template at all: it is
    whichever directory the operator has on the consuming side's global
    `skills.paths`, and this process cannot know that. So it is a key, with a
    default that needs no action."""
    retval = config.LEARNING_SHARED_PATH
    return retval


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
    scope, reason = classify_scope(name, why, channel)
    amend = amend_candidate(name, why, channel)
    key = proposals.add(name, why, channel, thread_ts, ctx.get("user_id"),
                        scope=scope, scope_reason=reason,
                        amends=(amend or {}).get("name"))
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


RETRY = "RETRY:"


def _optional(api, path):
    """GET that reads a 404 as None, for the resume checks in open_pr."""
    try:
        retval = api("GET", path)
    except RuntimeError as exc:
        if "404" not in str(exc):
            raise
        retval = None
    return retval


def open_pr(key, name, channel, text, body, api=_gh, scope="channel"):
    """Branch, file and PR in learning.repo. Returns the PR URL.

    Resumable, keyed on the proposal id: a retry after a failure part-way
    (branch made, file not; file made, PR not) finds what exists and
    continues, so a transient error never strands a half-made proposal or
    makes a second branch for the same one."""
    repo, base = config.LEARNING_REPO, config.LEARNING_BASE
    cslug = channel_slug(channel)
    # Scope picks the destination inside the same catalog (#210): the
    # per-channel path, or the same template with the channel segment removed.
    template = config.LEARNING_PATH if scope == "channel" else shared_path()
    path = template.format(channel=cslug, name=name)
    # The branch keeps the channel either way -- it is provenance, not
    # destination, and two channels learning the same shared skill must not
    # collide on one branch name.
    branch = f"skill/{cslug}/{name}-{proposals.canonical(key)}"
    if _optional(api, f"repos/{repo}/git/ref/heads/{branch}") is None:
        sha = api("GET", f"repos/{repo}/git/ref/heads/{base}")["object"]["sha"]
        api("POST", f"repos/{repo}/git/refs", {"ref": f"refs/heads/{branch}", "sha": sha})
    existing = _optional(api, f"repos/{repo}/contents/{path}?ref={branch}")
    put = {
        "message": f"skill: {name} ({cslug})",
        "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
        "branch": branch,
    }
    if existing and existing.get("sha"):
        put["sha"] = existing["sha"]
    api("PUT", f"repos/{repo}/contents/{path}", put)
    owner = repo.split("/", 1)[0]
    open_prs = _optional(api, f"repos/{repo}/pulls?head={owner}:{branch}&state=open") or []
    if open_prs:
        retval = open_prs[0].get("html_url", "")
        return retval
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


def propose(key, ctx, api=_gh, scope=None):
    """A trusted user said yes, by text: acquire, then the acquired core.
    Trust is the caller's check (admin_tools), the same as approve_command.

    `scope` overrides what the classifier proposed at flag time (#210). The
    classifier only ever proposes; this is the override, and it arrives in
    words ("open it for every channel") rather than as another button, so the
    click path that approvals and proposals share does not grow a third
    action."""
    channel = ctx.get("channel")
    k = proposals.canonical(key)
    prop = proposals.acquire(k, channel)
    if prop is None:
        if proposals.status(k, channel)[0] == "held":
            retval = (f"[{k}] is already being acted on by another surface -- do not "
                      f"retry; that surface will report the outcome.")
            return retval
        parked = len(proposals.ids(channel))
        also = f" {parked} other proposal(s) are parked here." if parked else ""
        retval = f"no pending skill proposal '{k}' in this channel.{also}"
        return retval
    try:
        retval = propose_acquired(k, prop, ctx, api=api, scope=scope)
    finally:
        proposals.release(k)
    return retval


def propose_acquired(key, prop, ctx, api=_gh, scope=None):
    """The work, for a proposal the caller owns (#105). On a transient failure
    the proposal goes back under the SAME id via restore(); on success it is
    consumed with finish()."""
    channel = ctx.get("channel")
    name, why, thread_ts = prop["name"], prop["why"], prop["thread_ts"]
    # What the classifier proposed, unless a trusted user said otherwise. An
    # unrecognised value is ignored rather than guessed at: it would pick a
    # destination nobody asked for, and the proposed one is on the card.
    _scope = scope if scope in SCOPES else prop.get("scope", "channel")
    # Every failure below is one that may not repeat -- the waterfall was
    # down, the record file was not there yet, GitHub blinked -- so none of
    # them is a decline. The proposal goes back under the SAME id and the
    # card is re-rendered with its buttons; only a trusted user's Decline
    # closes a thread.
    text, err = draft(name, why, channel, thread_ts)
    if err:
        proposals.restore(key, prop)
        retval = f"{RETRY} could not draft `{name}`: {err}. Nothing was written; the proposal is still open."
        return retval
    meta, _body = skills._parse_text(text)
    if meta is None or not meta.get("name") or not meta.get("description"):
        proposals.restore(key, prop)
        retval = f"{RETRY} the draft for `{name}` had no usable frontmatter; nothing was written, the proposal is still open."
        return retval
    link = _permalink({**ctx, "thread_ts": thread_ts})
    body = (
        f"Proposed from a shmobster turn in `#{channel_slug(channel)}`, flagged by the agent "
        f"and opened by <@{ctx.get('user_id')}>.\n\n**Why:** {why}\n\n"
        + (f"**Thread:** {link}\n\n" if link else "")
        + (f"**Scope:** {'this channel only' if _scope == 'channel' else 'every channel'}"
           + (f" -- {prop.get('scope_reason')}" if prop.get("scope_reason") else "")
           + (f", overridden by <@{ctx.get('user_id')}>" if scope in SCOPES else "") + "\n\n")
        + (f"**May amend:** `{prop['amends']}` -- check whether this belongs as a section there "
           f"rather than as a new file.\n\n" if prop.get("amends") else "")
        + "Merging this PR is what makes the skill load (learning L1, #130); until then it is a proposal.\n\n"
        "Provenance: shmobster #129."
    )
    try:
        url = open_pr(key, name, channel, text, redact.scrub(body), api=api, scope=_scope)
    except Exception as exc:  # noqa: BLE001
        logging.exception("learning: could not open the PR for %s", name)
        proposals.restore(key, prop)
        retval = f"{RETRY} could not open the PR for `{name}`: {redact.scrub(str(exc))[:300]}. The proposal is still open; a retry resumes where this stopped."
        return retval
    proposals.finish(key)
    mark_thread(thread_ts, "proposed")
    logging.info("learning: PR opened for %s in %s by %s: %s", name, channel, ctx.get("user_id"), url)
    _where = "this channel only" if _scope == "channel" else "every channel"
    retval = (f"PR opened by <@{ctx.get('user_id')}> for `{name}` ({_where}): {url}\n"
              f"Merging it is the promotion; nothing loads until then.")
    return retval


def decline_acquired(key, prop, ctx):
    proposals.finish(key)
    mark_thread(prop["thread_ts"], "declined")
    retval = f"DECLINED by <@{ctx.get('user_id')}>: `{prop['name']}` -- this thread will not be asked again."
    return retval


def decline(key, ctx):
    channel = ctx.get("channel")
    k = proposals.canonical(key)
    prop = proposals.acquire(k, channel)
    if prop is None:
        if proposals.status(k, channel)[0] == "held":
            retval = f"[{k}] is already being acted on by another surface -- do not retry."
            return retval
        retval = f"no pending skill proposal '{k}' in this channel."
        return retval
    try:
        retval = decline_acquired(k, prop, ctx)
    finally:
        proposals.release(k)
    return retval


def dispatch(name, args, ctx):
    if name == "flag_skill":
        retval = flag(args, ctx)
    else:
        retval = f"unknown learning tool: {name}"
    return retval
