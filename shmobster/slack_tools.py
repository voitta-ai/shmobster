"""Slack-read tools (#28): let the agent fetch context a user references --
other threads, channel history, or a permalinked message -- using the bot's own
Slack client (needs channels:history / groups:history, already granted).

These are only exposed when the ingress provides a Slack client (i.e. the Slack
app). Other ingresses pass client=None and these tools aren't offered.

Every one of them is scoped to the channel the turn is happening in (#151).
They used to take an arbitrary `channel_id` straight to the client, past
`policy.check`, past the grant layer and past the approval card -- so the agent
could read any channel the bot belongs to, and post (or `<@mention>` someone)
into any of them, with no human in the path. Under the injection surface the
rest of this repo is built around -- thread text, attachments, fetched pages --
that is a cross-channel action a stranger can ask for.

So the target defaults to the current channel, and reaching another one
requires the channel's policy to name it in `slack_channels`. That is #149's
shape rather than an approval card's: a fetch to a host outside `allow_domains`
is refused rather than queued, because "may this channel reach that place at
all" is an operator's decision made in advance, not a per-message one. Posting
into another channel is the same question."""
import re

from . import config, identity

_MAX_OUTPUT = 4000
_PERMALINK = re.compile(r"/archives/(C\w+)/p(\d+)")

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "slack_read_thread",
            "description": "Read all messages in a Slack thread (its parent + replies).",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string", "description": "Channel ID (C...). Optional; defaults to this channel. Another channel works only if this channel's policy names it."},
                    "thread_ts": {"type": "string", "description": "Parent message ts."},
                },
                "required": ["thread_ts"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "slack_read_channel",
            "description": "Read recent messages from a Slack channel.",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string", "description": "Channel ID (C...). Optional; defaults to this channel. Another channel works only if this channel's policy names it."},
                    "limit": {"type": "integer", "description": "How many recent messages (default 20)."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "slack_read_permalink",
            "description": "Resolve a Slack message permalink (a .../archives/C.../p... URL) to that message and its thread.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The Slack message permalink."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "slack_post",
            "description": "Post a message to a Slack channel (optionally as a thread reply). Use to proactively message a channel or ping another user -- mention them with <@USERID>. Do NOT use it to deliver your answer to the person who asked: your reply is already posted in the current thread for you, and posting it here as well puts it somewhere they are not looking. If you do post into a thread, pass thread_ts -- without it the message lands in the channel, outside the thread.",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string", "description": "Channel ID (C...) to post to. Optional; defaults to this channel. Another channel works only if this channel's policy names it in slack_channels."},
                    "text": {"type": "string", "description": "Message text. Mention users with <@USERID>."},
                    "thread_ts": {"type": "string", "description": "Optional: post as a reply in this thread."},
                },
                "required": ["text"],
            },
        },
    },
]

NAMES = {t["function"]["name"] for t in TOOLS}


def _fmt(messages):
    lines = []
    for m in messages:
        who = identity.speaker(m)
        text = (m.get("text") or "").strip()
        if text:
            lines.append(f"[{who}] {text}")
    out = "\n".join(lines) or "(no messages)"
    if len(out) > _MAX_OUTPUT:
        out = out[:_MAX_OUTPUT] + "\n...[truncated]"
    return out


def _read_thread(client, channel_id, thread_ts):
    r = client.conversations_replies(channel=channel_id, ts=thread_ts, limit=50)
    return _fmt(r.get("messages", []))


def _read_channel(client, channel_id, limit=20):
    r = client.conversations_history(channel=channel_id, limit=int(limit))
    return _fmt(r.get("messages", []))


def _read_permalink(client, url):
    m = _PERMALINK.search(url or "")
    if not m:
        return "not a Slack archive permalink (expected .../archives/C.../p...)"
    channel_id, digits = m.group(1), m.group(2)
    ts = digits[:-6] + "." + digits[-6:]
    r = client.conversations_replies(channel=channel_id, ts=ts, limit=50)
    return _fmt(r.get("messages", []))


def _scope(target, ctx):
    """(ok, reason) for reaching `target` from this turn. The turn's own channel
    always; any other only when the policy named it."""
    here = (ctx or {}).get("channel")
    if not target or target == here:
        return (True, "")
    named = ((ctx or {}).get("policy") or {}).get("slack_channels") or []
    # A bare string is one id, not a haystack. Written `"slack_channels": "C9"`
    # instead of `["C9"]` -- an easy thing to type -- `target in named` becomes
    # a substring test, and a policy naming `C99999` would admit `C9`. Measured
    # before this line existed: it posted.
    if isinstance(named, str):
        named = [named]
    elif not isinstance(named, (list, tuple, set)):
        named = []
    if target in named:
        return (True, "")
    retval = (
        False,
        f"refusing to reach {target}: this turn is in {here or 'no channel'}, and "
        f"{target} is not in this channel's slack_channels policy",
    )
    return retval


def _marker():
    if config.AGENT_LABEL:
        return f":robot_face: [agent: {config.AGENT_LABEL}]"
    return ":robot_face: [agent]"


def _post(client, channel_id, text, thread_ts=None):
    r = client.chat_postMessage(
        channel=channel_id, text=f"{_marker()} {text}", thread_ts=thread_ts or None
    )
    if r.get("ok"):
        return f"posted to {channel_id} (ts {r.get('ts')})"
    return f"post failed: {r.get('error')}"


def dispatch(name, args, client, ctx=None):
    if client is None:
        return "no slack client available in this context"
    here = (ctx or {}).get("channel")
    # An omitted channel_id means "here", which is what the model should be
    # asking for nearly always. A named one still has to clear the scope check;
    # defaulting is a convenience, not the gate.
    target = args.get("channel_id") or here
    try:
        if name == "slack_read_permalink":
            # The target is inside the URL rather than in an argument, so it is
            # parsed first and checked like any other (#151).
            url = args.get("url", "")
            m = _PERMALINK.search(url or "")
            if not m:
                return "not a Slack archive permalink (expected .../archives/C.../p...)"
            ok, why = _scope(m.group(1), ctx)
            if not ok:
                return why
            return _read_permalink(client, url)
        # "Is there a target at all" before "may we reach it": a falsy target
        # never reached the client either way, but the order said otherwise to
        # anyone reading it.
        if not target:
            return f"{name}: no channel_id given and this turn is not in a channel"
        ok, why = _scope(target, ctx)
        if not ok:
            return why
        if name == "slack_read_thread":
            retval = _read_thread(client, target, args.get("thread_ts", ""))
        elif name == "slack_read_channel":
            retval = _read_channel(client, target, args.get("limit", 20))
        elif name == "slack_post":
            retval = _post(client, target, args.get("text", ""), args.get("thread_ts"))
        else:
            retval = f"unknown slack tool: {name}"
    except Exception as exc:
        retval = f"slack read error: {exc}"
    return retval
