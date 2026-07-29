"""Slack-read tools (#28): let the agent fetch context a user references --
other threads, channel history, or a permalinked message -- using the bot's own
Slack client (needs channels:history / groups:history, already granted).

These are only exposed when the ingress provides a Slack client (i.e. the Slack
app). Other ingresses pass client=None and these tools aren't offered."""
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
                    "channel_id": {"type": "string", "description": "Channel ID (C...)."},
                    "thread_ts": {"type": "string", "description": "Parent message ts."},
                },
                "required": ["channel_id", "thread_ts"],
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
                    "channel_id": {"type": "string", "description": "Channel ID (C...)."},
                    "limit": {"type": "integer", "description": "How many recent messages (default 20)."},
                },
                "required": ["channel_id"],
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
            "description": "Post a message to a Slack channel (optionally as a thread reply). Use to proactively message a channel or ping another user -- mention them with <@USERID>.",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string", "description": "Channel ID (C...) to post to."},
                    "text": {"type": "string", "description": "Message text. Mention users with <@USERID>."},
                    "thread_ts": {"type": "string", "description": "Optional: post as a reply in this thread."},
                },
                "required": ["channel_id", "text"],
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


def dispatch(name, args, client):
    if client is None:
        return "no slack client available in this context"
    try:
        if name == "slack_read_thread":
            retval = _read_thread(client, args.get("channel_id", ""), args.get("thread_ts", ""))
        elif name == "slack_read_channel":
            retval = _read_channel(client, args.get("channel_id", ""), args.get("limit", 20))
        elif name == "slack_read_permalink":
            retval = _read_permalink(client, args.get("url", ""))
        elif name == "slack_post":
            retval = _post(client, args.get("channel_id", ""), args.get("text", ""), args.get("thread_ts"))
        else:
            retval = f"unknown slack tool: {name}"
    except Exception as exc:
        retval = f"slack read error: {exc}"
    return retval
