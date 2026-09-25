"""Who said a Slack message -- me, another agent instance, or a human (#60).

Two instances (e.g. Cosima, Barrymore) can share a workspace and channel, but
each is its own Slack app with a unique bot user id (config.BOT_USER_ID, from
auth.test at startup). Labeling history by that id lets an agent recognize its
own prior posts AND, crucially, see a sibling agent's posts as a *different*
agent rather than as itself -- the mislabeling that was read as impersonation.

Used by both history surfaces: the in-thread context flattener (slack_app) and
the slack_read_* tools (slack_tools) -- and by the ingress, to decide whether a
message event is a turn at all (#23)."""
import re

from . import config

_AGENT_MARKER = re.compile(r"\[agent:\s*([^\]]+)\]")


def _agent_name(m):
    """The agent name a bot message advertises: from its '[agent: X]' marker if
    present, else the Slack bot_profile name, else None."""
    mo = _AGENT_MARKER.search(m.get("text") or "")
    if mo:
        retval = mo.group(1).strip()
        return retval
    retval = (m.get("bot_profile") or {}).get("name")
    return retval


def speaker(m):
    """A short speaker label for one Slack message from THIS instance's point of
    view: '<label> (me)', '<name> (another agent)', or 'user <id>'."""
    uid = m.get("user")
    if config.BOT_USER_ID and uid == config.BOT_USER_ID:
        retval = f"{config.AGENT_LABEL or 'me'} (me)"
        return retval
    if m.get("bot_id"):
        name = _agent_name(m)
        retval = f"{name} (another agent)" if name else f"another agent ({uid or m.get('bot_id')})"
        return retval
    retval = f"user {uid}" if uid else "user"
    return retval


def dm_turn(event):
    """True when this `message` event is a direct message this agent should
    answer (#23).

    In a channel the mention is the address, and answering every message would
    make the agent a participant in conversations nobody asked it into. A DM
    has no one else in it, so the message *is* the address, and requiring
    `@shmobster` in a one-to-one conversation is a tax with nothing on the
    other side.

    The rest is about not talking to ourselves. A reply posted into a DM comes
    back as a `message` event, and an agent that answers its own posts will
    hold both ends of the conversation until the dedup table rolls over. Three
    separate ways that shows up: `bot_id` on anything a bot posted, our own
    `BOT_USER_ID` when the app posts as its user, and a `subtype` for the edits
    and joins and deletions that are not somebody talking."""
    if (event or {}).get("channel_type") != "im":
        return False
    if event.get("bot_id") or event.get("subtype"):
        return False
    # Not knowing who we are is a reason not to answer, not a reason to skip
    # the check. `bot_id` already catches our own posts -- the app posts with a
    # bot token, so Slack sets it -- but that is one guard standing alone, and
    # the failure it would be standing alone against is an agent talking to
    # itself in a loop. The id is resolved before serving; if it is empty,
    # something is wrong enough that DMs can wait. Startup says so.
    if not config.BOT_USER_ID:
        return False
    if event.get("user") == config.BOT_USER_ID:
        return False
    retval = bool(event.get("user"))
    return retval


# Slack's own answer first: a real broadcast arrives as a `broadcast` element
# inside the message's rich-text blocks, with the range it addressed. The text
# form is the fallback for events delivered without blocks, and it is anchored
# -- matching the bare prefix `<!here` would turn `<!here-not-a-broadcast>`, or
# a pasted snippet containing it, into an unsolicited public reply (Codex
# adversarial review, #260).
_BROADCAST_RANGES = frozenset(("here", "channel", "everyone"))
_BROADCAST_RE = re.compile(r"<!(here|channel|everyone)(\|[^>]*)?>")


def broadcast_turn(event):
    """True when this channel `message` is an @here/@channel the agent should
    answer (#260).

    A broadcast is addressed to everyone in the room, and the agent is in the
    room. Requiring `@Cosima` on top of `@here` is the tax #23 removed for
    DMs, one surface over: the operator's words were "the @here message should
    reach Slack", after an @here asking why nothing was happening went to
    everybody except the participant able to answer it.

    Same three ways of not talking to ourselves as `dm_turn`, for the same
    reason -- and one more that matters here: the agent's own replies carry a
    `bot_id`, and an agent that answered its own broadcast would hold both ends
    of a conversation the whole channel can see.

    A mention alongside the broadcast is left to `app_mention`, which Slack
    delivers separately; answering here too would run the turn twice."""
    ev = event or {}
    if ev.get("channel_type") not in ("channel", "group"):
        return False
    if ev.get("bot_id") or ev.get("subtype"):
        return False
    if not config.BOT_USER_ID or ev.get("user") == config.BOT_USER_ID:
        return False
    if not ev.get("user"):
        return False
    text = ev.get("text") or ""
    if config.BOT_USER_ID and f"<@{config.BOT_USER_ID}>" in text:
        return False  # app_mention has this one
    if _has_broadcast_block(ev.get("blocks")):
        retval = True
        return retval
    retval = bool(_BROADCAST_RE.search(text))
    return retval


def _has_broadcast_block(blocks):
    """True when Slack itself marked a broadcast in the message's blocks.

    Walked rather than pattern-matched: the element sits inside
    rich_text -> rich_text_section -> broadcast, and a future nesting should
    read as "found" rather than as "absent"."""
    stack = list(blocks or [])
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        if node.get("type") == "broadcast" and node.get("range") in _BROADCAST_RANGES:
            return True
        for value in node.values():
            if isinstance(value, list):
                stack.extend(value)
    return False
