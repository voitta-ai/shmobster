"""Who said a Slack message -- me, another agent instance, or a human (#60).

Two instances (e.g. Cosima, Barrymore) can share a workspace and channel, but
each is its own Slack app with a unique bot user id (config.BOT_USER_ID, from
auth.test at startup). Labeling history by that id lets an agent recognize its
own prior posts AND, crucially, see a sibling agent's posts as a *different*
agent rather than as itself -- the mislabeling that was read as impersonation.

Used by both history surfaces: the in-thread context flattener (slack_app) and
the slack_read_* tools (slack_tools)."""
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
