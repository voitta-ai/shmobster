"""Where a turn is happening, as the core needs to know it (#336).

The handler, the admin tools and learning used to take a Slack WebClient and
build Slack strings around it: "You are in Slack channel ...", `<@U...>`, a
chat_postMessage for an alert, a chat_getPermalink for a PR body. A second
transport needs the same four things said its own way, and nothing else from
the client. So the core takes a Surface, and only the Slack surface hands out
a client -- for the slack tools, which are Slack by nature and are offered
only there.

The base class is the answer for a surface that cannot do a thing: no
location detail, no self id, an alert that was not delivered, no permalink.
Each of those degrades exactly the way a missing Slack client did before.
"""
from . import config, redact, slack_blocks


class Surface:
    kind = None
    client = None

    def location(self, channel, thread_ts):
        retval = f"You are in conversation {channel}."
        return retval

    def self_line(self):
        return None

    def post(self, channel, thread_ts, text, blocks=None):
        """Post into the conversation; whether it was delivered."""
        return False

    def permalink(self, channel, ts):
        return ""

    def withdrawn(self, channel, thread_ts, req_id, req, note):
        """Retire the card of a request the agent withdrew (#350), so nobody
        approves what is gone. A surface that cannot edit a card says it in
        the conversation instead; a typed answer to the id finds nothing
        either way."""
        retval = self.post(channel, thread_ts, f"[{req_id}] {note}")
        return retval


class SlackSurface(Surface):
    kind = "slack"

    def __init__(self, client):
        self.client = client

    def location(self, channel, thread_ts):
        loc = f"You are in Slack channel {channel}"
        _cname = config.CHANNEL_NAMES.get(channel)
        if _cname:
            loc += f" ({_cname})"
        loc += "."
        if thread_ts:
            loc += f" This thread's ts is {thread_ts}."
        loc += " Use the slack tools with this channel_id to read history or post here."
        retval = loc
        return retval

    def self_line(self):
        if not config.BOT_USER_ID:
            return None
        retval = (
            f"Your Slack user id is {config.BOT_USER_ID}; a message mentioning "
            f"<@{config.BOT_USER_ID}> is addressed to YOU -- that's you, not "
            "another agent, so never wait on yourself."
        )
        return retval

    def post(self, channel, thread_ts, text, blocks=None):
        try:
            self.client.chat_postMessage(channel=channel, text=text, blocks=blocks,
                                         thread_ts=thread_ts or None)
        except Exception:
            retval = False
            return retval
        retval = True
        return retval

    def withdrawn(self, channel, thread_ts, req_id, req, note):
        """Rewrite the card in place: the buttons go, the command stays (#94's
        rule), and the note says why. chat_update is silent, which is fine
        here -- what matters is that no live button is left. A card whose ts
        was not kept gets a line in the thread instead."""
        if req.get("card_ts"):
            try:
                self.client.chat_update(channel=channel, ts=req["card_ts"],
                                        text=redact.scrub(f"Withdrawn [{req_id}]"),
                                        blocks=slack_blocks.withdrawn(req_id, req, note))
                retval = True
                return retval
            except Exception:  # noqa: BLE001 -- fall back to saying it in the thread
                pass
        retval = self.post(channel, thread_ts, f":no_entry_sign: [{req_id}] {note}")
        return retval

    def permalink(self, channel, ts):
        try:
            retval = self.client.chat_getPermalink(channel=channel, message_ts=ts).get("permalink", "")
        except Exception:  # noqa: BLE001
            retval = ""
        return retval
