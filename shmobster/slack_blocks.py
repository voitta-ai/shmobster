"""Slack Block Kit rendering.

Separate from `slack_app` because that module builds the Bolt `App` at import
time (an `auth.test` round-trip), which makes everything in it untestable
offline -- and rendering an approval card is exactly the kind of thing that
needs a regression test, since it is one of the surfaces a credential can reach
(#72). Separate from `approvals` because that module is deliberately
ingest-agnostic: it owns the queue, each ingest renders its own surface."""
from . import redact


def approval(req_id, req):
    """Approve/Deny buttons for one parked command (#50). The command goes in a
    code block so a long one stays readable; the request id rides in the button
    value, which is what the action handler acts on.

    The id is boot-unique and shown in full (#109). This card is a Slack
    message that outlives the process, and both ways of acting on it -- the
    button and a human typing the id -- must resolve to nothing after a restart
    rather than to whichever request inherited its number."""
    retval = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                # Scrubbed here, not only in the fallback `text`: the command
                # is rendered twice and a credential rides argv routinely (#72).
                "text": redact.scrub(
                    f":lock: *Needs approval* [{req_id}] ({req['reason']})\n"
                    f"```{req['command']}```"
                ),
            },
        },
        {
            "type": "actions",
            "block_id": f"approval_{req_id}",
            "elements": [
                {
                    "type": "button",
                    "action_id": "approve_command",
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "value": req_id,
                },
                {
                    "type": "button",
                    "action_id": "deny_command",
                    "style": "danger",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "value": req_id,
                },
            ],
        },
    ]
    return retval


_CLAIMED_VERB = {"approve_command": "Approving", "deny_command": "Denying"}


def claimed(action_id, req_id, user_id, req):
    """The card a click leaves behind while it is being acted on (#101).

    Posted before the command runs, not after. `chat_update` is silent -- no
    notification, no unread marker -- so a card that only changes once the
    command finishes leaves the clicker with a live button and no sign their
    click landed, which reads as a lost click. It also takes the buttons away
    inside Slack's ack window, which is what closes the double-click race:
    approve pops the request and then executes, so a second click during a slow
    run finds nothing pending and overwrites the real output with an error.

    The command stays visible, because this replaces the only place it is
    shown and the operator still wants to read it while it runs.
    """
    text = f":hourglass_flowing_sand: *{_CLAIMED_VERB.get(action_id, 'Working on')}* [{req_id}] -- <@{user_id}>"
    if req:
        # Scrubbed for the reason approval() gives: a credential rides argv.
        text += "\n" + redact.scrub(f"```{req['command']}```")
    retval = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    return retval
