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
    value, which is what the action handler acts on."""
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
