"""Slack Block Kit rendering.

Separate from `slack_app` because that module builds the Bolt `App` at import
time (an `auth.test` round-trip), which makes everything in it untestable
offline -- and rendering an approval card is exactly the kind of thing that
needs a regression test, since it is one of the surfaces a credential can reach
(#72). Separate from `approvals` because that module is deliberately
ingest-agnostic: it owns the queue, each ingest renders its own surface."""
from . import redact

# Slack refuses a section whose text runs past 3000 characters
# (`invalid_blocks`), and a parked command can be far longer than that. Past
# this length the card carries a head and a tail and links the full command,
# which the ingest posts as its own thread reply (message text has no such
# cap). The margin leaves room for the header line and the link.
CARD_COMMAND_MAX = 2000
_HEAD = 1200
_TAIL = 500


def command_fits(command):
    """Whether a command can go on a card whole. Measured after scrubbing,
    because that is the text the card actually carries."""
    retval = len(redact.scrub(command)) <= CARD_COMMAND_MAX
    return retval


def _command(req):
    """The command as a card shows it: whole when it fits, otherwise head and
    tail around a link to the full text.

    Scrubbed before it is cut, not after: cutting first could split a
    credential so the redactor no longer recognizes either half."""
    cmd = redact.scrub(req["command"])
    if len(cmd) <= CARD_COMMAND_MAX:
        retval = f"```{cmd}```"
    else:
        link = req.get("full_link")
        where = (f"<{link}|full command ({len(cmd)} chars)>" if link else
                 f"full command ({len(cmd)} chars) could not be linked -- "
                 f"look for it just above in this thread")
        retval = f"```{cmd[:_HEAD]}\n...\n{cmd[-_TAIL:]}```\n{where}"
    return retval


def approval_text(req_id, req):
    """The notification fallback for an approval card: short, because the
    full command is on the card or linked from it."""
    cmd = redact.scrub(req["command"])
    if len(cmd) > CARD_COMMAND_MAX:
        cmd = cmd[:200] + " ..."
    retval = f"Needs approval [{req_id}]: {cmd}"
    return retval


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
                # A refusal and a question must not look alike (#172): the
                # same lock and the same "needs approval" on both would leave a
                # trusted user clicking through a row of cards with no signal
                # that the classifier refused this one rather than queued it.
                # The buttons stay either way -- a human is still the last word
                # (#105) -- but overriding a refusal should read as a decision.
                "text": redact.scrub(
                    (f":no_entry: *Refused by the classifier* -- approve only if you "
                     f"are sure [{req_id}] ({req['reason']})\n"
                     if req.get("refused") else
                     f":lock: *Needs approval* [{req_id}] ({req['reason']})\n")
                ) + _command(req),
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
        text += "\n" + _command(req)
    retval = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    return retval


def expired(req_id, message, stale_boot):
    """The card a request leaves behind once nothing can act on it (#258).

    Buttons that resolve to nothing are worse than no buttons: the reader
    presses again, gets the same line, and concludes the agent is broken --
    which is exactly what four identical "not pending here" replies looked
    like from the outside.

    #94's rule holds, and is the reason for the `message` argument: a click
    that resolves nothing must not destroy the only copy of the parked
    command, so the command is lifted out of the card being replaced rather
    than dropped. Only the actions block goes."""
    kept = []
    for block in (message or {}).get("blocks") or []:
        if block.get("type") != "actions":
            # block_id is dropped: Slack rejects an echoed id in a rewritten
            # message, and the text is the part worth keeping.
            kept.append({k: v for k, v in block.items() if k != "block_id"})
    why = ("this card predates a restart, so its request is gone -- ask again"
           if stale_boot else "already acted on")
    kept.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f":lock: *Expired* [{req_id}] -- {why}."}],
    })
    retval = kept
    return retval


def proposal(key, prop, tags):
    """The "worth a skill?" card (#129): the agent's flag, tagging the trusted
    users who may act on it, with Open PR / Decline. Same shape as the
    approval card so the click handler is shared; the id rides in the value."""
    # Where it would land and why, before anyone clicks (#210). The classifier
    # only proposes -- the trusted click is still the gate -- so the card has to
    # show its reasoning, not just its answer: a proposal a human cannot check
    # is one they have to take on faith.
    _scope = prop.get("scope", "channel")
    _where = ("this channel only" if _scope == "channel" else "every channel")
    _lines = [f":bulb: *Worth a skill?* [{key}] `{prop['name']}` -- {prop['why']}",
              f"scope: *{_where}* -- {prop.get('scope_reason') or 'default'}"]
    if prop.get("amends"):
        _lines.append(f"may amend the existing `{prop['amends']}` rather than add a sibling")
    if _scope == "shared":
        # Named, not offered as a button. Publishing to the public catalog needs
        # the catalog.json / bundle-symlink / version-bump wiring that
        # claudeception owns, and a second copy of it here would drift (#210 Q3).
        _lines.append("if this belongs in the *public* catalog, hand it to the "
                      "skillz session -- this instance does not publish there")
    _lines.append(f"{tags} -- a trusted user decides; nothing is written until then. "
                  f"To change the scope, say so when you approve.")
    text = redact.scrub("\n".join(_lines))
    retval = [
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        {
            "type": "actions",
            "block_id": f"proposal_{key}",
            "elements": [
                {
                    "type": "button",
                    "action_id": "open_skill_pr",
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "Open PR"},
                    "value": key,
                },
                {
                    "type": "button",
                    "action_id": "decline_skill",
                    "text": {"type": "plain_text", "text": "Decline"},
                    "value": key,
                },
            ],
        },
    ]
    return retval


_CLAIMED_VERB.update({"open_skill_pr": "Drafting the skill PR for", "decline_skill": "Declining"})


def proposal_claimed(action_id, key, user_id, prop):
    text = f":hourglass_flowing_sand: *{_CLAIMED_VERB.get(action_id, 'Working on')}* [{key}] -- <@{user_id}>"
    if prop:
        text += "\n" + redact.scrub(f"`{prop['name']}` -- {prop['why']}")
    retval = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    return retval
