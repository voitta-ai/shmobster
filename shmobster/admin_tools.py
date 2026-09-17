"""Privileged tools: change my own restrictions (#36 tier 2) and approve a
parked mutating command (#48).

Only trusted users (config.trusted_users, matched by Slack user ID) may. A
non-trusted attempt is refused loudly and all trusted users are tagged.
set_policy changes *restrictions* (cwd / github_repos / aws_profile) -- never
the trusted_users list itself (that stays file-only, to prevent escalation).
approve_command grants *permission* for one already-parked command; the channel
policy still bounds its scope when it runs. reload_skills re-reads the skills
catalog (#74) -- gated too, since it changes which instructions I will follow."""
from . import approvals, config, learning, policy as policy_mod, proposals, redact, skills, slack_blocks, tools

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "set_policy",
            "description": (
                "Change a channel's capability restrictions (cwd / github_repos / "
                "aws_profile). ONLY trusted users may. Call this ONLY when a "
                "trusted user explicitly asks you to widen or change your scope -- "
                "do NOT call it on your own initiative because a task seems to need "
                "more access. If you lack scope, say so and ask a trusted user; a "
                "self-initiated call just gets refused and alarms everyone."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string", "description": "Channel ID (C...) whose policy to change; default to the current channel."},
                    "cwd": {"type": "string", "description": "Working dir for commands in that channel."},
                    "github_repos": {"type": "array", "items": {"type": "string"}, "description": "Allowed owner/repo globs for git/gh (empty list = no repo restriction)."},
                    "aws_profile": {"type": "string", "description": "AWS profile for commands in that channel."},
                    "exclude": {"type": "array", "items": {"type": "string"}, "description": "Paths under cwd to keep off-limits (best-effort text guard, e.g. [\"~/g/OneDrive\"]); empty list clears it."},
                    "skills": {"type": "array", "items": {"type": "string"}, "description": "Directories of <name>/SKILL.md this channel alone may load, on top of the global skills.paths (#130); empty list clears it."},
                },
                "required": ["channel_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reload_skills",
            "description": (
                "Re-scan the configured skills directories so newly added or "
                "edited skills are usable without restarting. ONLY trusted users "
                "may -- call it when one asks you to pick up new skills."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "approve_command",
            "description": (
                "Approve and run a mutating command that run_shell parked for "
                "approval. ONLY trusted users may -- use when a trusted user okays "
                "a pending request id (e.g. 'approve a1b2c3d4e5f60718-3', 'go ahead')."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "The id from the 'pending approval [id]' message, in full -- ids are unique per boot and a bare number resolves to nothing."},
                },
                "required": ["request_id"],
            },
        },
    },
]

_LEARNING_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "propose_skill",
            "description": (
                "Open the PR for a flagged skill proposal (the 'Worth a skill?' "
                "card). ONLY trusted users may -- use when one says so by id "
                "(e.g. 'propose a1b2c3d4e5f60718-2'). Drafts the SKILL.md from this "
                "thread's record and opens a PR; merging it is the promotion."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "The id from the 'Worth a skill?' card, in full."},
                },
                "required": ["request_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decline_skill",
            "description": (
                "Decline a flagged skill proposal by id. ONLY trusted users may. "
                "The thread is not asked again."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "The id from the 'Worth a skill?' card, in full."},
                },
                "required": ["request_id"],
            },
        },
    },
]
TOOLS = TOOLS + _LEARNING_TOOLS

NAMES = {t["function"]["name"] for t in TOOLS}


def is_trusted(user_id):
    retval = user_id in config.TRUSTED_USERS
    return retval


def _held_answer(kind, key, channel, queue):
    """What a consumer that failed to take a request is told. Held and absent
    are different truths (#105): "no pending request" for a command another
    surface is running right now is exactly the contradiction the in-flight
    hold exists to prevent."""
    state, _req = queue.status(key, channel)
    if state == "held":
        retval = (
            f"[{key}] is already being acted on by another surface (a click or a "
            f"text approval got there first) -- do not retry; that surface will "
            f"report the outcome in this channel."
        )
        return retval
    retval = f"no pending {kind} '{key}' in this channel."
    return retval


def run_denied(request_id, req, ctx):
    """Core of Deny for a request the caller already acquired (#105): consume
    it and report. The button path acquires in _resolve; the text path in
    deny()."""
    approvals.finish(request_id)
    retval = f"DENIED by <@{ctx.get('user_id')}>, not run: {req['command']}"
    return retval


def deny(request_id, ctx):
    """Drop a parked request without running it (#50 -- the Deny button).
    Trust-gated like approve_command; denial is a privileged act too, since a
    stranger could otherwise cancel work a trusted user asked for."""
    if not is_trusted(ctx.get("user_id")):
        retval = _refuse(ctx, "deny a mutating command")
        return retval
    channel = ctx.get("channel")
    key = approvals.canonical(request_id)
    req = approvals.acquire(key, channel)
    if req is None:
        retval = _held_answer("request", key, channel, approvals)
        return retval
    try:
        retval = run_denied(key, req, ctx)
    finally:
        approvals.release(key)
    return retval


def _trusted_tags():
    return " ".join(f"<@{u}>" for u in config.TRUSTED_USERS) or "(no trusted users configured)"


_REFUSED = "REFUSED: requester is not a trusted user. Trusted users have been notified."


def _post_alert(ctx, alert, card=None):
    """Post an alert straight to the channel, so the trusted-user tag is
    guaranteed rather than left to the model to relay. Returns whether Slack
    took it: refuse_click alerts at most once per user per request, so it has
    to know whether the one it is allowed to send actually landed.

    `card` rides along as blocks when the alert is about something still
    actionable (#215), so the alert IS the affordance rather than a pointer to
    one. The alert text becomes the first block: blocks win over `text` in the
    client, so a card without it would drop the sentence explaining why the
    card is there, and `text` stays as the notification fallback."""
    client, channel = ctx.get("client"), ctx.get("channel")
    if not (client and channel):
        retval = False
        return retval
    blocks = None
    if card:
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": alert}}] + list(card)
    try:
        client.chat_postMessage(channel=channel, text=alert, blocks=blocks,
                                thread_ts=ctx.get("thread_ts") or None)
    except Exception:
        retval = False
        return retval
    retval = True
    return retval


def _refuse(ctx, what):
    """Loud refusal, and tag all trusted users so they know.

    Deliberately does NOT assert the user asked for this (#59): the attempt to
    {what} may be the agent's own initiative during this user's turn, not a
    request from them. The old wording ("<user> asked me to change my config")
    read as a prompt-injection attack whenever the model self-initiated a
    set_policy call, and sent agents into false-alarm paralysis.

    The button path does know who acted and writes its own alert -- see
    refuse_click, where the hedge above would be a lie (#94)."""
    alert = (
        f":warning: A privileged change was attempted during <@{ctx.get('user_id')}>'s turn "
        f"(to {what}) and refused -- only trusted users may. This can be my own "
        f"doing, not necessarily their request. {_trusted_tags()} for visibility."
    )
    _post_alert(ctx, alert)
    return _REFUSED


_CLICK_LABELS = {
    "approve_command": "Approve", "deny_command": "Deny",
    "open_skill_pr": "Open PR", "decline_skill": "Decline",
}
_QUEUES = {"open_skill_pr": proposals, "decline_skill": proposals}
_CLICK_ALERTED = {}  # (request_id, channel, user_id) -> None; one alert each
_CLICK_ALERT_MAX = 200


def _alerted(request_id, channel, user_id):
    """Whether this user's click on this request here has already been alerted.

    Leaving the card standing (#94) also leaves its buttons re-clickable, and
    the alert tags every trusted user -- so without this, one stranger holding
    down a button is an unbounded ping. The destructive chat_update used to
    swallow the second click by accident; this does it on purpose. In-memory
    and capped, like the queue it shadows.

    Keyed by channel too (#107), and on the boot-unique queue key rather than
    the short id (#109): without either, a stale click on [1] silences the
    alert for a live [1] -- in another channel, or after a restart in the same
    one -- hiding exactly the unauthorized click trusted users are meant to
    hear about."""
    retval = (str(request_id), channel, user_id) in _CLICK_ALERTED
    return retval


def _mark_alerted(request_id, channel, user_id):
    """Record a *delivered* alert. Only delivery counts: a swallowed Slack
    failure on the one alert a user gets would otherwise mean the trusted users
    are never told and every retry is suppressed as already-told."""
    _CLICK_ALERTED[(str(request_id), channel, user_id)] = None
    while len(_CLICK_ALERTED) > _CLICK_ALERT_MAX:
        del _CLICK_ALERTED[next(iter(_CLICK_ALERTED))]


def _live_card(queue, key, req):
    """The still-parked request, rendered fresh and clickable (#215).

    Each queue renders its own surface, so the renderer is chosen by queue
    rather than by sniffing the dict -- the same split `_QUEUES` already makes
    for `status`. Returns None when there is nothing to render, so a caller
    cannot turn a missing request into an empty card."""
    if req is None:
        retval = None
    elif queue is proposals:
        retval = slack_blocks.proposal(key, req, _trusted_tags())
    else:
        retval = slack_blocks.approval(key, req)
    return retval


def refuse_click(request_id, ctx, action_id):
    """A non-trusted user pressed Approve or Deny on a parked command (#94).

    Split from the model path because the two know different things. A button
    press has an unambiguous actor -- the model cannot click -- so the #59
    hedge would be a falsehood here, and saying it sent an agent hunting a
    self-initiated mutation that had never happened.

    It also names the command, because the click is exactly when someone asks
    "what was parked?", and the card that answers that is the only other place
    it is written down. The queue is left untouched: refusing a click must not
    consume the request.
    """
    label = _CLICK_LABELS.get(action_id, "a button")
    user_id = ctx.get("user_id")
    who = f"<@{user_id}>"
    channel = ctx.get("channel")
    # Keyed on the canonical id, so a `#4` and a `4` are one request and one
    # alert -- and so a previous boot's id and this boot's cannot share an entry
    # (#109), which is what let a stale click silence the alert for a live one.
    key = approvals.canonical(request_id)
    if _alerted(key, channel, user_id):
        retval = "REFUSED: requester is not a trusted user. Trusted users have already been notified."
        return retval
    queue = _QUEUES.get(action_id, approvals)
    _state, req = queue.status(key, channel)
    # Kept before the flattening below, because rendering a live card needs the
    # request as its own queue's renderer expects it (#215).
    live = req
    # Only the pending branch sets one. A held request is already being acted
    # on and an absent one cannot be acted on at all, so a card in either would
    # be a button that does nothing -- the failure this is fixing, inverted.
    card = None
    if req is not None and "command" not in req:
        # A skill proposal (#129) renders as its name, not a command line.
        req = {"command": f"skill proposal `{req.get('name')}`"}
    if _state == "held":
        # Asked FIRST, because the queue goes quiet in the middle of this: a
        # trusted click acquires the request, rewrites the card to the claimed
        # button-less state, and the approve path pops it before running the
        # command -- so peek() says "pending" early in that window and "gone"
        # for the whole run, while neither is the useful answer. Only the hold
        # spans it. Promising live buttons here would send someone to press
        # buttons that are no longer there; calling it gone is worse still,
        # since the command is executing as the message is written.
        alert = (
            f":warning: {who} clicked *{label}* on request [{key}], but only "
            f"trusted users may act on a parked command -- nothing ran. A trusted "
            f"user is already acting on it. {_trusted_tags()} for visibility."
        )
        if req is not None:
            alert += "\n" + redact.scrub(f"```{req['command']}```")
    elif _state == "absent":
        # A stale card -- already claimed, denied, evicted, or cleared by a
        # restart. Saying "still parked" here would be the same kind of
        # confident falsehood this whole change exists to stop telling.
        alert = (
            f":warning: {who} clicked *{label}* on request [{key}], which is "
            f"no longer pending in this channel -- nothing ran. Only trusted users "
            f"may act on a parked command. {_trusted_tags()} for visibility."
        )
    else:
        # Says what happens next, not just what the rule is (#107). The card
        # and its buttons are deliberately left standing -- refusing a click
        # must not consume the request -- and without being told so the thread
        # reads this as the click having consumed something.
        #
        # It used to say the buttons "on the card above" were still live. True,
        # and useless: "above" is however far the conversation has travelled
        # since. Measured -- a click landed 43 minutes and a dozen messages
        # after the card was posted, the alert pointed up at it, and the
        # trusted user asked the agent to list what was parked and approved by
        # typing ids instead. The buttons worked the entire time; nobody could
        # find them. So the alert carries its own (#215), and the click lands
        # where the conversation is.
        #
        # Two cards for one request is fine: both resolve the same id, whichever
        # is clicked gets rewritten to the claimed state, and a click on the
        # other then reads "no longer pending", which is true. The command is
        # not repeated here -- the card renders it, scrubbed, and printing it
        # twice in one message is how a credential gets two chances (#72).
        alert = (
            f":warning: {who} clicked *{label}* on request [{key}], but only "
            f"trusted users may act on a parked command -- nothing ran. It is "
            f"still parked, so {_trusted_tags()} can act on it right here."
        )
        card = _live_card(queue, key, live)
    if _post_alert(ctx, alert, card):
        _mark_alerted(key, channel, user_id)
    retval = _REFUSED
    return retval


def _reload_skills():
    """Re-scan the skills paths (#74). Reading files is not a mutation, but the
    trust gate stays on: it changes what instructions the agent will follow."""
    try:
        count = skills.reload()
    except Exception as exc:
        retval = f"reload_skills failed: {exc}"
        return retval
    retval = f"skills reloaded: {count} indexed ({', '.join(skills.names()) or 'none'})"
    return retval


def run_approved(request_id, req, ctx):
    """Core of Approve for a request the caller already acquired (#105):
    consume it (finish before execute -- the same pop-then-run rule as
    always), run it under the channel policy, report."""
    approvals.finish(request_id)
    policy = policy_mod.resolve(ctx.get("channel"))
    out = tools.execute(req["command"], policy)
    retval = f"APPROVED by <@{ctx.get('user_id')}> and ran: {req['command']}\n{out}"
    return retval


def _approve_command(args, ctx):
    channel = ctx.get("channel")
    req_id = approvals.canonical(args.get("request_id", ""))
    req = approvals.acquire(req_id, channel)
    if req is None and approvals.status(req_id, channel)[0] == "held":
        retval = _held_answer("request", req_id, channel, approvals)
        return retval
    if req is None:
        # How many are parked, never which (#109). The likeliest way to reach
        # here is a trusted user quoting an id off a card from before a restart,
        # and this answer goes back into the tool loop as another turn the model
        # may act on -- so listing the live ids hands it an approvable id the
        # human never named, and "helpfully" retrying with one runs a command
        # nobody quoted. The count still says the queue is not empty, which is
        # what stops "no pending request" reading as "your request was
        # consumed" (#107); the id itself is on the card, where the human is.
        parked = len(approvals.ids(channel))
        also = f" {parked} other request(s) are parked here." if parked else ""
        retval = (
            f"no pending request '{req_id}' in this channel.{also} Do not guess "
            f"another id: ask the user to quote the id from the card they mean, "
            f"or to use its Approve button."
        )
        return retval
    try:
        retval = run_approved(req_id, req, ctx)
    finally:
        approvals.release(req_id)
    return retval


def dispatch(name, args, ctx):
    if name not in NAMES:
        return f"unknown admin tool: {name}"
    user_id = ctx.get("user_id")
    if not is_trusted(user_id):
        what = {
            "set_policy": "change my config restrictions",
            "reload_skills": "reload my skills",
            "propose_skill": "open a skill PR",
            "decline_skill": "decline a skill proposal",
        }.get(name, "approve a mutating command")
        return _refuse(ctx, what)
    if name == "reload_skills":
        retval = _reload_skills()
        return retval
    if name == "approve_command":
        retval = _approve_command(args, ctx)
        return retval
    if name == "propose_skill":
        retval = learning.propose(args.get("request_id", ""), ctx)
        return retval
    if name == "decline_skill":
        retval = learning.decline(args.get("request_id", ""), ctx)
        return retval
    updates = {
        "cwd": args.get("cwd"),
        "github_repos": args.get("github_repos"),
        "aws_profile": args.get("aws_profile"),
        "exclude": args.get("exclude"),
        "skills": args.get("skills"),
    }
    channel_id = args.get("channel_id") or ctx.get("channel")
    try:
        pol = config.set_channel_policy(channel_id, updates)
        return f"policy for {channel_id} updated (live): {pol}"
    except Exception as exc:
        return f"set_policy failed: {exc}"
