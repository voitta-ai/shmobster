"""Privileged tools: change my own restrictions (#36 tier 2) and approve a
parked mutating command (#48).

Only trusted users (config.trusted_users, matched by Slack user ID) may. A
non-trusted attempt is refused loudly and all trusted users are tagged.
set_policy changes *restrictions* (cwd / github_repos / aws_profile) -- never
the trusted_users list itself (that stays file-only, to prevent escalation).
approve_command grants *permission* for one already-parked command; the channel
policy still bounds its scope when it runs. reload_skills re-reads the skills
catalog (#74) -- gated too, since it changes which instructions I will follow."""
from . import approvals, config, policy as policy_mod, redact, skills, tools

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
                "a pending request id (e.g. 'approve 3', 'go ahead')."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "The id from the 'pending approval [id]' message."},
                },
                "required": ["request_id"],
            },
        },
    },
]

NAMES = {t["function"]["name"] for t in TOOLS}


def is_trusted(user_id):
    retval = user_id in config.TRUSTED_USERS
    return retval


def deny(request_id, ctx):
    """Drop a parked request without running it (#50 -- the Deny button).
    Trust-gated like approve_command; denial is a privileged act too, since a
    stranger could otherwise cancel work a trusted user asked for."""
    if not is_trusted(ctx.get("user_id")):
        retval = _refuse(ctx, "deny a mutating command")
        return retval
    channel = ctx.get("channel")
    req = approvals.pop(request_id, channel)
    if req is None:
        retval = f"no pending request '{approvals.short(request_id)}' in this channel."
        return retval
    retval = f"DENIED by <@{ctx.get('user_id')}>, not run: {req['command']}"
    return retval


def _trusted_tags():
    return " ".join(f"<@{u}>" for u in config.TRUSTED_USERS) or "(no trusted users configured)"


_REFUSED = "REFUSED: requester is not a trusted user. Trusted users have been notified."


def _post_alert(ctx, alert):
    """Post an alert straight to the channel, so the trusted-user tag is
    guaranteed rather than left to the model to relay. Returns whether Slack
    took it: refuse_click alerts at most once per user per request, so it has
    to know whether the one it is allowed to send actually landed."""
    client, channel = ctx.get("client"), ctx.get("channel")
    if not (client and channel):
        retval = False
        return retval
    try:
        client.chat_postMessage(channel=channel, text=alert, thread_ts=ctx.get("thread_ts") or None)
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


_CLICK_LABELS = {"approve_command": "Approve", "deny_command": "Deny"}
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
    # The queue key for the dedupe and the lookup, the short form for what the
    # alert says (#109). A button value carries the boot nonce and a typed id
    # does not, so keying the dedupe on the raw string would let one user's two
    # routes to the same request each spend an alert -- and, worse, would let a
    # previous boot's [4] and this boot's [4] share one.
    key = approvals.canonical(request_id)
    label_id = approvals.short(request_id)
    if _alerted(key, channel, user_id):
        retval = "REFUSED: requester is not a trusted user. Trusted users have already been notified."
        return retval
    _state, req = approvals.status(key, channel)
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
            f":warning: {who} clicked *{label}* on request [{label_id}], but only "
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
            f":warning: {who} clicked *{label}* on request [{label_id}], which is "
            f"no longer pending in this channel -- nothing ran. Only trusted users "
            f"may act on a parked command. {_trusted_tags()} for visibility."
        )
    else:
        # Says what happens next, not just what the rule is (#107). The card
        # and its buttons are deliberately left standing, and without being
        # told so the thread reads this as the click having consumed something
        # -- which sent one straight to asking the agent to re-raise a request
        # that was sitting right there, still clickable.
        alert = (
            f":warning: {who} clicked *{label}* on request [{label_id}], but only "
            f"trusted users may act on a parked command -- nothing ran. The request "
            f"is still parked and the *Approve* / *Deny* buttons on the card above "
            f"are still live, so {_trusted_tags()} can act on it there."
            # Scrubbed like every other rendering of a parked command (#72): a
            # credential rides argv routinely, and this is a fresh channel post.
            "\n" + redact.scrub(f"```{req['command']}```")
        )
    if _post_alert(ctx, alert):
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


def _approve_command(args, ctx):
    channel = ctx.get("channel")
    req_id = args.get("request_id", "")
    req = approvals.pop(req_id, channel)
    if req is None:
        # Short ids throughout, because this text goes back to the model to
        # relay and then to a human to type (#109).
        outstanding = [approvals.short(k) for k in approvals.ids(channel)] or ["(none)"]
        return (
            f"no pending request '{approvals.short(req_id)}' in this channel. "
            f"Outstanding here: {', '.join(outstanding)}"
        )
    policy = policy_mod.resolve(channel)
    out = tools.execute(req["command"], policy)
    return f"APPROVED by <@{ctx.get('user_id')}> and ran: {req['command']}\n{out}"


def dispatch(name, args, ctx):
    if name not in NAMES:
        return f"unknown admin tool: {name}"
    user_id = ctx.get("user_id")
    if not is_trusted(user_id):
        what = {
            "set_policy": "change my config restrictions",
            "reload_skills": "reload my skills",
        }.get(name, "approve a mutating command")
        return _refuse(ctx, what)
    if name == "reload_skills":
        retval = _reload_skills()
        return retval
    if name == "approve_command":
        retval = _approve_command(args, ctx)
        return retval
    updates = {
        "cwd": args.get("cwd"),
        "github_repos": args.get("github_repos"),
        "aws_profile": args.get("aws_profile"),
        "exclude": args.get("exclude"),
    }
    channel_id = args.get("channel_id") or ctx.get("channel")
    try:
        pol = config.set_channel_policy(channel_id, updates)
        return f"policy for {channel_id} updated (live): {pol}"
    except Exception as exc:
        return f"set_policy failed: {exc}"
