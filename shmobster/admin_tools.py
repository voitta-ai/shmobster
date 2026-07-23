"""Privileged tools: change my own restrictions (#36 tier 2) and approve a
parked mutating command (#48).

Only trusted users (config.trusted_users, matched by Slack user ID) may. A
non-trusted attempt is refused loudly and all trusted users are tagged.
set_policy changes *restrictions* (cwd / github_repos / aws_profile) -- never
the trusted_users list itself (that stays file-only, to prevent escalation).
approve_command grants *permission* for one already-parked command; the channel
policy still bounds its scope when it runs."""
from . import approvals, config, policy as policy_mod, tools

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "set_policy",
            "description": (
                "Change a channel's capability restrictions (cwd / github_repos / "
                "aws_profile). ONLY trusted users may -- use when a trusted user "
                "asks you to widen or change what you can do in a channel."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string", "description": "Channel ID (C...) whose policy to change; default to the current channel."},
                    "cwd": {"type": "string", "description": "Working dir for commands in that channel."},
                    "github_repos": {"type": "array", "items": {"type": "string"}, "description": "Allowed owner/repo globs for git/gh (empty list = no repo restriction)."},
                    "aws_profile": {"type": "string", "description": "AWS profile for commands in that channel."},
                },
                "required": ["channel_id"],
            },
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


def _trusted_tags():
    return " ".join(f"<@{u}>" for u in config.TRUSTED_USERS) or "(no trusted users configured)"


def _refuse(ctx, what):
    """Loud refusal, and tag all trusted users so they know (post directly so
    the tag is guaranteed, not left to the model to relay)."""
    client, channel = ctx.get("client"), ctx.get("channel")
    user_id = ctx.get("user_id")
    alert = (
        f":no_entry: <@{user_id}> asked me to {what}, but only trusted users "
        f"may. {_trusted_tags()} -- heads up."
    )
    if client and channel:
        try:
            client.chat_postMessage(channel=channel, text=alert, thread_ts=ctx.get("thread_ts") or None)
        except Exception:
            pass
    return "REFUSED: requester is not a trusted user. Trusted users have been notified."


def _approve_command(args, ctx):
    channel = ctx.get("channel")
    req_id = str(args.get("request_id", "")).lstrip("#")
    req = approvals.pop(req_id, channel)
    if req is None:
        outstanding = approvals.ids(channel) or ["(none)"]
        return (
            f"no pending request '{req_id}' in this channel. "
            f"Outstanding here: {', '.join(outstanding)}"
        )
    policy = policy_mod.resolve(channel)
    out = tools.execute(req["command"], policy)
    return f"APPROVED by <@{ctx.get('user_id')}> and ran: {req['command']}\n{out}"


def dispatch(name, args, ctx):
    if name not in NAMES:
        return f"unknown admin tool: {name}"
    user_id = ctx.get("user_id")
    if user_id not in config.TRUSTED_USERS:
        what = (
            "change my config restrictions" if name == "set_policy"
            else "approve a mutating command"
        )
        return _refuse(ctx, what)
    if name == "approve_command":
        retval = _approve_command(args, ctx)
        return retval
    updates = {
        "cwd": args.get("cwd"),
        "github_repos": args.get("github_repos"),
        "aws_profile": args.get("aws_profile"),
    }
    channel_id = args.get("channel_id") or ctx.get("channel")
    try:
        pol = config.set_channel_policy(channel_id, updates)
        return f"policy for {channel_id} updated (live): {pol}"
    except Exception as exc:
        return f"set_policy failed: {exc}"
