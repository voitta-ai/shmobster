"""Ingest-agnostic handler with a tool-calling loop (Iter 1).

text in -> the model may call run_shell (gated by YOLT) any number of times ->
labeled reply out. Knows nothing about Slack, so any ingest reuses it.
Per-channel policy (Iter 2) and multi-user (Iter 4) layer on top."""
import json

from . import admin_tools, config, llm, policy as policy_mod, skills, slack_tools, spine, tools

_SYSTEM = None


def _system_prompt():
    global _SYSTEM
    if _SYSTEM is None:
        _SYSTEM = spine.load_system_prompt()
    return _SYSTEM


def _agent_marker():
    if config.AGENT_LABEL:
        retval = f":robot_face: [agent: {config.AGENT_LABEL}]"
    else:
        retval = ":robot_face: [agent]"
    return retval


def _finalize(answer, steps):
    """Prefix the agent marker; warn on the reply once the loop neared the cap."""
    out = f"{_agent_marker()} {answer}"
    if steps >= config.WARN_TOOL_STEPS:
        out += (
            f"\n\n:warning: used {steps}/{config.MAX_TOOL_STEPS} tool steps "
            "(nearing the limit -- consider narrowing the request)."
        )
    retval = out
    return retval


def handle(text, thread_context=None, channel=None, thread_ts=None, user_id=None, slack_client=None, attachments=None):
    policy = policy_mod.resolve(channel)
    tool_schemas = list(tools.TOOLS)
    if slack_client is not None:
        tool_schemas += slack_tools.TOOLS + admin_tools.TOOLS
    # Skills are offered only when some are configured, and the menu is rebuilt
    # per turn so a reload_skills takes effect without a restart (#74).
    skill_menu = skills.prompt_block()
    if skill_menu:
        tool_schemas += skills.TOOLS
    system = _system_prompt()
    if skill_menu:
        system += "\n\n" + skill_menu
    _ident = []
    if config.AGENT_LABEL:
        _ident.append(
            f"Your name is {config.AGENT_LABEL}. Introduce and refer to yourself "
            f"only as {config.AGENT_LABEL}. \"Shmobster\" is the software platform "
            "you run on, not your name -- never call yourself Shmobster."
        )
    if config.BOT_USER_ID:
        _ident.append(
            f"Your Slack user id is {config.BOT_USER_ID}; a message mentioning "
            f"<@{config.BOT_USER_ID}> is addressed to YOU -- that's you, not "
            "another agent, so never wait on yourself."
        )
    if _ident:
        system = " ".join(_ident) + "\n\n" + system
    if channel:
        loc = f"You are in Slack channel {channel}"
        _cname = config.CHANNEL_NAMES.get(channel)
        if _cname:
            loc += f" ({_cname})"
        loc += "."
        if thread_ts:
            loc += f" This thread's ts is {thread_ts}."
        loc += " Use the slack tools with this channel_id to read history or post here."
        system += "\n\n" + loc
    if thread_context:
        system += "\n\n## Conversation so far in this thread\n" + thread_context
    # A plain string when there's nothing attached -- multimodal content lists
    # are the exception, and not every vendor in the waterfall accepts one.
    # ponytail: if a fallback rejects images the Router just moves on; add a
    # per-vendor capability flag only once that actually costs us a turn.
    if attachments:
        user_content = [{"type": "text", "text": text}] + list(attachments)
    else:
        user_content = text
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content},
    ]
    steps = 0
    while steps < config.MAX_TOOL_STEPS:
        steps += 1
        msg = llm.complete(messages, tools=tool_schemas)
        calls = getattr(msg, "tool_calls", None)
        if not calls:
            retval = _finalize(msg.content, steps)
            return retval
        messages.append(msg.model_dump())
        for call in calls:
            try:
                args = json.loads(call.function.arguments or "{}")
            except ValueError:
                args = {}
            name = call.function.name
            if name in admin_tools.NAMES:
                ctx = {"user_id": user_id, "channel": channel, "thread_ts": thread_ts, "client": slack_client}
                result = admin_tools.dispatch(name, args, ctx)
                # An admin tool (set_policy) may have just changed this channel's
                # policy; re-resolve so the rest of THIS turn's tool calls see the
                # new scope instead of the stale dict from turn start (#58).
                policy = policy_mod.resolve(channel)
            elif name in skills.NAMES:
                result = skills.dispatch(name, args)
            elif name in slack_tools.NAMES:
                result = slack_tools.dispatch(name, args, slack_client)
            else:
                result = tools.dispatch(name, args, policy, channel)
            messages.append(
                {"role": "tool", "tool_call_id": call.id, "content": result}
            )
    # Hit the step cap -> one final tools-less call so the user gets a real
    # answer from what we gathered, instead of a dead-end "(stopped)" message.
    final = llm.complete(messages)
    answer = final.content or "(reached the tool-step limit without a definitive answer)"
    retval = _finalize(answer, steps)
    return retval
