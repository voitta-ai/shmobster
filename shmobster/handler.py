"""Ingest-agnostic handler with a tool-calling loop (Iter 1).

text in -> the model may call run_shell (gated by YOLT) any number of times ->
labeled reply out. Knows nothing about Slack, so any ingest reuses it.
Per-channel policy (Iter 2) and multi-user (Iter 4) layer on top."""
import json

from . import config, llm, policy as policy_mod, slack_tools, spine, tools

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


def handle(text, thread_context=None, channel=None, slack_client=None):
    policy = policy_mod.resolve(channel)
    tool_schemas = list(tools.TOOLS)
    if slack_client is not None:
        tool_schemas += slack_tools.TOOLS
    system = _system_prompt()
    if config.AGENT_LABEL:
        system = f"Your name is {config.AGENT_LABEL}.\n\n" + system
    if thread_context:
        system += "\n\n## Conversation so far in this thread\n" + thread_context
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": text},
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
            if name in slack_tools.NAMES:
                result = slack_tools.dispatch(name, args, slack_client)
            else:
                result = tools.dispatch(name, args, policy)
            messages.append(
                {"role": "tool", "tool_call_id": call.id, "content": result}
            )
    # Hit the step cap -> one final tools-less call so the user gets a real
    # answer from what we gathered, instead of a dead-end "(stopped)" message.
    final = llm.complete(messages)
    answer = final.content or "(reached the tool-step limit without a definitive answer)"
    retval = _finalize(answer, steps)
    return retval
