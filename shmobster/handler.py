"""Ingest-agnostic handler with a tool-calling loop (Iter 1).

text in -> the model may call run_shell (gated by YOLT) any number of times ->
labeled reply out. Knows nothing about Slack, so any ingest reuses it.
Per-channel policy (Iter 2) and multi-user (Iter 4) layer on top."""
import json

from . import config, llm, policy as policy_mod, spine, tools

_SYSTEM = None
_MAX_STEPS = 6


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


def handle(text, thread_context=None, channel=None):
    policy = policy_mod.resolve(channel)
    system = _system_prompt()
    if thread_context:
        system += "\n\n## Conversation so far in this thread\n" + thread_context
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": text},
    ]
    for _ in range(_MAX_STEPS):
        msg = llm.complete(messages, tools=tools.TOOLS)
        calls = getattr(msg, "tool_calls", None)
        if not calls:
            retval = f"{_agent_marker()} {msg.content}"
            return retval
        messages.append(msg.model_dump())
        for call in calls:
            try:
                args = json.loads(call.function.arguments or "{}")
            except ValueError:
                args = {}
            result = tools.dispatch(call.function.name, args, policy)
            messages.append(
                {"role": "tool", "tool_call_id": call.id, "content": result}
            )
    retval = f"{_agent_marker()} (stopped after {_MAX_STEPS} tool steps)"
    return retval
