"""Ingest-agnostic message handler: text in, labeled reply out.

Deliberately knows nothing about Slack -- so any ingest (Bolt now, xoxc or CLI
later) reuses it. Exec/tools (Iter 1), per-channel policy (Iter 2), and
multi-user (Iter 4) layer on top of this."""
from . import config, llm, spine

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


def handle(text):
    messages = [
        {"role": "system", "content": _system_prompt()},
        {"role": "user", "content": text},
    ]
    answer = llm.reply(messages)
    retval = f"{_agent_marker()} {answer}"
    return retval
