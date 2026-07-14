"""Runnable Iter 1 check -- no Slack, no network, no API keys.

Verifies config parse, spine load, the YOLT gate wiring (yolt stubbed), and the
handler tool-calling loop (llm stubbed). Run from repo root: python selfcheck.py
"""
import os

os.environ["SHMOBSTER_CONFIG"] = "examples/shmobster-config-example.json"

from shmobster import config, handler, llm, spine, tools, yolt_gate  # noqa: E402

# 0) config parsed: waterfall + channels + exec block
assert [v["name"] for v in config.WATERFALL] == ["anthropic", "openrouter", "nvidia"], config.WATERFALL
assert config.CHANNELS == {"C0ACJGUGB0A"}, config.CHANNELS
assert config.YOLT_CLASSIFIER.endswith("grammar_classifier.py"), config.YOLT_CLASSIFIER

# 1) spine loads bundled SOUL.md
assert "Shmobster" in spine.load_system_prompt()

# 2) tools.run_shell honors the YOLT verdict (yolt stubbed -> no subprocess)
yolt_gate.classify = lambda cmd: ("safe", "read-only")
out = tools.run_shell("echo selfcheck_marker_123")
assert "selfcheck_marker_123" in out, out
yolt_gate.classify = lambda cmd: ("unsafe", "mutating")
blocked = tools.run_shell("rm -rf /tmp/x")
assert blocked.startswith("NOT RUN"), blocked


# 3) handler tool-loop: model asks to run a command, then answers
class _FakeFn:
    def __init__(self, name, args):
        self.name = name
        self.arguments = args


class _FakeCall:
    def __init__(self, cid, name, args):
        self.id = cid
        self.function = _FakeFn(name, args)


class _FakeMsg:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls

    def model_dump(self):
        return {"role": "assistant", "content": self.content}


yolt_gate.classify = lambda cmd: ("safe", "read-only")
_script = [
    _FakeMsg(tool_calls=[_FakeCall("c1", "run_shell", '{"command": "echo hi_from_tool"}')]),
    _FakeMsg(content="ran it: hi_from_tool"),
]
_step = {"i": 0}


def _fake_complete(messages, tools=None):
    m = _script[_step["i"]]
    _step["i"] += 1
    return m


llm.complete = _fake_complete
reply = handler.handle("run echo")
assert reply.startswith(":robot_face: [agent: shmobster]"), reply
assert "ran it: hi_from_tool" in reply, reply

# 4) thread context (Iter 11) flows into the system prompt
captured = {}


def _capture(messages, tools=None):
    captured["sys"] = messages[0]["content"]
    return _FakeMsg(content="ok")


llm.complete = _capture
handler.handle("current", thread_context="[user] earlier q\n[shmobster] earlier a")
assert "Conversation so far in this thread" in captured["sys"], captured["sys"]
assert "earlier q" in captured["sys"], captured["sys"]

print("selfcheck OK")
