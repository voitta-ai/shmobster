"""Runnable Iter 0 check -- no Slack, no network, no API keys.

Proves the spine loads and the handler returns a labeled reply, with the LLM
stubbed. Run from repo root:  python selfcheck.py
"""
import os

os.environ.setdefault("SHMOBSTER_WORKSPACE", "./workspace")
os.environ.setdefault("SHMOBSTER_AGENT_LABEL", "shmobster")

from shmobster import handler, llm, spine  # noqa: E402

# 1) spine loads the bundled SOUL.md
system_prompt = spine.load_system_prompt()
assert "Shmobster" in system_prompt, "spine should load SOUL.md content"

# 2) handler labels the reply and passes text through to the LLM
llm.reply = lambda messages: "pong"  # stub: no network/keys needed
out = handler.handle("ping")
assert out.startswith(":robot_face: [agent: shmobster]"), out
assert out.endswith("pong"), out

# 3) the user's text actually reaches the model
seen = {}
llm.reply = lambda messages: seen.setdefault("text", messages[-1]["content"])
handler.handle("hello there")
assert seen["text"] == "hello there", seen

print("selfcheck OK")
