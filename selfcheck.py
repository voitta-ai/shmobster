"""Runnable Iter 1 check -- no Slack, no network, no API keys.

Verifies config parse, spine load, the YOLT gate wiring (yolt stubbed), and the
handler tool-calling loop (llm stubbed). Run from repo root: python selfcheck.py
"""
import ast
import io
import json
import logging
import datetime
import os
import tempfile
import time

os.environ["SHMOBSTER_CONFIG"] = "examples/shmobster-config-example.json"
# The example config references its secrets from the environment (#73), and an
# unset one is a hard startup failure by design. Offline sanity must not need
# real keys, so stub every name the example refers to with a placeholder.
for _var in (
    "SLACK_BOT_TOKEN",
    "SLACK_APP_TOKEN",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "REQUESTY_API_KEY",
    "OPENROUTER_API_KEY",
):
    os.environ.setdefault(_var, f"selfcheck-placeholder-{_var.lower()}")

import litellm  # noqa: E402

from shmobster import __version__, admin_tools, announce, approvals, build, config, handler, identity, llm, policy, redact, skills, slack_blocks, slack_tools, spine, state, tools, yolt_gate  # noqa: E402

# Redaction (#72) fails loud without voitta-yolt's secret_redact, and the example
# config points at a placeholder path (CI has no yolt checkout). Stand up a stub
# next to a stub classifier so every handler path below exercises the scrub; the
# real detector is asserted in section 19 when this machine has it.
_yolt_dir = tempfile.mkdtemp()
with open(os.path.join(_yolt_dir, "secret_redact.py"), "w") as _f:
    _f.write(
        "import re\n"
        "_P = [('aws-access-key-id', re.compile(r'\\bAKIA[0-9A-Z]{16}\\b')),\n"
        "      ('slack-token', re.compile(r'\\bxox[baprse]-[0-9A-Za-z-]{8,}'))]\n"
        "def redact(text):\n"
        "    if not text:\n"
        "        return text\n"
        "    for kind, pat in _P:\n"
        "        text = pat.sub('[REDACTED:%s]' % kind, text)\n"
        "    return text\n"
    )
# Later sections stub llm.complete; section 21 needs the real one, so keep a
# reference before any of that happens.
_REAL_COMPLETE = llm.complete
_REAL_YOLT = config.YOLT_CLASSIFIER
config.YOLT_CLASSIFIER = os.path.join(_yolt_dir, "grammar_classifier.py")

# 0) config parsed: waterfall + channels + exec block
assert [v["name"] for v in config.WATERFALL] == [
    "anthropic", "gemini", "requesty", "codex", "openrouter"], config.WATERFALL
# the codex rung (#35) is a subscription, not an api_key row: it authenticates
# from the codex CLI's token file, so a key here would be a config error
assert "api_key" not in next(v for v in config.WATERFALL if v["name"] == "codex")
# every fallback must be a distinct vendor: a waterfall whose slots share a
# rate-limit budget is one outage, listed four times
assert len({v["name"] for v in config.WATERFALL}) == len(config.WATERFALL), config.WATERFALL
assert len(config.CHANNELS) == 1, config.CHANNELS
_ex_ch = next(iter(config.CHANNELS))  # the example config's placeholder channel id
assert _REAL_YOLT.endswith("grammar_classifier.py"), _REAL_YOLT

# 1) spine loads bundled SOUL.md
assert "engineering agent" in spine.load_system_prompt()

# 2) tools.run_shell honors the YOLT verdict (yolt stubbed -> no subprocess)
yolt_gate.classify = lambda cmd: ("safe", "read-only")
out = tools.run_shell("echo selfcheck_marker_123", {})
assert "selfcheck_marker_123" in out, out
yolt_gate.classify = lambda cmd: ("unsafe", "mutating")
blocked = tools.run_shell("rm -rf /tmp/x", {})
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
assert "Your name is shmobster" in captured["sys"], captured["sys"]  # identity from config (#8/PR2)

# 5) per-channel policy (Iter #4): github repo scope + aws profile guard
gh_pol = {"github_repos": ["voitta-ai/*"]}
assert policy.check("gh repo view voitta-ai/shmobster", gh_pol)[0], "allowed repo passes"
assert not policy.check("gh repo view other-org/thing", gh_pol)[0], "disallowed repo blocks"
aws_pol = {"aws_profile": "doubledoor"}
assert policy.check("aws s3 ls", aws_pol)[0], "aws without override passes"
assert not policy.check("aws s3 ls --profile other", aws_pol)[0], "profile override blocks"
# run_shell surfaces a policy block (yolt says safe, policy says no)
yolt_gate.classify = lambda cmd: ("safe", "read-only")
blocked_repo = tools.run_shell("gh repo view other-org/thing", gh_pol)
assert blocked_repo.startswith("BLOCKED by channel policy"), blocked_repo


# 6) tool-loop step cap -> a real final answer, not "(stopped after N steps)"
def _always_tool(messages, tools=None):
    if tools is None:  # the final tools-less summarizing call
        return _FakeMsg(content="best-effort summary")
    return _FakeMsg(tool_calls=[_FakeCall("c", "run_shell", '{"command": "echo x"}')])


yolt_gate.classify = lambda cmd: ("safe", "read-only")
config.MAX_TOOL_STEPS = 3  # keep the test fast + trip the near-limit warning
config.WARN_TOOL_STEPS = 2
llm.complete = _always_tool
capped = handler.handle("keep going")
assert "best-effort summary" in capped, capped
assert "stopped after" not in capped, capped
assert "3/3 tool steps" in capped, capped  # nearing-limit warning fired

# 7) config validation: tool-step bounds must be positive ints
for bad in (0, -1, True, 2.5, "3"):
    try:
        config._positive_int("x", bad)
        raise AssertionError(f"{bad!r} should have been rejected")
    except SystemExit:
        pass
config._positive_int("x", 5)  # valid -> no raise

# 8) slack-read tools (#28): permalink ts parse + routing + no-client graceful
class _FakeSlack:
    def __init__(self):
        self.last = None

    def conversations_replies(self, channel, ts, limit=50):
        self.last = ("replies", channel, ts)
        return {"messages": [{"user": "U1", "text": "hi from thread"}]}

    def conversations_history(self, channel, limit=20):
        self.last = ("history", channel)
        return {"messages": [{"user": "U2", "text": "chan msg"}]}

    def chat_postMessage(self, channel, text, thread_ts=None):
        self.last = ("post", channel, text, thread_ts)
        return {"ok": True, "ts": "1.2"}


_fs = _FakeSlack()
perm = slack_tools.dispatch(
    "slack_read_permalink",
    {"url": f"https://example.slack.com/archives/{_ex_ch}/p1234567890123456"},
    _fs,
)
assert "hi from thread" in perm, perm
assert _fs.last == ("replies", _ex_ch, "1234567890.123456"), _fs.last
assert "chan msg" in slack_tools.dispatch("slack_read_channel", {"channel_id": "C1"}, _fs)
assert "no slack client" in slack_tools.dispatch("slack_read_thread", {}, None)
assert "posted to C9" in slack_tools.dispatch("slack_post", {"channel_id": "C9", "text": "hi"}, _fs)
assert _fs.last[0] == "post" and _fs.last[1] == "C9", _fs.last


# 9) channel-context injection into the system prompt
_capch = {}


def _cap_ch(messages, tools=None):
    _capch["sys"] = messages[0]["content"]
    return _FakeMsg(content="ok")


llm.complete = _cap_ch
config.BOT_USER_ID = "UBOTSELF"
handler.handle("hey", channel=_ex_ch, thread_ts="123.456", slack_client=_fs)
assert f"Slack channel {_ex_ch}" in _capch["sys"], _capch["sys"]
assert "123.456" in _capch["sys"], _capch["sys"]
assert "UBOTSELF" in _capch["sys"], _capch["sys"]  # self user-id injected

# 10) trusted-user self-config (#36): trust gate by Slack user id
config.TRUSTED_USERS = {"U_TRUSTED"}
_posted = {}


class _FakePost:
    def chat_postMessage(self, channel, text, thread_ts=None):
        _posted["text"] = text
        return {"ok": True, "ts": "1"}


# non-trusted -> loud refusal + trusted users tagged, no write
_res = admin_tools.dispatch(
    "set_policy", {"channel_id": "C1", "cwd": "/x"},
    {"user_id": "U_STRANGER", "channel": "C1", "client": _FakePost()},
)
assert _res.startswith("REFUSED"), _res
assert "<@U_TRUSTED>" in _posted["text"], _posted

# trusted -> applies (set_channel_policy stubbed so no file is written)
_applied = {}


def _fake_set(ch, updates):
    _applied["call"] = (ch, updates)
    return {"cwd": updates.get("cwd")}


config.set_channel_policy = _fake_set
_res2 = admin_tools.dispatch(
    "set_policy", {"channel_id": "C1", "cwd": "/x"},
    {"user_id": "U_TRUSTED", "channel": "C1", "client": None},
)
assert "updated" in _res2, _res2
assert _applied["call"][0] == "C1", _applied

# 11) approval flow (#48): a mutating command parks; a trusted user releases it
yolt_gate.classify = lambda cmd: ("unsafe", "mutating")
policy.resolve = lambda ch: {}  # keep exec off this machine's real policy file
_parked = tools.run_shell("echo approved_marker_456", {}, "C1")
assert "pending approval" in _parked, _parked
_req = _parked.split("[", 1)[1].split("]", 1)[0]
assert approvals.ids("C1") == [_req], approvals.ids("C1")

# non-trusted approval is refused, and the request stays parked
_ref = admin_tools.dispatch(
    "approve_command", {"request_id": _req},
    {"user_id": "U_STRANGER", "channel": "C1", "client": _FakePost()},
)
assert _ref.startswith("REFUSED"), _ref
assert approvals.ids("C1") == [_req], approvals.ids("C1")

# wrong channel can't release another channel's request
_other = admin_tools.dispatch(
    "approve_command", {"request_id": _req},
    {"user_id": "U_TRUSTED", "channel": "C_OTHER", "client": None},
)
assert "no pending request" in _other, _other

# trusted, same channel -> runs, and the request is consumed
_ran = admin_tools.dispatch(
    "approve_command", {"request_id": _req},
    {"user_id": "U_TRUSTED", "channel": "C1", "client": None},
)
assert "approved_marker_456" in _ran, _ran
assert approvals.ids("C1") == [], approvals.ids("C1")

# 12) Slack approval surface (#50): each parked command is handed to an ingest
# exactly once, and Deny drops it unrun -- trust-gated like approve
_parked2 = tools.run_shell("echo never_runs_789", {}, "C1")
_req2 = _parked2.split("[", 1)[1].split("]", 1)[0]
_surfaced = approvals.claim_unsurfaced("C1")
assert [k for k, _ in _surfaced] == [_req2], _surfaced
assert approvals.claim_unsurfaced("C1") == [], "already surfaced -> no duplicate buttons"

_dref = admin_tools.deny(_req2, {"user_id": "U_STRANGER", "channel": "C1", "client": _FakePost()})
assert _dref.startswith("REFUSED"), _dref
assert approvals.ids("C1") == [_req2], approvals.ids("C1")

_den = admin_tools.deny(_req2, {"user_id": "U_TRUSTED", "channel": "C1", "client": None})
assert _den.startswith("DENIED"), _den
assert approvals.ids("C1") == [], approvals.ids("C1")

# 12b) a refused click (#94). The ingest half -- that slack_app leaves the card
# and its buttons standing -- can't be reached offline, since importing
# slack_app builds a Bolt App. What is checkable is everything the ingest calls:
# the queue survives, and the alert says who clicked, which button, and what it
# did not run.
_parked3 = tools.run_shell("echo refused_click_321", {}, "C1")
_req3 = _parked3.split("[", 1)[1].split("]", 1)[0]
assert approvals.peek(_req3, "C1")["command"] == "echo refused_click_321"
assert approvals.peek(_req3, "C_OTHER") is None, "peek is channel-scoped, like pop"

_cref = admin_tools.refuse_click(
    _req3, {"user_id": "U_STRANGER", "channel": "C1", "client": _FakePost()}, "approve_command"
)
assert _cref.startswith("REFUSED"), _cref
assert approvals.ids("C1") == [_req3], approvals.ids("C1")
assert "<@U_STRANGER>" in _posted["text"], _posted
assert "Approve" in _posted["text"], _posted
assert "echo refused_click_321" in _posted["text"], _posted
# ...and it does not hedge about the agent's own initiative: that wording is
# #59's, for the model path, and a button press has exactly one possible actor.
assert "my own" not in _posted["text"], _posted

_den3 = admin_tools.deny(_req3, {"user_id": "U_TRUSTED", "channel": "C1", "client": None})
assert _den3.startswith("DENIED"), _den3
assert approvals.ids("C1") == [], approvals.ids("C1")

# the card stays live, so its buttons stay clickable -- one stranger must not
# be able to tag every trusted user on repeat. Second click, same pair: still
# refused, but silent.
_posted.clear()
_again = admin_tools.refuse_click(
    _req3, {"user_id": "U_STRANGER", "channel": "C1", "client": _FakePost()}, "deny_command"
)
assert _again.startswith("REFUSED"), _again
assert _posted == {}, _posted

# a click on a stale card -- the request already claimed, denied, or cleared by
# a restart -- must not claim it is "still parked". Being confidently wrong in
# the alert is the failure this whole path exists to stop.
_sref = admin_tools.refuse_click(
    _req3, {"user_id": "U_STRANGER_2", "channel": "C1", "client": _FakePost()}, "deny_command"
)
assert _sref.startswith("REFUSED"), _sref
assert "no longer pending" in _posted["text"], _posted
assert "still parked" not in _posted["text"], _posted


# ...and the one alert a user gets is spent on a DELIVERED one. A Slack failure
# is swallowed, so counting the attempt would leave the trusted users never
# told and every retry suppressed as already-told.
class _FailingPost:
    def chat_postMessage(self, channel, text, thread_ts=None):
        raise RuntimeError("slack is down")


_ctx_flaky = {"user_id": "U_STRANGER_3", "channel": "C1", "client": _FailingPost()}
_posted.clear()
assert admin_tools.refuse_click(_req3, _ctx_flaky, "approve_command").startswith("REFUSED")
assert _posted == {}, _posted
_ctx_flaky["client"] = _FakePost()
assert admin_tools.refuse_click(_req3, _ctx_flaky, "approve_command").startswith("REFUSED")
assert "<@U_STRANGER_3>" in _posted["text"], "a failed post must not spend the alert"

# 13) cwd tilde/var expansion (#54): a policy cwd of "~/..." resolves to an
# absolute path, not the literal string that makes subprocess raise ENOENT
assert policy.cwd_for({"cwd": "~/xyzzy"}) == os.path.expanduser("~/xyzzy"), policy.cwd_for({"cwd": "~/xyzzy"})
assert policy.cwd_for({}) == os.path.expanduser(os.path.expandvars(config.EXEC_CWD))

# 14) mid-turn policy re-resolve (#58): a set_policy call partway through a turn
# updates the policy the rest of that turn's tools receive (was stale before)
_pols = {"C1": {"cwd": "/old"}}
policy.resolve = lambda ch: _pols.get(ch, {})
_seen_pol = []


def _rec_tools(name, args, pol, channel=None):
    _seen_pol.append(pol)
    return "ok"


def _flip_admin(name, args, ctx):
    _pols["C1"] = {"cwd": "/new"}
    return "policy updated"


tools.dispatch = _rec_tools
_real_admin = (admin_tools.dispatch, admin_tools.NAMES)  # restored in 17)
admin_tools.dispatch = _flip_admin
admin_tools.NAMES = {"set_policy"}
_turn_script = [
    _FakeMsg(tool_calls=[_FakeCall("a", "set_policy", '{"channel_id":"C1"}')]),
    _FakeMsg(tool_calls=[_FakeCall("b", "run_shell", '{"command":"x"}')]),
    _FakeMsg(content="done"),
]
_turn_i = {"n": 0}


def _turn(messages, tools=None):
    m = _turn_script[_turn_i["n"]]
    _turn_i["n"] += 1
    return m


config.MAX_TOOL_STEPS = 5
config.WARN_TOOL_STEPS = 4
llm.complete = _turn
handler.handle("go", channel="C1", slack_client=_fs)
assert _seen_pol and _seen_pol[-1] == {"cwd": "/new"}, _seen_pol  # run_shell saw the post-set_policy value

# 15) cwd exclude guard (#55): a path under an excluded dir is blocked, siblings
# and non-path tokens pass; tilde/relative both resolve against cwd
_ex_pol = {"cwd": "/home/u", "exclude": ["/home/u/secret"]}
assert not policy.check("cat /home/u/secret/x", _ex_pol)[0], "abs path under exclude blocks"
assert not policy.check("cd /home/u/secret", _ex_pol)[0], "cd into exclude blocks"
assert not policy.check("cat secret/x", _ex_pol)[0], "relative resolves against cwd then blocks"
assert policy.check("cat /home/u/public/x", _ex_pol)[0], "sibling dir passes"
assert policy.check("ls -la", _ex_pol)[0], "non-path token ignored"
_ex_pol2 = {"cwd": "~/g", "exclude": ["~/g/OneDrive"]}
assert not policy.check("cat ~/g/OneDrive/f", _ex_pol2)[0], "tilde exclude blocks"
assert policy.check("cat ~/g/other/f", _ex_pol2)[0], "tilde sibling passes"

# 16) speaker identity (#60): own posts are "(me)", a sibling agent's are labeled
# as another agent (not me), a human is a plain user
config.BOT_USER_ID = "UME"
config.AGENT_LABEL = "Cosima"
_me = identity.speaker({"user": "UME", "bot_id": "B1", "text": ":robot_face: [agent: Cosima] hi"})
assert "(me)" in _me and "Cosima" in _me, _me
_sib = identity.speaker({"user": "UOTHER", "bot_id": "B2", "text": ":robot_face: [agent: Barrymore] hi"})
assert "Barrymore" in _sib and "another agent" in _sib and "(me)" not in _sib, _sib
assert identity.speaker({"user": "UHUMAN"}) == "user UHUMAN", identity.speaker({"user": "UHUMAN"})
# _fmt (slack_read_*) uses the same labeling
_flat = slack_tools._fmt([{"user": "UME", "bot_id": "B1", "text": "mine"}, {"user": "UH", "text": "theirs"}])
assert "(me)] mine" in _flat and "user UH] theirs" in _flat, _flat

# 17) skill loading (#74): a skillz-format SKILL.md is indexed, summarized into
# the standing menu, offered as a tool and readable in full on demand
_skroot = os.path.join(tempfile.mkdtemp(), "skills")
os.makedirs(os.path.join(_skroot, "worktree-convention"))
with open(os.path.join(_skroot, "worktree-convention", "SKILL.md"), "w") as _f:
    _f.write(
        "---\nname: worktree-convention\ndescription: |\n"
        "  Where worktrees live and how to name them. Long tail that the menu "
        "line should not carry, repeated at length so the summary has to cut it.\n"
        "---\n\n# worktree-convention\n\nPut worktrees in <REPO>.worktrees.\n"
    )
config.SKILL_PATHS = [_skroot]
assert skills.reload() == 1
assert skills.names() == ["worktree-convention"], skills.names()
_menu = skills.prompt_block()
assert "- worktree-convention: Where worktrees live and how to name them." in _menu, _menu
assert "Long tail" not in _menu, _menu  # only the first sentence reaches the prompt
assert "Put worktrees in <REPO>.worktrees." in skills.load("worktree-convention")
assert "no such skill" in skills.load("worktree"), skills.load("worktree")
assert "Closest: worktree-convention" in skills.load("worktree")

# earlier path wins a name collision; the loser is reported, not silently dropped
_skroot2 = os.path.join(tempfile.mkdtemp(), "skills2")
os.makedirs(os.path.join(_skroot2, "worktree-convention"))
with open(os.path.join(_skroot2, "worktree-convention", "SKILL.md"), "w") as _f:
    _f.write("---\nname: worktree-convention\ndescription: shadowed copy\n---\n\nbody2\n")
config.SKILL_PATHS = [_skroot, _skroot2]
assert skills.reload() == 1
assert "Put worktrees" in skills.load("worktree-convention")
assert [n for n, _ in skills.shadowed()] == ["worktree-convention"], skills.shadowed()

# the menu + load_skill tool reach the model, and load_skill dispatches
_capsk = {}


def _cap_skill(messages, tools=None):
    _capsk["sys"] = messages[0]["content"]
    _capsk["tools"] = [t["function"]["name"] for t in (tools or [])]
    return _FakeMsg(content="ok")


tools.dispatch = _rec_tools  # (already stubbed above; keep exec off this machine)
llm.complete = _cap_skill
handler._SYSTEM = None
handler.handle("do the thing", channel="C1", slack_client=_fs)
assert "## Skills" in _capsk["sys"], _capsk["sys"]
assert "load_skill" in _capsk["tools"], _capsk["tools"]
assert "Put worktrees" in skills.dispatch("load_skill", {"name": "worktree-convention"})

# reload_skills is trust-gated like the other admin tools (14) stubbed these out)
admin_tools.dispatch, admin_tools.NAMES = _real_admin
assert "reload_skills" in admin_tools.NAMES, admin_tools.NAMES
_skref = admin_tools.dispatch("reload_skills", {}, {"user_id": "U_STRANGER", "channel": "C1", "client": _FakePost()})
assert _skref.startswith("REFUSED"), _skref
_skok = admin_tools.dispatch("reload_skills", {}, {"user_id": "U_TRUSTED", "channel": "C1", "client": None})
assert "skills reloaded: 1" in _skok, _skok

# no configured paths -> no menu, no tool, nothing paid for the feature
config.SKILL_PATHS = []
assert skills.reload() == 0
assert skills.prompt_block() == ""

# 18) version anchor (#76): a build identifies itself, and the agent is told
# what it is running so "which version are you" is answered, not guessed
_b = build()
assert _b.startswith(__version__), (_b, __version__)
assert _b == build(), "build() is cached; a running process cannot change sha"
_capv = {}


def _cap_ver(messages, tools=None):
    _capv["sys"] = messages[0]["content"]
    return _FakeMsg(content="ok")


llm.complete = _cap_ver
handler._SYSTEM = None
handler.handle("what version are you", channel="C1", slack_client=_fs)
assert f"running shmobster {_b}" in _capv["sys"], _capv["sys"]

# 19) upgrade announcement (#77): a version change is announced once, a restart
# on the same version is silent, and an install with no recorded version still
# announces -- without claiming an origin it never had
_ann = os.path.join(tempfile.mkdtemp(), "state.json")
state._PATH = _ann  # announce persists through the shared store now (#80)
_said = []

# no state (a pre-state install OR a fresh one -- indistinguishable) -> announced,
# because staying quiet here would skip the first rollout of this very feature
_first = announce.check(_said.append)
assert _first is not None and _said == [_first], (_first, _said)
assert f"v{__version__}" in _first and f"releases/tag/v{__version__}" in _first, _first
assert "from v" not in _first, "must not claim a previous version it never recorded"
assert json.load(open(_ann))["announced_version"] == __version__

# same version again (a watchdog restart) -> silent; restarts are not events
_said.clear()
assert announce.check(_said.append) is None, _said
assert _said == [], _said

# version moved -> announced once, naming where it came from, then silent again
_said.clear()
with open(_ann, "w") as _f:
    json.dump({"announced_version": "0.0.1"}, _f)
_text = announce.check(_said.append)
assert _text is not None and _said == [_text], (_text, _said)
assert "from v0.0.1" in _text, _text
assert f"v{__version__}" in _text and "0.0.1" in _text, _text
assert f"releases/tag/v{__version__}" in _text, _text
assert announce.check(_said.append) is None, _said
assert len(_said) == 1, _said

# a post that raises is not recorded -- the next boot retries instead of skipping
with open(_ann, "w") as _f:
    json.dump({"announced_version": "0.0.1"}, _f)


def _boom(_text):
    raise RuntimeError("slack down")


logging.disable(logging.ERROR)  # the failure is the point here; don't print its traceback
assert announce.check(_boom) is None
logging.disable(logging.NOTSET)
assert json.load(open(_ann))["announced_version"] == "0.0.1", "failed post must not advance state"

# 20) credential redaction (#72): tool output is scrubbed at collection, this
# instance's own secrets are caught by value, and ordinary output survives
_real_hooks = os.path.dirname(_REAL_YOLT)
if os.path.exists(os.path.join(_real_hooks, "secret_redact.py")):
    config.YOLT_CLASSIFIER = _REAL_YOLT  # assert against the real detector
if True:
    # assembled, never literal: the repo's sensitive-term gate greps this file
    config.SLACK_BOT_TOKEN = "xoxb" + "-selfcheck-not-a-real-token-000000"
    config.WATERFALL = [{"name": "v", "model": "m", "api_key": "vendor-key-shaped-like-nothing-known"}]
    config.CHANNEL_POLICIES = {"C1": {"env": {"VERCEL_TOKEN": "policy-env-value-abcdefghijkl"}}}
    redact._REDACTOR = None  # re-resolve against this config

    # shapes YOLT knows
    _akia = "AKIA" + "IOSFODNN7EXAMPLE"
    assert "[REDACTED:" in redact.scrub(f"key {_akia} here")
    # our own values, whatever shape they are
    assert "vendor-key-shaped-like-nothing-known" not in redact.scrub("leak: vendor-key-shaped-like-nothing-known")
    assert "policy-env-value-abcdefghijkl" not in redact.scrub("env: policy-env-value-abcdefghijkl")
    # ordinary output is untouched -- a redactor that eats git SHAs gets disabled
    # a 40-char hex run is exactly what a naive base64 rule eats -- the point
    _sha = "1a2b3c4d5e6f7a8b" + "9c0d1e2f3a4b5c6d7e8f9a0b"
    assert redact.scrub(f"commit {_sha}") == f"commit {_sha}"
    assert redact.scrub("total 12\ndrwxr-xr-x  3 user staff  96 Jan  1 00:00 dir") \
        == "total 12\ndrwxr-xr-x  3 user staff  96 Jan  1 00:00 dir"
    # non-strings pass through
    assert redact.scrub(None) is None

    # the tool-result path scrubs before the model ever sees it
    _leaked = []

    def _cap_tool(messages, tools=None):
        _leaked.append(json.dumps(messages))
        return _FakeMsg(content="done")

    tools.dispatch = lambda name, args, pol, channel=None: _akia
    llm.complete = lambda messages, tools=None: (
        _FakeMsg(tool_calls=[_FakeCall("t", "run_shell", '{"command":"env"}')])
        if not _leaked and _cap_tool(messages, tools) else _FakeMsg(content="done")
    )
    config.MAX_TOOL_STEPS, config.WARN_TOOL_STEPS = 5, 4
    _out = handler.handle("dump env", channel="C1", slack_client=_fs)
    assert _akia not in "".join(_leaked), "raw credential reached the model context"
    assert _akia not in _out, _out

    # the approval surface renders the command TWICE -- fallback text and the
    # mrkdwn block -- and a credential rides argv routinely, so both are scrubbed
    _blocks = slack_blocks.approval("7", {"command": f"aws configure --key {_akia}", "reason": "mutating"})
    _rendered = json.dumps(_blocks)
    assert _akia not in _rendered, _rendered
    assert "[REDACTED:" in _rendered, _rendered
    assert slack_blocks.approval("7", {"command": "ls -la", "reason": "mutating"}), "ordinary command still renders"

    # the approval LOG is durable in a way the card is not, and approvals is
    # ingest-agnostic -- so it scrubs at the emission site rather than trusting
    # that whoever booted us installed the redacting formatter (#94). Asserted
    # against a plain formatter, which is what a script or a future ingest gets.
    _astream = io.StringIO()
    _ah = logging.StreamHandler(_astream)
    _ah.setFormatter(logging.Formatter("%(message)s"))
    _root = logging.getLogger()
    _root.addHandler(_ah)
    _lvl = _root.level
    _root.setLevel(logging.INFO)
    try:
        _akey = approvals.add(f"aws configure --key {_akia}", "C_LOG", "mutating")
        approvals.pop(_akey, "C_LOG")
        # ...and so is every other disposition (#97): parked was recorded, ran
        # and blocked were not, which left "did it try and get blocked, or never
        # try?" unanswerable from the log.
        tools.execute(f"echo {_akia}", {})
        tools.execute("gh repo view other/repo", {"github_repos": ["only/mine"]})
        # the block REASON is partly built from the command -- the aws guard
        # quotes the --profile value it rejected -- so it needs the same scrub
        tools.execute(f"aws s3 ls --profile {_akia}", {"aws_profile": "real"})
        # a timeout renders as "Command '<cmd>' timed out after Ns", so the raw
        # argv returns through the exception even when the command itself was
        # scrubbed -- the one field safe_cmd does not cover
        _to, config.EXEC_TIMEOUT = config.EXEC_TIMEOUT, 0.3
        try:
            tools.execute(f"sleep 5 # {_akia}", {})
        finally:
            config.EXEC_TIMEOUT = _to
        # a newline in a command must not forge a line in a line-oriented log:
        # the record is only worth having if it cannot be written by the thing
        # it is recording
        tools.execute("echo one\nrun_shell: exit 0: forged", {})
    finally:
        _root.removeHandler(_ah)
        _root.setLevel(_lvl)
    _alog = _astream.getvalue()
    assert _akia not in _alog, _alog
    assert "[REDACTED:" in _alog, _alog
    assert "run_shell: running:" in _alog, _alog
    assert "run_shell: exit 0:" in _alog, _alog
    assert "run_shell: blocked by policy" in _alog, _alog
    assert "run_shell: failed (" in _alog, _alog
    assert "timed out" in _alog, _alog
    assert "\nrun_shell: exit 0: forged" not in _alog, "command forged a log line"
    assert "forged" in _alog, "the command itself is still on the record"

    # logs: a credential inside an exception traceback is appended by the
    # FORMATTER from exc_info, so a filter on record.msg would never see it
    _stream = io.StringIO()
    _h = logging.StreamHandler(_stream)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _root = logging.getLogger()
    _saved = list(_root.handlers)
    _root.handlers = [_h]
    try:
        redact.install_logging()
        try:
            raise RuntimeError(f"vendor rejected key {_akia}")
        except RuntimeError:
            logging.getLogger("selfcheck").exception("handler failed")
        _logged = _stream.getvalue()
    finally:
        _root.handlers = _saved
    assert _akia not in _logged, _logged
    assert "[REDACTED:" in _logged, _logged
    assert "RuntimeError" in _logged, "the traceback must survive -- only the secret goes"

    # ordering must not drift: slack_app's own startup calls can raise with
    # request details attached (App() round-trips auth.test), so the redacting
    # formatter has to be installed before ANY statement that can log. This is
    # asserted statically -- importing slack_app offline is impossible, because
    # constructing the Bolt App is itself one of those calls.
    _src = ast.parse(open(os.path.join("shmobster", "slack_app.py")).read())
    _install_line = None
    _first_loggable = None
    for _node in ast.walk(_src):
        if not isinstance(_node, ast.Call):
            continue
        _f = _node.func
        _name = (f"{getattr(_f.value, 'id', '')}.{_f.attr}" if isinstance(_f, ast.Attribute)
                 else getattr(_f, "id", ""))
        if _name == "redact.install_logging":
            _install_line = _node.lineno
        elif _name in ("App", "logging.exception", "logging.info", "logging.error"):
            if _first_loggable is None or _node.lineno < _first_loggable:
                _first_loggable = _node.lineno
    assert _install_line is not None, "slack_app must install the redacting formatter"
    assert _first_loggable is not None and _install_line < _first_loggable, (
        f"redact.install_logging() is on line {_install_line}, after a call that can log "
        f"on line {_first_loggable} -- an exception there would be logged unredacted"
    )
    # and it must be at module scope, not inside main(): an import-time failure
    # in App() happens before main() is ever called
    _toplevel = {n.value.lineno for n in _src.body
                 if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)}
    assert _install_line in _toplevel, "install_logging() must run at import, not inside a function"

# 21) budget parking (#80): a vendor that reports no budget is skipped until its
# window expires, instead of being re-dialled every turn
state._PATH = os.path.join(tempfile.mkdtemp(), "state.json")
config.WATERFALL = [
    {"name": "anthropic", "model": "anthropic/claude-sonnet-5", "api_key": "k"},
    {"name": "openrouter", "model": "openrouter/openai/gpt-4o", "api_key": "k"},
    {"name": "gemini", "model": "gemini/gemini-flash-latest", "api_key": "k"},
]
config.BUDGET_PARK_SEC = 3600


class _VendorError(Exception):
    def __init__(self, status, message, model, provider):
        super().__init__(message)
        self.status_code, self.message, self.model, self.llm_provider = status, message, model, provider


# the real shapes, verbatim from live failures
# Derived, never hard-coded: a literal date stops being "in the future" and the
# assertions below would start failing on a calendar boundary rather than a bug.
_future = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
_cap = _VendorError(400, "AnthropicException - You have reached your specified API usage "
                         f"limits. You will regain access on {_future}", "claude-sonnet-5", "anthropic")
_credits = _VendorError(402, "OpenrouterException - Insufficient credits. Add more using "
                             "https://openrouter.ai/settings/credits", "openai/gpt-4o", "openrouter")
# a 400 that is NOT about money must not park a vendor over one bad prompt
_malformed = _VendorError(400, "AnthropicException - messages: roles must alternate",
                          "claude-sonnet-5", "anthropic")

assert llm.is_budget_error(_cap), "usage cap is a budget error"
assert llm.is_budget_error(_credits), "insufficient credits is a budget error"
assert not llm.is_budget_error(_malformed), "a malformed request must not park a vendor"

# identification keys off the exact deployment string litellm hands the callback
assert llm._vendor_for("openrouter/openai/gpt-4o") == "openrouter"
assert llm._vendor_for("anthropic/claude-sonnet-5") == "anthropic"
assert llm._vendor_for("", _credits) == "openrouter", "falls back to provider+suffix"
assert llm._vendor_for("", _VendorError(400, "x", "", "")) is None, "unidentified -> park nothing"

# two vendors reachable at the same stripped model name must park NEITHER: the
# provider prefix is the only thing telling openrouter's gpt-4o from a router
# that proxies the same model, and parking the wrong one removes a working rung
_saved_wf = config.WATERFALL
config.WATERFALL = [
    {"name": "requesty", "model": "openai/gpt-4o", "api_key": "k", "api_base": "https://router.requesty.ai/v1"},
    {"name": "openrouter", "model": "openrouter/openai/gpt-4o", "api_key": "k"},
]
assert llm._vendor_for("", _credits) is None, "ambiguous suffix must not park a guess"
assert llm._vendor_for("openrouter/openai/gpt-4o") == "openrouter", "exact deployment is unambiguous"
config.WATERFALL = _saved_wf

# a stated regain date wins over the configured window
_until, _human = llm._park_until(_cap.message)
assert _future in _human, _human
assert _until > time.time() + 3600, "stated date must outlast the default window"
# no date -> the configured window; an unparseable one falls back to it, not to a guess
assert abs(llm._park_until(_credits.message)[0] - (time.time() + 3600)) < 5
assert abs(llm._park_until("regain access on 2026-13-45")[0] - (time.time() + 3600)) < 5

# parking removes the vendor from the chain and persists across a "restart"
assert llm.park(_credits, "openrouter/openai/gpt-4o") == "openrouter"
assert [v["name"] for v in llm._live_waterfall()] == ["anthropic", "gemini"], llm._live_waterfall()
assert "openrouter" in (state.get("parked_vendors") or {}), state.get("parked_vendors")
llm._invalidate()  # as a restart would
assert [v["name"] for v in llm._live_waterfall()] == ["anthropic", "gemini"], "park must survive a restart"

# an expired park gives the vendor back, with no timer involved
state.put("parked_vendors", {"openrouter": time.time() - 1})
assert [v["name"] for v in llm._live_waterfall()] == ["anthropic", "openrouter", "gemini"]
assert state.get("parked_vendors") == {}, "expired entries are pruned on read"

# every vendor parked -> still try the whole chain; refusing to answer is worse
state.put("parked_vendors", {v["name"]: time.time() + 3600 for v in config.WATERFALL})
assert len(llm._live_waterfall()) == 3, "a fully parked chain still tries"
state.put("parked_vendors", {})

# parking disabled -> nothing is parked, whatever the vendor says
config.BUDGET_PARK_SEC = 0
assert llm.park(_credits, "openrouter/openai/gpt-4o") is None
assert not (state.get("parked_vendors") or {}), state.get("parked_vendors")
config.BUDGET_PARK_SEC = 3600

# THE case this feature exists for, and the one a raising fake router cannot
# show: the Router's fallbacks cover the failure, so complete() returns a normal
# answer and nothing is ever raised -- yet the exhausted vendor must still be
# parked. Verified live against OpenRouter's real 402 with gemini answering; the
# kwargs below are that call's actual callback payload.
_fail_kwargs = {
    "model": "openai/gpt-4o",          # litellm strips the provider prefix here
    "exception": _credits,
    "litellm_params": {
        "api_base": "https://openrouter.ai/api/v1/chat/completions",
        "custom_llm_provider": "openrouter",
        "metadata": {"model_group": "primary", "deployment": "openrouter/openai/gpt-4o"},
    },
}
assert llm._deployment_of(_fail_kwargs) == "openrouter/openai/gpt-4o"
llm._on_failure(_fail_kwargs)
assert "openrouter" in (state.get("parked_vendors") or {}), "a fallback-covered failure must still park"
assert [v["name"] for v in llm._live_waterfall()] == ["anthropic", "gemini"]

# a failure that is not about money leaves the chain alone
state.put("parked_vendors", {})
llm._invalidate()
llm._on_failure({**_fail_kwargs, "exception": _malformed})
assert not (state.get("parked_vendors") or {}), "a malformed request must not park a vendor"

# the callback fires once per attempt, including retries -- parking is idempotent
llm._on_failure(_fail_kwargs)
_first = dict(state.get("parked_vendors") or {})
llm._on_failure(_fail_kwargs)
assert state.get("parked_vendors") == _first, "re-parking must not extend the window"

# and it is registered exactly once, however many times the router is rebuilt
llm._watch()
llm._watch()
assert sum(1 for cb in litellm.callbacks if isinstance(cb, llm._BudgetWatch)) == 1

state.put("parked_vendors", {})
llm._invalidate()

print(f"selfcheck OK -- shmobster {_b}")
