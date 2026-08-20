"""Runnable Iter 1 check -- no Slack, no network, no API keys.

Verifies config parse, spine load, the YOLT gate wiring (yolt stubbed), and the
handler tool-calling loop (llm stubbed). Run from repo root: python selfcheck.py
"""
import os
import tempfile

os.environ["SHMOBSTER_CONFIG"] = "examples/shmobster-config-example.json"
# The example config references its secrets from the environment (#73), and an
# unset one is a hard startup failure by design. Offline sanity must not need
# real keys, so stub every name the example refers to with a placeholder.
for _var in (
    "SLACK_BOT_TOKEN",
    "SLACK_APP_TOKEN",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "NVIDIA_API_KEY",
):
    os.environ.setdefault(_var, f"selfcheck-placeholder-{_var.lower()}")

from shmobster import admin_tools, approvals, config, handler, identity, llm, policy, skills, slack_tools, spine, tools, yolt_gate  # noqa: E402

# 0) config parsed: waterfall + channels + exec block
assert [v["name"] for v in config.WATERFALL] == ["anthropic", "openrouter", "nvidia"], config.WATERFALL
assert len(config.CHANNELS) == 1, config.CHANNELS
_ex_ch = next(iter(config.CHANNELS))  # the example config's placeholder channel id
assert config.YOLT_CLASSIFIER.endswith("grammar_classifier.py"), config.YOLT_CLASSIFIER

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

print("selfcheck OK")
