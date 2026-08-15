"""Single JSON config (no .env). Path from SHMOBSTER_CONFIG, default
./shmobster-config.json. See examples/shmobster-config-example.json and README.

Holds everything per-deployment: Slack tokens, agent identity, and the ordered
waterfall. Gitignored; keep it chmod 600 (it holds secrets)."""
import json
import os

_PATH = os.getenv("SHMOBSTER_CONFIG", "shmobster-config.json")


def _load():
    if not os.path.exists(_PATH):
        raise SystemExit(
            f"config not found: {_PATH}\n"
            "copy examples/shmobster-config-example.json to shmobster-config.json "
            "and fill in the values."
        )
    with open(_PATH, "r") as f:
        retval = json.load(f)
    return retval


_cfg = _load()
_slack = _cfg.get("slack", {})
_agent = _cfg.get("agent", {})

SLACK_BOT_TOKEN = _slack.get("bot_token", "")
SLACK_APP_TOKEN = _slack.get("app_token", "")
# channels: list of {name, id}. name is for humans; id is what Slack matches.
_channels = _slack.get("channels", [])
CHANNELS = {c["id"] for c in _channels}
CHANNEL_NAMES = {c["id"]: c.get("name", c["id"]) for c in _channels}

AGENT_LABEL = _agent.get("label", "")  # empty -> auto-derive from Slack (#8)
BOT_USER_ID = ""  # resolved at startup (auth.test) so the agent recognizes itself
WORKSPACE = _agent.get("workspace", "./workspace")

# Ordered list of {name, model, api_key, [api_base]} -- first is primary.
WATERFALL = _cfg.get("waterfall", [])

# Exec (Iter 1): shell commands are gated by voitta-yolt. yolt_classifier is the
# path to voitta-yolt's grammar_classifier.py. Read-only commands auto-run;
# mutating ones park for a trusted user's approval (#48, see approvals.py).
_exec = _cfg.get("exec", {})
YOLT_CLASSIFIER = _exec.get("yolt_classifier", "")
EXEC_CWD = _exec.get("cwd", ".")
EXEC_TIMEOUT = _exec.get("timeout_sec", 30)

# Per-channel policy (Iter #4): channel_id -> {cwd, aws_profile, github_repos}.
# Unlisted channels fall back to default_policy. This is the capability envelope
# keyed by channel (where/what), distinct from who (multi-user, later).
#
# Policies are machine-specific but NOT secret, so they live in their own
# gitignored file (SHMOBSTER_POLICIES, default ./shmobster-policies.json), copied
# from examples/shmobster-policies-example.json. For back-compat, inline
# channel_policies/default_policy in the main config are used when no policy file
# is present.
_POLICIES_PATH = os.getenv("SHMOBSTER_POLICIES", "shmobster-policies.json")


def _load_policies():
    if os.path.exists(_POLICIES_PATH):
        with open(_POLICIES_PATH, "r") as f:
            retval = json.load(f)
        return retval
    retval = {
        "channel_policies": _cfg.get("channel_policies", {}),
        "default_policy": _cfg.get("default_policy", {}),
    }
    return retval


_policies = _load_policies()
CHANNEL_POLICIES = _policies.get("channel_policies", {})
DEFAULT_POLICY = _policies.get("default_policy", {})

# Trusted users (Slack user IDs) who may change my restrictions via chat (#36).
TRUSTED_USERS = set(_cfg.get("trusted_users", []))


def reload_policies():
    """Re-read the policy source into the module globals so a set_channel_policy
    write takes effect without a restart."""
    global CHANNEL_POLICIES, DEFAULT_POLICY, _cfg, _policies
    _cfg = _load()
    _policies = _load_policies()
    CHANNEL_POLICIES = _policies.get("channel_policies", {})
    DEFAULT_POLICY = _policies.get("default_policy", {})


def set_channel_policy(channel_id, updates):
    """Merge `updates` (non-None values) into a channel's policy and persist to
    the active policy source (the separate file if present, else the main
    config), then reload. Returns the new policy. Never touches trusted_users."""
    path = _POLICIES_PATH if os.path.exists(_POLICIES_PATH) else _PATH
    with open(path, "r") as f:
        data = json.load(f)
    cps = data.setdefault("channel_policies", {})
    pol = dict(cps.get(channel_id, {}))
    pol.update({k: v for k, v in updates.items() if v is not None})
    cps[channel_id] = pol
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    reload_policies()
    return pol


# Tool-call loop bounds (configurable). Hard stop at MAX_TOOL_STEPS; once the
# loop has used >= WARN_TOOL_STEPS, the reply carries a "nearing the limit" note.
MAX_TOOL_STEPS = _cfg.get("max_tool_steps", 50)
WARN_TOOL_STEPS = _cfg.get("warn_tool_steps", 40)


def _positive_int(name, v):
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise SystemExit(f"config {name} must be a positive integer (got {v!r})")


_positive_int("max_tool_steps", MAX_TOOL_STEPS)
_positive_int("warn_tool_steps", WARN_TOOL_STEPS)
if WARN_TOOL_STEPS >= MAX_TOOL_STEPS:
    raise SystemExit(
        f"config warn_tool_steps ({WARN_TOOL_STEPS}) must be < "
        f"max_tool_steps ({MAX_TOOL_STEPS})"
    )

# Liveness watchdog (#66): seconds without a Slack ping/pong before we exit
# nonzero so the supervisor restarts us. Must comfortably exceed a normal
# reconnect (~1s); 0 disables the watchdog.
WATCHDOG_TIMEOUT_SEC = _cfg.get("watchdog_timeout_sec", 120)
if isinstance(WATCHDOG_TIMEOUT_SEC, bool) or not isinstance(WATCHDOG_TIMEOUT_SEC, int) or WATCHDOG_TIMEOUT_SEC < 0:
    raise SystemExit(
        "config watchdog_timeout_sec must be a non-negative integer "
        f"(got {WATCHDOG_TIMEOUT_SEC!r})"
    )
if 0 < WATCHDOG_TIMEOUT_SEC < 30:
    raise SystemExit(
        f"config watchdog_timeout_sec ({WATCHDOG_TIMEOUT_SEC}) is too low; "
        "use 0 to disable or at least 30 seconds"
    )
