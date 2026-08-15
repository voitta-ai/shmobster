"""Single JSON config (no .env). Path from SHMOBSTER_CONFIG, default
./shmobster-config.json. See examples/shmobster-config-example.json and README.

Holds everything per-deployment: Slack tokens, agent identity, and the ordered
waterfall. Gitignored; keep it chmod 600 if it holds literal secrets.

Secrets should be referenced from the environment rather than pasted in:
any string value may contain ${VAR} and is expanded from the process
environment at load time (e.g. "api_key": "${GEMINI_API_KEY}"). A referenced
variable that is unset fails startup loudly (never sends an empty key).

macOS note: launchd does NOT read ~/.bash_profile. A launchd-run shmobster only
sees ${VAR} if the variable is in the launchctl environment (export it via
`launchctl setenv` / osx-env-sync) or the plist's EnvironmentVariables."""
import json
import os
import re
from typing import Any

_PATH = os.getenv("SHMOBSTER_CONFIG", "shmobster-config.json")

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _interpolate(obj: Any) -> Any:
    """Recursively expand ${VAR} references in string values from os.environ.
    Fail loudly (not open) on an unset variable, so a missing secret stops
    startup instead of silently degrading to an empty credential."""
    if isinstance(obj, dict):
        retval = {k: _interpolate(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        retval = [_interpolate(v) for v in obj]
    elif isinstance(obj, str):
        missing = []

        def _sub(m):
            name = m.group(1)
            val = os.environ.get(name)
            if not val:  # unset OR empty -> fail loud; never send an empty credential
                missing.append(name)
                replacement = m.group(0)
            else:
                replacement = val
            return replacement

        expanded = _ENV_REF.sub(_sub, obj)
        if missing:
            raise SystemExit(
                "config references unset or empty environment variable(s): "
                + ", ".join(sorted(set(missing)))
                + "\nmacOS launchd does not read ~/.bash_profile; export them via "
                "`launchctl setenv` (osx-env-sync) or the plist EnvironmentVariables."
            )
        retval = expanded
    else:
        retval = obj
    return retval


def _load() -> Any:
    if not os.path.exists(_PATH):
        raise SystemExit(
            f"config not found: {_PATH}\n"
            "copy examples/shmobster-config-example.json to shmobster-config.json "
            "and fill in the values."
        )
    with open(_PATH, "r") as f:
        raw = json.load(f)
    retval = _interpolate(raw)
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

# Liveness watchdog (#66): seconds without a working Socket Mode connection
# before we exit nonzero so the supervisor restarts us. 0 disables it.
#
# The floor is 90s, not "a bit more than a reconnect": the SDK tears a session
# down at ping_interval * 4 (40s under slack_bolt's ping_interval of 10) and
# then needs another cycle to re-establish and pong, and the watchdog wants a
# session to survive 60s before calling it stable. Anything below that turns
# hiccups the SDK heals by itself into a restart loop.
WATCHDOG_TIMEOUT_SEC = _cfg.get("watchdog_timeout_sec", 120)
if isinstance(WATCHDOG_TIMEOUT_SEC, bool) or not isinstance(WATCHDOG_TIMEOUT_SEC, int) or WATCHDOG_TIMEOUT_SEC < 0:
    raise SystemExit(
        "config watchdog_timeout_sec must be a non-negative integer "
        f"(got {WATCHDOG_TIMEOUT_SEC!r})"
    )
if 0 < WATCHDOG_TIMEOUT_SEC < 90:
    raise SystemExit(
        f"config watchdog_timeout_sec ({WATCHDOG_TIMEOUT_SEC}) is too low and would "
        "restart on hiccups the SDK recovers from; use 0 to disable or at least 90"
    )
