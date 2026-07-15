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
WORKSPACE = _agent.get("workspace", "./workspace")

# Ordered list of {name, model, api_key, [api_base]} -- first is primary.
WATERFALL = _cfg.get("waterfall", [])

# Exec (Iter 1): shell commands are gated by voitta-yolt. yolt_classifier is the
# path to voitta-yolt's grammar_classifier.py. Read-only commands auto-run;
# mutating ones are blocked pending approval.
_exec = _cfg.get("exec", {})
YOLT_CLASSIFIER = _exec.get("yolt_classifier", "")
EXEC_CWD = _exec.get("cwd", ".")
EXEC_TIMEOUT = _exec.get("timeout_sec", 30)

# Per-channel policy (Iter #4): channel_id -> {cwd, aws_profile, github_repos}.
# Unlisted channels fall back to default_policy. This is the capability envelope
# keyed by channel (where/what), distinct from who (multi-user, later).
CHANNEL_POLICIES = _cfg.get("channel_policies", {})
DEFAULT_POLICY = _cfg.get("default_policy", {})
