"""Iter 0 config: env-driven, no hardcoded secrets. Everything per-deployment
comes from .env (see .env.example)."""
import os

from dotenv import load_dotenv

load_dotenv()


def _list(name, default=""):
    raw = os.getenv(name, default)
    retval = [x.strip() for x in raw.split(",") if x.strip()]
    return retval


SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")
SLACK_APP_TOKEN = os.getenv("SLACK_APP_TOKEN", "")

# Channels Shmobster will respond in. Empty set = respond anywhere it's mentioned.
CHANNELS = set(_list("SHMOBSTER_CHANNELS"))

AGENT_LABEL = os.getenv("SHMOBSTER_AGENT_LABEL", "shmobster")
WORKSPACE = os.getenv("SHMOBSTER_WORKSPACE", "./workspace")

# Ordered waterfall; first is primary, rest are fallbacks in order.
MODELS = _list("SHMOBSTER_MODELS", "anthropic/claude-sonnet-5")
