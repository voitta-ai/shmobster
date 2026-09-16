"""Boot the agent by reading its workspace .md spine into a system prompt.

Runtime-agnostic: point SHMOBSTER_WORKSPACE at the openclaw-workspace clone and
the same files (SOUL/USER/CALIBRATION/RUNBOOKS/TOOLS) load unchanged. Order
follows openclaw-workspace AGENTS.md."""
import os

from . import config

_SPINE_FILES = ["SOUL.md", "USER.md", "CALIBRATION.md", "RUNBOOKS.md", "TOOLS.md"]


def files():
    """The spine's paths, resolved -- what a channel must not overwrite (#174).

    Absent names resolve too, so creating a `USER.md` that does not exist yet is
    covered by the same denial as editing the `SOUL.md` that does."""
    retval = tuple(os.path.realpath(os.path.join(config.WORKSPACE, name))
                   for name in _SPINE_FILES)
    return retval


def load_system_prompt():
    parts = []
    for name in _SPINE_FILES:
        path = os.path.join(config.WORKSPACE, name)
        if os.path.exists(path):
            with open(path, "r") as f:
                parts.append(f"# {name}\n\n{f.read().strip()}")
    if parts:
        retval = "\n\n---\n\n".join(parts)
    else:
        retval = "You are Shmobster, a terse and capable Slack agent."
    return retval
