"""Small persistent key/value store for facts that must survive a restart.

The watchdog and launchd restart this process routinely, so anything the agent
*learned* has to outlive the process or it is re-learned every few minutes. Two
users today: the last announced version (#77) and the parked-vendor expiries
(#80) -- without persistence the second one is pointless, since a restart would
send every turn back to dialling a vendor known to be out of budget.

Not secret (versions and timestamps), but it lives next to the config and is
gitignored: path from SHMOBSTER_STATE, default ./shmobster-state.json.

Read-modify-write per call rather than a cached dict: writes are rare (an
upgrade, a vendor going dark), and re-reading means a second instance or a hand
edit is not silently clobbered."""
import json
import logging
import os

_PATH = os.getenv("SHMOBSTER_STATE", "shmobster-state.json")


def read():
    """The whole state dict. A missing or corrupt file reads as empty -- state is
    a cache of things we learned, never a reason to fail a boot."""
    if not os.path.exists(_PATH):
        retval = {}
        return retval
    try:
        with open(_PATH, "r") as f:
            loaded = json.load(f)
        retval = loaded if isinstance(loaded, dict) else {}
    except (OSError, ValueError):
        logging.warning("state: %s unreadable; treating as empty", _PATH)
        retval = {}
    return retval


def get(key, default=None):
    retval = read().get(key, default)
    return retval


def put(key, value):
    """Merge one key into the file. Returns True on a successful write."""
    data = read()
    data[key] = value
    try:
        with open(_PATH, "w") as f:
            json.dump(data, f, indent=2)
        retval = True
    except OSError:
        logging.exception("state: could not write %s", _PATH)
        retval = False
    return retval
