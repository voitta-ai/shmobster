"""Announce a version change once, on the first boot after an upgrade (#77).

An instance is restarted constantly -- the watchdog does it, launchd does it --
so "announce on boot" would be noise. The signal is a *version change*: the
last announced version is persisted, and only a difference is worth saying.

Ingest-agnostic on purpose. This module knows nothing about Slack; it takes a
`post(text)` callable, so a second ingest mode (email, CLI, whatever comes) gets
upgrade announcements by passing its own poster. See CLAUDE.md -- a new ingest
that skips this is a mode where operators stop hearing about upgrades."""
import json
import logging
import os

from . import __version__, build

_STATE_PATH = os.getenv("SHMOBSTER_STATE", "shmobster-state.json")

_RELEASE_URL = "https://github.com/voitta-ai/shmobster/releases/tag/v{version}"


def _read_state():
    if not os.path.exists(_STATE_PATH):
        retval = {}
        return retval
    try:
        with open(_STATE_PATH, "r") as f:
            retval = json.load(f)
    except (OSError, ValueError):
        # A corrupt state file must not stop the agent from booting; the worst
        # case is one duplicate announcement.
        retval = {}
    return retval


def _write_state(state):
    try:
        with open(_STATE_PATH, "w") as f:
            json.dump(state, f, indent=2)
        ok = True
    except OSError:
        logging.exception("could not write %s -- upgrade may re-announce", _STATE_PATH)
        ok = False
    return ok


def message(previous):
    """The announcement text. `previous` is the version last announced."""
    url = _RELEASE_URL.format(version=__version__)
    retval = (
        f":sparkles: upgraded to *shmobster v{__version__}* (from v{previous}) "
        f"-- <{url}|release notes>. Now running `{build()}`."
    )
    return retval


def check(post):
    """Announce via `post(text)` if the version changed since the last boot that
    announced. Returns the text posted, or None.

    A missing state file means a new install, not an upgrade: the version is
    recorded silently, so standing up an instance does not announce to a channel
    that has never seen this agent before."""
    state = _read_state()
    previous = state.get("announced_version")
    if previous == __version__:
        retval = None
        return retval
    if previous is None:
        state["announced_version"] = __version__
        _write_state(state)
        logging.info("announce: first boot at %s -- recorded, not announced", __version__)
        retval = None
        return retval
    text = message(previous)
    try:
        post(text)
    except Exception:
        # Do not record: an announcement that failed to post should be retried
        # on the next boot rather than silently skipped.
        logging.exception("announce: could not post upgrade notice")
        retval = None
        return retval
    state["announced_version"] = __version__
    _write_state(state)
    logging.info("announce: %s -> %s announced", previous, __version__)
    retval = text
    return retval
