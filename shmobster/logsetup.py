"""Where the agent's own log goes (#155).

Its own module rather than a few lines in slack_app, for one reason: importing
slack_app builds the Bolt App, which calls auth.test and dies without a real
token -- so nothing offline can reach a function that lives there. A log
handler is exactly the kind of thing that should be checkable offline.
"""
import logging
import logging.handlers
import os

from . import config


_LOG_FORMAT = "%(asctime)s %(levelname)s:%(name)s:%(message)s"


class _PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """RotatingFileHandler that keeps every file it opens at 0600.

    A single chmod after construction is not enough, and the failure is
    invisible: each rollover opens a NEW file under the process umask, so with
    a 0022 umask the log is 0600 until it first rotates and 0644 forever after
    -- measured, all three files, while the one assertion that existed only
    looked at the first. Overriding _open covers the initial open and every
    rollover; an archive (.1, .2) inherits its mode from the file it was
    renamed from, which was opened here too."""

    def _open(self):
        retval = super()._open()
        os.chmod(self.baseFilename, 0o600)
        return retval


def handler():
    """The agent's own rotating log when config.logging.path is set (#155).

    Without it, logging goes to stderr and the supervisor decides everything:
    the live deployment's launchd-redirected error log reached 185 MB of mostly
    reconnect noise, mode 0644 on a multi-user box, with nothing to rotate it.
    The contents are redacted at emission, so what leaks is not credentials --
    it is every command every channel asked for, readable by any local account.

    The directory is created 0700 and every file the handler opens is forced to
    0600 (see _PrivateRotatingFileHandler): the stdlib honors the process umask,
    which under launchd is whatever the plist says, and the sample plist cannot
    fix a file that already exists."""
    if not config.LOG_PATH:
        retval = logging.StreamHandler()
        return retval
    directory = os.path.dirname(os.path.abspath(config.LOG_PATH))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    retval = _PrivateRotatingFileHandler(
        config.LOG_PATH, maxBytes=config.LOG_MAX_BYTES, backupCount=config.LOG_BACKUPS,
    )
    return retval


def setup():
    """Called from main(), not at import: opening (and chmod-ing) a file is not
    something importing a module should do."""
    logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT, handlers=[handler()])
