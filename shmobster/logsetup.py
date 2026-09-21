"""Where the agent's own log goes (#155).

Its own module rather than a few lines in slack_app, for one reason: importing
slack_app builds the Bolt App, which calls auth.test and dies without a real
token -- so nothing offline can reach a function that lives there. A log
handler is exactly the kind of thing that should be checkable offline.
"""
import logging
import logging.handlers
import os
import stat

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


# 10 MB is logsetup's own rollover size, so a supervisor file past it is one
# that would already have rotated had the managed log been on (#230).
_STDERR_BIG = 10 * 1024 * 1024


def warnings():
    """What is wrong with where this process's log is actually going (#230).

    Two things, and the second is the one that cost 251 MB.

    **The managed log is opt-in and silently off.** Without `logging.path`,
    handler() returns a StreamHandler and everything goes to stderr, where the
    supervisor decides the mode and nothing rotates -- which is the exact
    failure #155 was written to fix, still reachable by leaving one key out.

    **The supervisor's own file exists either way.** launchd redirects stderr
    to StandardErrorPath whatever the config says, and the crash that matters
    happens in slack_app's App() constructor at *import*, before main() ever
    calls setup(). So a crash-looping box writes the same traceback into an
    unrotated file forever, and configuring logging.path does not stop it.

    Found by fstat on our own stderr rather than by reading the plist: the
    process does not know its StandardErrorPath, but it can ask what fd 2 is.
    That covers launchd, nohup, `2>file` and anything else, and says nothing
    when stderr is a tty or a pipe."""
    retval = []
    if not config.LOG_PATH:
        retval.append(
            "logging.path is unset, so the agent logs to stderr and whatever "
            "started it owns the file -- unrotated, at a mode this process did "
            "not choose. Set logging.path (see the example config) to get the "
            "rotating 0600 log (#155)"
        )
    try:
        st = os.fstat(2)
    except OSError:
        st = None
    if st is not None and stat.S_ISREG(st.st_mode):
        if st.st_mode & 0o077:
            retval.append(
                f"stderr is a file with mode {st.st_mode & 0o777:04o} -- readable "
                "beyond its owner. It holds every command every channel asked for"
            )
        if st.st_size > _STDERR_BIG:
            retval.append(
                f"stderr is a file of {st.st_size // (1024 * 1024)} MB and nothing "
                "here rotates it -- the supervisor redirected it (launchd's "
                "StandardErrorPath), so rotation is the supervisor's job "
                "(newsyslog.d) or the file needs truncating"
            )
    return retval


def setup():
    """Called from main(), not at import: opening (and chmod-ing) a file is not
    something importing a module should do."""
    logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT, handlers=[handler()])
