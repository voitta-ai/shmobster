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
edit is not silently clobbered. Every write holds a thread lock and an flock on
`<state>.lock` (so a second process sharing the file is covered too) and lands
by rename (#363), so a reader never sees a truncated file; a caller
that derives a key's new value from its old one uses update(), not get() then
put()."""
import contextlib
import fcntl
import json
import logging
import os
import threading

_PATH = os.getenv("SHMOBSTER_STATE", "shmobster-state.json")
# Several threads write (the gateway poll on every page, learning, the waterfall):
# one at a time, and through a rename, so a reader never sees a half-written file.
# Reentrant so an update() function may itself call get().
_LOCK = threading.RLock()
# Held depth of _LOCK's interprocess half; only touched while _LOCK is held.
_DEPTH = 0


def lock_path():
    """The interprocess lock's path, `<state>.lock`. The one place it is
    derived: the sandbox denies this same path to every channel (#440)."""
    retval = f"{_PATH}.lock"
    return retval


class _Unlocked(Exception):
    """The interprocess lock could not be taken; the write is refused."""


@contextlib.contextmanager
def _locked():
    """The thread lock plus an flock on `<state>.lock`, held around a whole
    read-modify-write. The rename keeps readers consistent, but two processes
    sharing the file (a second instance, or the old process still finishing
    during a restart) would otherwise each rename their own copy and the last
    one wins, losing the other's key. Readers stay lock-free. Reentrant within
    a thread: only the outermost entry takes the flock. Fails closed: when the
    lock file cannot be opened or locked, raises _Unlocked and nothing is
    written -- an unguarded write is exactly the lost update this prevents."""
    global _DEPTH
    with _LOCK:
        fd = None
        if _DEPTH == 0:
            try:
                fd = os.open(lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
                if os.fstat(fd).st_nlink != 1:
                    # A second name for the lock's inode reaches it past the
                    # sandbox's pathname deny (#440): a hard link planted
                    # before that deny existed. Nothing here makes one.
                    # Refused rather than repaired: two processes replacing
                    # the inode at once can each lock a different one.
                    logging.error(
                        "state: %s has another hard link, so a sandboxed command "
                        "could hold it; not writing. Stop shmobster, delete the "
                        "lock file (it is recreated on the next write), and "
                        "remove the other link", lock_path())
                    raise OSError("lock file has more than one link")
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                logging.exception("state: could not lock %s; not writing", lock_path())
                if fd is not None:
                    os.close(fd)
                raise _Unlocked() from None
        _DEPTH += 1
        try:
            yield
        finally:
            _DEPTH -= 1
            if fd is not None:
                os.close(fd)  # closing the descriptor releases the flock


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


def _write(data):
    """Replace the file with `data` atomically: a temp file in the same
    directory, fsync'd, then renamed over it. The temp file takes the current
    file's mode (a rename carries the temp file's permissions, so a hand-set
    0600 must not widen); a first write gets the umask default, as before. The
    name is unique, so a second process cannot clobber a half-written temp."""
    try:
        mode = os.stat(_PATH).st_mode & 0o777
    except FileNotFoundError:
        mode = None
    tmp = f"{_PATH}.{os.getpid()}.{os.urandom(6).hex()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if mode is not None else 0o666)
    try:
        if mode is not None:
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, _PATH)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def update(key, fn, default=None):
    """Read-modify-write one key under the module lock: `fn` gets the current
    value (or `default`) and returns the new one, which is written. Use this,
    not get() then put(), whenever the new value is derived from the old --
    otherwise two concurrent callers each write their own copy and one update
    is lost. Returns (new value, True on a successful write); when the lock
    cannot be taken, `fn` is not called and this returns (current value, False)."""
    try:
        with _locked():
            data = read()
            value = fn(data.get(key, default))
            data[key] = value
            ok = _save(data)
    except _Unlocked:
        value, ok = get(key, default), False
    retval = (value, ok)
    return retval


def put(key, value):
    """Merge one key into the file. Returns True on a successful write."""
    try:
        with _locked():
            data = read()
            data[key] = value
            retval = _save(data)
    except _Unlocked:
        retval = False
    return retval


def _save(data):
    try:
        _write(data)
        retval = True
    except OSError:
        logging.exception("state: could not write %s", _PATH)
        retval = False
    return retval
