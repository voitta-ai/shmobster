"""Confine a command to the channel's tree with macOS sandbox-exec (#116).

The channel policy's `cwd` used to be only the working directory: nothing
stopped an absolute path elsewhere, a symlink inside the tree pointing out of
it, or a path the shell resolves at runtime -- for reads or for writes. The
textual `exclude` guard in policy.py says so in its own docstring ("NOT a
sandbox"). This is the sandbox.

Every command -- YOLT-safe, granted, or approved -- runs as
`sandbox-exec -p <profile> /bin/sh -c <command>` with a seatbelt profile built
per channel from its policy:

- writes: the channel cwd, its sibling `<cwd>.worktrees/` (the worktree
  convention puts a branch worktree next to the repo, not under it), the temp
  dir, `/dev`, a few caches under $HOME the toolchain insists on, and the
  policy's own `allow_write`;
- reads: denied under /Users and /Volumes -- every home, /Users/Shared,
  every mounted drive -- except the tree, the writable caches, the config
  files git/gh need, and the policy's own `allow_read`. The system roots
  (/usr, /opt/homebrew, /Library, /System, /private/etc) stay readable: the
  toolchain lives there and is the same for every channel;
- the policy's `exclude` paths are denied last, so they win.

Allowances are per channel, in the policy, never global, and never for a
credential: a file a channel can read, a read-only `cat` posts into Slack
without a card. Secrets reach a channel through the keychain (gh), the
channel's own `env`, or not at all -- git runs over https so ~/.ssh is never
granted (gitcfg.py). Relative entries in `exclude`, `allow_read` and
`allow_write` resolve against the channel cwd, the way policy._norm_path does.

Seatbelt matches on the resolved vnode path, which is what makes symlinks
unable to escape and why every path here goes through realpath first (`/tmp`
is `/private/tmp` to the kernel). Verified on Darwin 25: a write outside the
allowed subpath and a write through a symlink that resolves outside it both
fail with "Operation not permitted".

Fail closed: if sandbox-exec cannot be found the command does not run. The
sandbox answers *where* a command may reach; approval (approvals.py) answers
*may it run at all*; policy.check answers *is it in scope*. Three gates,
each enforced on every command.

Not contained: the network. `git push`, `gh`, `aws`, `curl -X POST` are
external effects, and they stay behind the approval card."""
import os
import shutil
import sys
import tempfile

from . import policy

# Under $HOME, readable by default: what git and gh read on every invocation,
# and the toolchain roots. Nothing here holds a secret: gh's token is in the
# keychain (hosts.yml carries only the login), git never touches ~/.ssh
# (gitcfg.py), and ~/.aws is absent because credentials there are file-borne.
_HOME_READ = (
    "~/.gitconfig",
    "~/.gitignore_global",
    "~/.config/gh",
    "~/.nvm",
    "~/.local",
)

# Under $HOME, read+write by default: caches the toolchain fails without
# (npm's _cacache and _logs, node-gyp, pip). Caches, not project data.
_HOME_WRITE = (
    "~/.npm",
    "~/.cache",
    "~/Library/Caches",
)

_SYSTEM_WRITE = (
    "/private/tmp",
    "/dev",
)

# Read-denied wholesale; the allows below carve the channel's own paths back
# out. Not $HOME alone: /Users/Shared and every other home are just as far
# outside the tree, and a mounted drive is where the data someone did not
# mean to expose tends to live.
_DENY_READ = (
    "/Users",
    "/Volumes",
)


def _real(path, base=None):
    """realpath of a policy path: ~ and $VARS expanded, a relative entry
    taken against `base` (the channel cwd), never the process cwd."""
    p = os.path.expanduser(os.path.expandvars(path))
    if base is not None and not os.path.isabs(p):
        p = os.path.join(base, p)
    retval = os.path.realpath(p)
    return retval


def _quote(path):
    # Seatbelt string literals: backslash and double quote are the escapes.
    retval = '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return retval


def _under(path, root):
    retval = path == root or path.startswith(root + os.sep)
    return retval


def _ancestors(path, stop):
    """Every directory from `path`'s parent up to and including `stop`.
    Traversal into an allowed subpath needs metadata on each parent, and the
    deny roots are otherwise fully denied."""
    retval = []
    cur = os.path.dirname(path)
    while _under(cur, stop) and cur != os.sep:
        retval.append(cur)
        if cur == stop:
            break
        cur = os.path.dirname(cur)
    return retval


def roots(pol):
    """(write_paths, read_paths, deny_roots) for a channel policy, all
    realpaths. read_paths excludes what is already in write_paths."""
    cwd = _real(policy.cwd_for(pol))
    writes = [cwd, cwd + ".worktrees", _real(tempfile.gettempdir())]
    writes += [_real(p) for p in _SYSTEM_WRITE]
    writes += [_real(p) for p in _HOME_WRITE]
    writes += [_real(p, cwd) for p in (pol.get("allow_write") or [])]
    reads = [_real(p) for p in _HOME_READ]
    reads += [_real(p, cwd) for p in (pol.get("allow_read") or [])]
    writes = list(dict.fromkeys(writes))
    reads = [p for p in dict.fromkeys(reads) if p not in writes]
    deny = [_real(p) for p in _DENY_READ]
    retval = (writes, reads, deny)
    return retval


def profile(pol):
    """The seatbelt profile for one channel policy. Later rules win."""
    writes, reads, deny = roots(pol)
    cwd = _real(policy.cwd_for(pol))
    excludes = [_real(p, cwd) for p in (pol.get("exclude") or [])]
    meta = set()
    for p in writes + reads:
        for root in deny:
            if _under(p, root):
                meta.update(_ancestors(p, root))
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny file-write*)",
        "(allow file-write* " + " ".join(f"(subpath {_quote(p)})" for p in writes) + ")",
        "(deny file-read* " + " ".join(f"(subpath {_quote(p)})" for p in deny) + ")",
    ]
    if meta:
        lines.append(
            "(allow file-read-metadata "
            + " ".join(f"(literal {_quote(p)})" for p in sorted(meta))
            + ")"
        )
    lines.append(
        "(allow file-read* "
        + " ".join(f"(subpath {_quote(p)})" for p in writes + reads)
        + ")"
    )
    if excludes:
        lines.append(
            "(deny file-read* file-write* "
            + " ".join(f"(subpath {_quote(p)})" for p in excludes)
            + ")"
        )
    retval = "\n".join(lines) + "\n"
    return retval


def wrap(command, pol):
    """argv that runs `command` confined to the channel's tree. Raises
    RuntimeError when the sandbox is unavailable -- the caller must not fall
    back to running unconfined."""
    exe = shutil.which("sandbox-exec")
    if not exe:
        raise RuntimeError(
            f"sandbox-exec not found on {sys.platform}; refusing to run unconfined (#116)"
        )
    retval = [exe, "-p", profile(pol), "/bin/sh", "-c", command]
    return retval
