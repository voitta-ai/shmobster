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
  dir, `/dev`, and a few caches under $HOME the toolchain insists on;
- reads: everything outside $HOME (the toolchain lives in /usr, /opt/homebrew,
  /Library), plus under $HOME only the tree, the writable caches, and the
  config files git/gh need; `exec.sandbox.read` / `exec.sandbox.write` in the
  config add to that for one machine's tooling;
- the policy's `exclude` paths are denied last, so they win over everything.

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

from . import config, policy

# Under $HOME, readable by default: what git and gh read on every invocation,
# and the toolchain roots. ~/.ssh is deliberately absent (see config.py).
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


def _real(path):
    retval = os.path.realpath(os.path.expanduser(os.path.expandvars(path)))
    return retval


def _quote(path):
    # Seatbelt string literals: backslash and double quote are the escapes.
    retval = '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return retval


def _ancestors(path, stop):
    """Every directory strictly between `stop` and `path`, plus `stop`
    itself. Traversal into an allowed subpath needs metadata on each parent,
    and $HOME is otherwise fully denied."""
    retval = []
    cur = os.path.dirname(path)
    while (cur == stop or cur.startswith(stop + os.sep)) and cur != os.sep:
        retval.append(cur)
        if cur == stop:
            break
        cur = os.path.dirname(cur)
    return retval


def roots(pol):
    """(write_paths, read_paths) for a channel policy, all realpaths.
    read_paths excludes what is already in write_paths."""
    cwd = _real(policy.cwd_for(pol))
    home = _real("~")
    writes = [cwd, cwd + ".worktrees", _real(tempfile.gettempdir())]
    writes += [_real(p) for p in _SYSTEM_WRITE]
    writes += [_real(p) for p in _HOME_WRITE]
    writes += [_real(p) for p in config.SANDBOX_WRITE]
    reads = [_real(p) for p in _HOME_READ]
    reads += [_real(p) for p in config.SANDBOX_READ]
    writes = list(dict.fromkeys(writes))
    reads = [p for p in dict.fromkeys(reads) if p not in writes]
    retval = (writes, reads, home)
    return retval


def profile(pol):
    """The seatbelt profile for one channel policy. Later rules win."""
    writes, reads, home = roots(pol)
    excludes = [_real(p) for p in (pol.get("exclude") or [])]
    meta = set()
    for p in writes + reads:
        if p.startswith(home + os.sep) or p == home:
            meta.update(_ancestors(p, home))
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny file-write*)",
        "(allow file-write* " + " ".join(f"(subpath {_quote(p)})" for p in writes) + ")",
        f"(deny file-read* (subpath {_quote(home)}))",
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
