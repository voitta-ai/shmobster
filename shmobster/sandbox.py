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
external effects, and they stay behind the approval card.

...except in one variant, the offline profile (#348): `profile(pol,
offline=True)` is the same profile with the network and the local IPC that
amounts to it denied on top. It exists for one caller -- an inline interpreter
program in an unattended channel (grant.check_offline), whose card used to
carry only the agent's claim of what the program does. Under this profile the
claim stops mattering: whatever the program does, it reaches what `cp`, `rm`
and `tee` already reach uncarded there, and nothing off the box. See
`_OFFLINE` for what it denies and what it leaves, and `offline_ready` for why
it is probed before the command is granted."""
import os
import shutil
import subprocess
import sys
import tempfile

from . import config, policy, spine

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

# gh keeps its token in the keychain, and then hosts.yml holds only the
# login. Where the keychain is unavailable gh writes the token into this
# file instead -- and a read-only cat of it would post the token into Slack.
# When that is the case the file is denied to every channel: gh is then
# unauthenticated in the sandbox rather than a leak. Fixed by `gh auth login`
# on a host with a working keychain.
_GH_HOSTS = "~/.config/gh/hosts.yml"

# The offline profile's additions (#348), appended after everything else so
# they are the profile's last word. They are what makes an interpreter's
# program irrelevant to its safety, so each one answers "how else could a
# program with no socket still reach off the box, or reach a secret the
# channel was not given?":
#
# - `network*`: every socket operation, inet and unix alike -- outbound
#   TCP/UDP to anywhere including 127.0.0.1, DNS (the resolver is a unix
#   socket to mDNSResponder), and a connect to a daemon's socket: docker, an
#   ssh agent, a database. Also bind and listen, so nothing on the box can
#   reach in to collect.
# - `mach-lookup`: the other half of local IPC on Darwin. A program with no
#   socket can still ask a daemon to act for it: the keychain (securityd),
#   the pasteboard, AppleEvents and LaunchServices -- `open` or `osascript`
#   start a process outside this sandbox, network and all. Two services are
#   carved back, both measured as needed and neither able to act elsewhere:
#   directory lookups (getpwuid), without which Python's `pwd`, node's
#   `os.userInfo()` and git's identity fail -- it answers who a uid is; and
#   dirhelper, which hands out the per-user temp dir, without which every
#   Python start prints a confstr() warning into the output.
# - `job-creation`: launchd jobs. `launchctl` reaches launchd through the
#   bootstrap port, not a mach-lookup (`launchctl print` still answers under
#   this profile), and a submitted job would run outside this sandbox. NOT
#   measured: proving it means attempting a submit, which creates a job if
#   the deny does not hold.
# - `signal`, except to this sandbox's own processes: a signal could stop the
#   agent or anything else the operator runs. `(target others)` was measured
#   NOT to stop a signal to an unrelated process, hence deny-all plus the
#   same-sandbox allow; the command's own children are in the same sandbox,
#   so `subprocess` timeouts and terminate() still work.
# Left reachable, on purpose: the filesystem exactly as the base profile
# draws it (reads and writes are the channel's own), the channel's own `env`,
# POSIX/SysV shared memory and semaphores (they need a cooperating process
# that already runs outside, which this cannot start), and the rest of
# `(allow default)`.
#
# Left reachable, NOT on purpose: the argv and environment of every other
# process this user runs -- this agent's own included -- through the
# KERN_PROCARGS2 sysctl. Measured on Darwin 25: neither `process-info*`
# (target others), nor `sysctl-read` by name, nor `sysctl-read` denied
# outright stops it, and `process-info*` denied outright stops the
# interpreter from starting. A program here can therefore print any
# credential this agent holds in its environment. Open question for #348.
_OFFLINE = (
    "(deny network*)",
    "(deny mach-lookup)",
    '(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo")'
    ' (global-name "com.apple.bsd.dirhelper"))',
    "(deny job-creation)",
    "(deny signal)",
    "(allow signal (target same-sandbox))",
)

# What the probe runs: no shell, no file, nothing but the profile itself being
# compiled and applied by the kernel.
_PROBE = "/usr/bin/true"


def gh_file_backed():
    """True when gh's hosts.yml carries a token."""
    retval = False
    try:
        with open(os.path.expanduser(_GH_HOSTS), "r") as f:
            retval = "oauth_token:" in f.read()
    except OSError:
        retval = False
    return retval


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


def _git_root(path):
    """The nearest directory at or above `path` holding a `.git`, or None."""
    cur = os.path.realpath(path)
    retval = None
    while True:
        if os.path.exists(os.path.join(cur, ".git")):
            retval = cur
            break
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return retval


def self_roots():
    """What this agent runs from, as realpaths: its own checkout, its venv, its
    state, log and trajectory files, and the voitta-yolt checkout it asks for a
    verdict. No channel may write any of them, whatever its tree covers.

    A channel's tree is the operator's choice, and a wide one -- a parent of
    several repos -- can contain the deployment itself. The grant layer vouches
    for an in-tree write on the verb, so without this a `sed -i` on the
    classifier is granted as an in-tree write and changes the verdict on the
    very next command (it is spawned per call), and a `tee` into this package
    or its venv runs unconfined at the next restart. SELF_FILES and the spine
    cover single files; this covers the code that reads them."""
    from . import state, trajectory  # deferred: both are leaves, kept off import order
    pkg = os.path.dirname(os.path.realpath(__file__))
    out = [_git_root(pkg) or pkg]
    if sys.prefix != sys.base_prefix:
        out.append(os.path.realpath(sys.prefix))
    out.append(os.path.realpath(state._PATH))
    out.append(os.path.realpath(trajectory._DIR))
    if config.LOG_PATH:
        out.append(os.path.dirname(_real(config.LOG_PATH)))
    if config.YOLT_CLASSIFIER:
        classifier = _real(config.YOLT_CLASSIFIER)
        # Its checkout when it has one; otherwise only its own directory, never
        # a parent guessed from the layout -- a stub in $TMPDIR would take the
        # whole temp dir with it.
        out.append(_git_root(os.path.dirname(classifier)) or os.path.dirname(classifier))
    retval = list(dict.fromkeys(out))
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


def profile(pol, offline=False):
    """The seatbelt profile for one channel policy. Later rules win. With
    `offline`, the network and network-shaped IPC are denied too (#348)."""
    writes, reads, deny = roots(pol)
    cwd = _real(policy.cwd_for(pol))
    excludes = [_real(p, cwd) for p in (pol.get("exclude") or [])]
    if gh_file_backed():
        excludes.append(_real(_GH_HOSTS))
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
    # After the write allow, so it wins: this deployment's own config and
    # policy files are neither readable nor writable from a channel, whatever
    # its cwd (#147). Before the `exclude` deny rather than after it only so
    # that the channel's own exclusions stay the profile's last word; two
    # denies do not compete.
    #
    # `file-write*` is the whole write surface, not just open-for-write:
    # verified on Darwin 25 that `mv`, `cp`, `sed -i` (which renames its temp
    # over the target), `rm`, `ln -sf`, a hardlink-then-rename, and the same
    # through `sh -c` or a shell variable all fail with "Operation not
    # permitted" and leave the file byte-identical. That is what makes the
    # textual guard in policy.py a courtesy message rather than the defence.
    #
    # The read deny costs a "Operation not permitted" line from `ls -l` and
    # `git status` on these two files and nothing else -- measured -- and buys
    # the read half the same independence from text matching.
    # Literals, not subpaths: they are files, realpath'd once at load, and an
    # absent path (no policy file yet, inline back-compat) still resolves, so
    # planting one later is denied too.
    if config.SELF_FILES:
        lines.append(
            "(deny file-read* file-write* "
            + " ".join(f"(literal {_quote(p)})" for p in config.SELF_FILES)
            + ")"
        )
    # The agent's own standing prompt (#174): write-denied, read left alone.
    # It is re-read into the system prompt every turn, so an in-tree write to it
    # is the shortest path there is to changing how the agent behaves; it is
    # also not a secret, and a channel greps its own tree.
    _spine = spine.files()
    if _spine:
        lines.append(
            "(deny file-write* "
            + " ".join(f"(literal {_quote(p)})" for p in _spine)
            + ")"
        )
    # The deployment's own code, venv, runtime files and classifier: read left
    # alone, writes denied (see self_roots). A channel whose tree IS the live
    # checkout keeps git working -- `git worktree add` and a commit in a
    # worktree write the main `.git/` -- so that gitdir is carved back, but
    # only where the channel could already write it; an allow here must not
    # widen anyone. The hooks/config deny below still wins inside it.
    _self = self_roots()
    lines.append(
        "(deny file-write* " + " ".join(f"(subpath {_quote(p)})" for p in _self) + ")"
    )
    _gitdirs = [os.path.join(p, ".git") for p in _self
                if os.path.isdir(os.path.join(p, ".git"))
                and any(_under(os.path.join(p, ".git"), w) for w in writes)]
    if _gitdirs:
        lines.append(
            "(allow file-write* " + " ".join(f"(subpath {_quote(p)})" for p in _gitdirs) + ")"
        )
    # git's own directory is not data, it is code git will run (#184). The
    # grant layer vouches for an in-tree write on the verb alone, and `.git/`
    # is in the tree, so `tee .git/hooks/pre-commit` + `chmod +x` + `git commit`
    # -- three commands the layer already grants -- executed arbitrary code with
    # no card. Writing `.git/config` reaches the same place without a commit:
    # `diff.external` runs on the next `git diff --ext-diff`, which is a read.
    # #183 refused that command spelled as `git -c diff.external=CMD`; refusing
    # the flag while leaving the file writable would close the door and leave
    # the window.
    #
    # Regexes rather than literals because the tree has more than one gitdir:
    # the channel's repo, every worktree under `<cwd>.worktrees`, each
    # `config.worktree` beside them, and `.git/modules/<name>/` for a submodule,
    # whose hooks and config are a second copy of exactly this hazard one level
    # down -- hence `(.+/)?` rather than an anchored `hooks/`.
    #
    # The regexes above match paths, and a rename moves a directory without
    # writing any path beneath it: `mv d .git` with `d/config` and `d/hooks/`
    # already inside installs both, and so does `mv d .git/hooks`. So the
    # entries that decide WHICH repository, config and hooks git loads are
    # frozen too -- created, overwritten, deleted or renamed, never from inside
    # the sandbox: every `.git` (a checkout's directory, a worktree's pointer
    # file), a `hooks` directory under one, a linked worktree's admin
    # directory and its `commondir` and `gitdir` files, a submodule's
    # gitdir, and the `worktrees` and `modules` directories holding them --
    # renaming a prebuilt container over either swaps every entry inside. The grant layer validates a worktree's pointer before a command
    # runs (#344); this is what keeps it the pointer git reads when the
    # command does, including after an earlier write in the same command.
    #
    # The cost: `git init`, `git clone`, `git worktree add/remove/prune` and
    # `git submodule add` fail in a channel, approved or not. An operator runs
    # those. (clone already failed here: it writes `.git/config`.)
    #
    # Deliberately NOT all of `.git/`: `git add` and `git commit` are granted
    # and have to write `index`, `objects` and `refs`. Denying those would
    # break the grant layer's own local-write tier rather than the hazard.
    lines.append(
        "(deny file-write* "
        + " ".join((
            r'(regex #"/\.git/(.+/)?hooks/")',
            r'(regex #"/\.git/(.+/)?config$")',
            r'(regex #"/config\.worktree$")',
            r'(regex #"/\.git$")',
            r'(regex #"/\.git/(modules/.+/)?hooks$")',
            r'(regex #"/\.git/(modules/.+/)?worktrees/[^/]+$")',
            r'(regex #"/\.git/(modules/.+/)?worktrees/[^/]+/(commondir|gitdir)$")',
            r'(regex #"/\.git/(modules/.+/)?modules/[^/]+$")',
            r'(regex #"/\.git/(modules/.+/)?(worktrees|modules)$")',
        ))
        + ")"
    )
    if excludes:
        lines.append(
            "(deny file-read* file-write* "
            + " ".join(f"(subpath {_quote(p)})" for p in excludes)
            + ")"
        )
    if offline:
        lines.extend(_OFFLINE)
    retval = "\n".join(lines) + "\n"
    return retval


def wrap(command, pol, network=True, offline=False):
    """argv that runs `command` confined to the channel's tree. Raises
    RuntimeError when the sandbox is unavailable -- the caller must not fall
    back to running unconfined. `network=False` also denies every socket, for
    a caller that runs nothing that should reach anywhere (gitstate's probes).
    `offline` applies the offline profile (#348): the network and the local
    IPC that amounts to it, for an inline interpreter program."""
    exe = shutil.which("sandbox-exec")
    if not exe:
        raise RuntimeError(
            f"sandbox-exec not found on {sys.platform}; refusing to run unconfined (#116)"
        )
    prof = profile(pol, offline) + ("" if network else "(deny network*)\n")
    retval = [exe, "-p", prof, "/bin/sh", "-c", command]
    return retval


def offline_ready(pol):
    """(ok, why): can this channel's offline profile be built AND applied?

    Asked before a command is granted on the strength of that profile (#348),
    so a failure parks the command as it always did instead of surfacing as an
    exec error after the grant. Building is not enough: seatbelt rejects an
    operation name it does not know only when the profile is applied, so a
    Darwin that renamed one would build a profile here and refuse it in
    sandbox-exec. Applying it to `true` is the whole question, for the cost
    of one process."""
    try:
        exe = shutil.which("sandbox-exec")
        if not exe:
            raise RuntimeError(f"sandbox-exec not found on {sys.platform}")
        proc = subprocess.run([exe, "-p", profile(pol, offline=True), _PROBE],
                              capture_output=True, text=True, timeout=10, env={})
        ok = proc.returncode == 0
        why = "" if ok else (proc.stderr.strip() or f"exit {proc.returncode}")
    except Exception as exc:
        ok, why = False, str(exc)
    retval = (ok, why)
    return retval
