"""Per-channel policy (Iter #4): the capability envelope keyed by channel.

resolve(channel) -> policy dict {cwd, aws_profile, github_repos}.
check(command, policy) -> (ok, reason): enforces the parts that need command
inspection -- github repo whitelist and aws-profile override guard. cwd and
AWS_PROFILE themselves are applied at exec time (tools.run_shell)."""
import fnmatch
import os
import re
import shlex
import subprocess

from . import config, spine


def resolve(channel):
    retval = config.CHANNEL_POLICIES.get(channel) or config.DEFAULT_POLICY
    return retval


def cwd_for(policy):
    # Expand ~ and $VARS at use-time (#54): a policy cwd like "~/g/git.voitta"
    # is stored verbatim (set via chat, JSON, etc.), but subprocess needs a real
    # absolute path -- an unexpanded "~" makes every command fail with ENOENT
    # before it runs.
    raw = policy.get("cwd") or config.EXEC_CWD
    retval = os.path.expanduser(os.path.expandvars(raw))
    return retval


def _slug(url):
    # git@github.com:owner/repo.git  or  https://github.com/owner/repo(.git)
    m = re.search(r"[:/]([^/:]+/[^/\s]+?)(?:\.git)?/?$", url.strip())
    retval = m.group(1) if m else None
    return retval


def _git_origin(cwd):
    try:
        proc = subprocess.run(
            ["git", "-C", cwd, "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5,
        )
        retval = _slug(proc.stdout) if proc.returncode == 0 else None
    except Exception:
        retval = None
    return retval


def _gh_repo(tokens):
    for i, t in enumerate(tokens):
        if t in ("-R", "--repo") and i + 1 < len(tokens):
            return tokens[i + 1]
    # positional owner/repo, e.g. `gh repo view owner/repo`
    for t in tokens[1:]:
        if re.match(r"^[\w.-]+/[\w.-]+$", t):
            return t
    return None


# A GitHub repo named as a URL, in the three forms git accepts for it.
_GITHUB_URL = re.compile(
    r"^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([\w.-]+/[\w.-]+?)(?:\.git)?/?$"
)


def _tokens(command):
    try:
        retval = shlex.split(command)
    except ValueError:
        retval = command.split()
    return retval


def _check_github(command, policy):
    allowed = policy.get("github_repos") or []
    if not allowed:
        return (True, "")
    tokens = _tokens(command)
    is_gh = "gh" in tokens
    is_git = "git" in tokens
    if not (is_gh or is_git):
        return (True, "")
    # A git command that names a GitHub URL outright (`git ls-remote
    # git@github.com:o/r`, `git push https://github.com/o/r`) targets that
    # repo, not the checkout's origin -- and since #122 every channel's git
    # carries the operator's credential over https, so the named repo is what
    # the whitelist has to be checked against.
    named = [m.group(1) for m in (_GITHUB_URL.match(t) for t in tokens) if m] if is_git else []
    for repo in named:
        if not any(fnmatch.fnmatch(repo, pat) for pat in allowed):
            return (False, f"repo '{repo}' not in channel whitelist {allowed}")
    if named and not is_gh:
        return (True, "")
    repo = _gh_repo(tokens) if is_gh else None
    if not repo:
        repo = _git_origin(cwd_for(policy))
    if not repo:
        return (False, "target github repo undeterminable; blocked by channel policy")
    if any(fnmatch.fnmatch(repo, pat) for pat in allowed):
        return (True, "")
    return (False, f"repo '{repo}' not in channel whitelist {allowed}")


def _check_aws(command, policy):
    prof = policy.get("aws_profile")
    if not prof:
        return (True, "")
    m = re.search(r"--profile[=\s]+(\S+)", command)
    if m and m.group(1) != prof:
        return (False, f"aws --profile override to '{m.group(1)}' blocked (channel allows '{prof}')")
    if "AWS_PROFILE=" in command:
        return (False, "inline AWS_PROFILE override blocked")
    return (True, "")


# A URL's authority, from any scheme. Stops where the authority does -- at '/',
# '?', '#', whitespace or a quote -- because `curl https://example.com?x=1`
# contacts example.com, and a host of "example.com?x=1" would match nothing and
# card a fetch the channel was given.
_URL_HOST = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://([^/\s'\"`?#]+)")

_EGRESS_VERBS = ("curl", "wget")

# git talks to a remote over https without any of the above (#149 review). Only
# these subcommands do: `git log --grep https://x` names a URL and contacts
# nothing, and carding it would be a guard inventing work.
_GIT_NET_SUBS = ("clone", "fetch", "pull", "push", "ls-remote", "submodule", "remote")


def _host_of(authority):
    """The host inside a URL authority: userinfo dropped, port dropped, IPv6
    literal kept whole. `https://evil.test@example.com/` contacts example.com,
    which is why userinfo goes before the port split rather than after."""
    hostport = authority.rsplit("@", 1)[-1]
    if hostport.startswith("["):          # [2001:db8::1]:443 -- the colons are the address
        retval = hostport[: hostport.index("]") + 1] if "]" in hostport else hostport
        return retval.lower()
    retval = hostport.split(":", 1)[0].lower()
    return retval


def _git_subcommand(tokens):
    """The subcommand in a `git` invocation, skipping git's own flags and the
    values of the two that take one."""
    retval = None
    i = tokens.index("git") + 1 if "git" in tokens else len(tokens)
    while i < len(tokens):
        t = tokens[i]
        if t in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        retval = t
        break
    return retval


def check_egress(command, policy):
    """(ok, reason) for the network reach of a read-only command (#149).

    `curl` and `wget` are read-only to YOLT, so they auto-run with no card, to
    any host, and so does `git ls-remote https://<anywhere>`. Everything else that leaves the box -- `nc`, `ssh`, `scp`, a
    `curl -X POST` -- is already mutating and already parks. That left one
    uncarded path off the machine, and the sandbox cannot help: it confines the
    filesystem, not the network. What is left to send is whatever the channel
    may legitimately read, which is its own tree -- a project `.env` or
    `terraform.tfvars` is one `cat` and one `curl` away.

    So a fetch is allowed without a card only when every host it names is in
    the channel's `allow_domains`. Anything else is *mutating*, not blocked: it
    parks for a trusted user, who can say yes. A channel with no
    `allow_domains` cards every fetch, which is the honest default -- the
    alternative is a built-in list that is wrong for somebody.

    The same applies to the git subcommands that contact a remote; the ones
    that do not (`git log --grep https://x`) are left alone.

    A host has to be statically visible in the command, which means a scheme.
    `curl example.com` and `curl "$URL"` park rather than being guessed at:
    this is a textual guard like `exclude`, and it says so instead of pretending
    to parse a shell."""
    tokens = _tokens(command)
    fetches = any(os.path.basename(t) in _EGRESS_VERBS for t in tokens)
    if not fetches and any(os.path.basename(t) == "git" for t in tokens):
        fetches = _git_subcommand(tokens) in _GIT_NET_SUBS
    if not fetches:
        return (True, "")
    hosts = [_host_of(h) for h in _URL_HOST.findall(command)]
    if not hosts:
        return (False, "fetch: no statically known host (use an explicit https:// URL)")
    allowed = [p.lower() for p in (policy.get("allow_domains") or [])]
    for host in hosts:
        if not any(fnmatch.fnmatch(host, pat) for pat in allowed):
            return (False, f"fetch to '{host}' is not in this channel's allow_domains")
    return (True, "")


def _norm_path(p, base):
    p = os.path.expanduser(os.path.expandvars(p))
    if not os.path.isabs(p):
        p = os.path.join(base, p)
    retval = os.path.normpath(p)
    return retval


def _check_exclude(command, policy):
    """Textual guard against a command touching an excluded subtree (#55).

    Not the containment -- that is the sandbox (#116, sandbox.py), which denies
    the same paths in the kernel and so also catches a symlink or a path the
    shell resolves at runtime. This runs first to block the obvious textual
    cases (`cat ~/g/OneDrive/x`, `cd <excluded>`) with a reason the agent can
    read, instead of a bare "Operation not permitted" from the shell."""
    excludes = policy.get("exclude") or []
    if not excludes:
        return (True, "")
    base = cwd_for(policy)
    ex_norm = [_norm_path(p, base) for p in excludes]
    for tok in _tokens(command):
        if "/" not in tok and "~" not in tok:
            continue  # not path-shaped; skip
        cand = _norm_path(tok, base)
        for ex in ex_norm:
            if cand == ex or cand.startswith(ex + os.sep):
                return (False, f"'{tok}' resolves under excluded path {ex}")
    return (True, "")


def _check_self(command, policy):
    """Block a command that names this deployment's own config or policy file
    (#147).

    Writing one is a capability change -- the policy file is `cwd`,
    `allow_read`/`allow_write`, `exclude`, `env` and `env_passthrough` -- and
    the grant layer would run it as an ordinary in-tree write, with no card,
    whenever a channel's cwd is the directory shmobster was started from.

    This is the readable reason, not the defence: it matches tokens, so a
    shell variable, a glob or an `sh -c` hides the path from it. The sandbox
    denies both operations on both files in the kernel (sandbox.py), which is
    what actually holds. This runs first so the agent is told why instead of
    reading "Operation not permitted" off a shell.

    Reads are refused as well as writes, and deliberately: the values are
    `${VAR}` references rather than literals (#73), but a config value is not
    something this agent posts into a channel under any circumstances.
    Changing a channel's policy has a route already -- set_policy, trusted
    users only."""
    if not config.SELF_FILES:
        return (True, "")
    base = cwd_for(policy)
    for tok in _tokens(command):
        if "/" not in tok and "." not in tok:
            continue  # neither path-shaped nor a bare filename
        cand = os.path.realpath(_norm_path(tok, base))
        if cand in config.SELF_FILES:
            return (False, f"'{tok}' is this deployment's own config; use set_policy to change a policy")
    return (True, "")


# Which argument a writing verb actually writes (#174 review). "A spine path
# appears next to a write verb" is not the question: `cp workspace/SOUL.md
# backup.md` reads the spine and writes somewhere else, and `sed -n 1,5p
# workspace/SOUL.md` writes nothing at all. Getting this wrong blocks ordinary
# work in the deployment's own tree, which is a guard nobody keeps.
#
# Verb list mirrors grant.FS_VERBS by hand rather than importing it: grant
# imports this module, so the arrow goes one way. A verb missing here costs a
# readable message, not the denial -- the sandbox is what holds.
def _write_targets(tokens):
    """The paths this command writes, as written. Best effort by design."""
    targets = set()
    for i, tok in enumerate(tokens):
        if tok in (">", ">>") and i + 1 < len(tokens):
            targets.add(tokens[i + 1])
    if not tokens:
        return targets
    verb = os.path.basename(tokens[0])
    args = [t for t in tokens[1:] if not t.startswith("-")]
    if verb in ("cp", "mv", "ln", "install") and len(args) >= 2:
        targets.add(args[-1])           # ... SOURCE DEST
    elif verb in ("tee", "touch"):
        targets.update(args)            # every file argument is written
    elif verb == "chmod":
        targets.update(args[1:])        # the mode is not a path
    elif verb == "sed" and any(t == "-i" or t.startswith("-i") for t in tokens):
        targets.update(args[1:])        # in place only; the script is not a path
    elif verb == "dd":
        targets.update(t.split("=", 1)[1] for t in tokens if t.startswith("of="))
    retval = targets
    return retval


def _check_spine(command, policy):
    """Block a command that writes the agent's own standing prompt (#174).

    `spine.load_system_prompt()` reads these files into the system prompt every
    turn, and when the bundled `./workspace` sits inside a channel's tree the
    grant layer runs `tee workspace/SOUL.md` as an ordinary in-tree write, with
    no card. That is not widening the envelope, it is editing the instructions
    that say how to behave inside it -- including the ones about being honest
    about what has been read (#134). #130 already refuses a channel `skills`
    entry under a writable root for the same reason; this is that hazard with a
    shorter path.

    Writes only, and only where the spine is the *target*. The spine is the
    agent's persona, not a secret, and a channel reads and copies its own tree
    legitimately: `cat workspace/SOUL.md`, `grep terse workspace/SOUL.md >
    /tmp/out` and `cp workspace/SOUL.md backup.md` all pass, because none of
    them writes the spine."""
    paths = spine.files()
    if not paths:
        return (True, "")
    base = cwd_for(policy)
    for tok in _write_targets(_tokens(command)):
        if os.path.realpath(_norm_path(tok, base)) in paths:
            return (False, f"'{tok}' is this agent's own standing prompt; it changes "
                           f"by a human edit or a PR, not from a channel")
    return (True, "")


def check(command, policy):
    for fn in (_check_github, _check_aws, _check_exclude, _check_self, _check_spine):
        ok, reason = fn(command, policy)
        if not ok:
            return (False, reason)
    return (True, "")
