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

from . import config


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


def _norm_path(p, base):
    p = os.path.expanduser(os.path.expandvars(p))
    if not os.path.isabs(p):
        p = os.path.join(base, p)
    retval = os.path.normpath(p)
    return retval


def _check_exclude(command, policy):
    """Best-effort guard against a command touching an excluded subtree (#55).

    NOTE: this is NOT a sandbox. cwd only sets the working dir; nothing stops an
    absolute path elsewhere, a symlink, or a shell resolving paths at runtime.
    This blocks the obvious textual cases (`cat ~/g/OneDrive/x`, `cd <excluded>`)
    to raise the bar; real containment needs OS-level sandboxing (see README)."""
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


def check(command, policy):
    for fn in (_check_github, _check_aws, _check_exclude):
        ok, reason = fn(command, policy)
        if not ok:
            return (False, reason)
    return (True, "")
