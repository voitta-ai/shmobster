"""Git over https for every channel, so nothing ever needs to read ~/.ssh.

ssh needs three files under ~/.ssh: config, known_hosts (host verification is
mandatory without a terminal) and a private key, or an agent that holds one.
Granting the directory to a channel grants a read-only `cat ~/.ssh/id_*` that
runs without a card; denying it breaks `git push`. Neither is acceptable, so
the channel's git does not use ssh at all.

Git >= 2.31 takes configuration from the environment (GIT_CONFIG_COUNT and
GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n), scoped to that one process: the
operator's repos and ~/.gitconfig are untouched, and the entries win over
the global and system config. Four entries:

- url.https://github.com/.insteadOf = git@github.com:  and  ssh://git@github.com/
  Every remote that names github over ssh is used over https. This also
  overrides the opposite rewrite an operator commonly carries in
  ~/.gitconfig (url.ssh://git@github.com/.insteadOf https://github.com/).
- credential.helper = ""  then  !gh auth git-credential
  The empty value resets the helper list; without it git also runs any
  helper configured system-wide -- Homebrew ships credential.helper
  osxkeychain, which hangs inside the sandbox waiting on a keychain prompt.
  gh keeps its token in the keychain, which the sandbox does not restrict,
  and gh itself already runs in every channel.

GIT_TERMINAL_PROMPT=0 goes with them: a git that would otherwise ask for a
password now fails at once instead of holding the command until the timeout.

Verified under the sandbox with ~/.ssh fully denied: `git ls-remote` and an
authenticated `git push --dry-run` both succeed."""
import os
import subprocess

_ENTRIES = (
    ("url.https://github.com/.insteadOf", "git@github.com:"),
    ("url.https://github.com/.insteadOf", "ssh://git@github.com/"),
    ("credential.helper", ""),
    ("credential.helper", "!gh auth git-credential"),
)


def env():
    """The environment additions, as a dict to merge over a channel's env."""
    retval = {"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": str(len(_ENTRIES))}
    for i, (key, value) in enumerate(_ENTRIES):
        retval[f"GIT_CONFIG_KEY_{i}"] = key
        retval[f"GIT_CONFIG_VALUE_{i}"] = value
    return retval


def _run(argv, extra_env=None):
    """(returncode, stdout) or (None, "") when the binary is missing or hangs."""
    retval = (None, "")
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=10,
            env={**os.environ, **(extra_env or {})},
        )
        retval = (proc.returncode, proc.stdout)
    except (OSError, subprocess.SubprocessError):
        retval = (None, "")
    return retval


def preflight():
    """Warnings for a host that cannot run git the way env() assumes: a git
    older than 2.31 ignores GIT_CONFIG_COUNT and would quietly go back to ssh
    and the system credential helpers; a gh that is not logged in cannot
    answer git's credential request. Startup logs these once."""
    retval = []
    rc, out = _run(["git", "config", "--get", "shmobster.preflight"], {**env(), "GIT_CONFIG_COUNT": "1",
                                                                       "GIT_CONFIG_KEY_0": "shmobster.preflight",
                                                                       "GIT_CONFIG_VALUE_0": "ok"})
    if rc is None:
        retval.append("git is not runnable")
    elif out.strip() != "ok":
        retval.append("git ignores GIT_CONFIG_COUNT (needs git >= 2.31); channels would fall back to ssh")
    rc, _ = _run(["gh", "auth", "status", "--hostname", "github.com"])
    if rc is None:
        retval.append("gh is not runnable; git over https has no credential helper")
    elif rc != 0:
        retval.append("gh is not logged in to github.com; git push will fail in every channel")
    return retval
