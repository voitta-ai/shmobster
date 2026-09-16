"""Gate a shell command through voitta-yolt's grammar classifier.

Subprocesses YOLT's `grammar_classifier.py --no-user-allow '<command>'`, which
prints {"decision": "safe"|"unsafe", "reason": ..., "allow_patterns": n}.
"safe" == read-only (auto-run); anything else (unsafe, unknown, error,
unconfigured) is treated as mutating -> needs approval. Fail-closed: if YOLT
can't run, we do NOT auto-run.

Every consumer here compares against "safe" rather than against "unsafe", and
that is load-bearing rather than stylistic: voitta-yolt 2.0.0 adds a fourth
verdict, "deny" (a git-state predicate refusing outright rather than asking).
It is the most restrictive thing the classifier can say, so a branch testing
`== "unsafe"` would let it fall through to the least restrictive path.

`--no-user-allow` is the whole of #148. Without it the classifier promotes any
command matching a `Bash(...)` pattern in `~/.claude/settings.json`,
`<cwd>/.claude/settings.json` or `<cwd>/.claude/settings.local.json` to "safe"
-- and it is subprocessed with this agent's cwd, so the operator's interactive
Claude Code permissions and this repo's own settings decided what a Slack
channel could auto-run. 123 patterns on the deployment host, among them
`gh pr merge*`, `gh api*`, `git push origin feature/*` and `codex exec *`: all
mutating, none ever seen by an approval card, all authorized by a file written
for a human at a terminal. A confused deputy, and the sandbox does not cover
it because these are network effects.

So "safe" here means what YOLT's own rules say, and nothing else. A command an
operator wants auto-run despite that does not exist yet; when one does, it
belongs in shmobster's own config where it is reviewable, not inherited from
somewhere else."""
import json
import logging
import subprocess
import sys

from . import config

_NO_USER_ALLOW = "--no-user-allow"


def _classify_raw(command, flags=(_NO_USER_ALLOW,), cwd=None):
    """(dict, error). The dict is YOLT's parsed output; error is a string when
    it could not be obtained.

    `cwd` is passed as `--cwd`, not as the subprocess's own directory, and the
    difference is the whole point (#182). voitta-yolt 2.0.x's `deny` verdict is
    produced by git-state predicates -- "would push to the default branch" --
    evaluated against the directory the command would run in. Left unsaid, that
    directory is whatever this agent process happens to be in, so the predicate
    reads one repository and answers about another: a false deny citing a branch
    the channel never named, or no deny at all from a non-git directory. The
    flag exists from 2.0.1 and `preflight` refuses to run without it.

    Errors are signalled out of band. On a rejected invocation the classifier
    exits non-zero and writes the reason to stderr, leaving stdout empty -- so a
    caller that only parses stdout reports a JSON decode error where the real
    event was a refusal with a named cause. Check the code, and say what stderr
    said."""
    path = config.YOLT_CLASSIFIER
    if not path:
        return (None, "yolt not configured (exec.yolt_classifier)")
    argv = [sys.executable, path, *flags]
    if cwd:
        argv += ["--cwd", cwd]
    argv.append(command)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    except Exception as exc:
        return (None, f"yolt error: {exc}")
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        why = detail[0] if detail else "no message on stderr"
        return (None, f"yolt exited {proc.returncode}: {why}")
    try:
        return (json.loads(proc.stdout), None)
    except Exception as exc:
        return (None, f"yolt error: {exc}")


def classify(command, cwd=None):
    data, err = _classify_raw(command, cwd=cwd)
    if err:  # fail closed -> mutating
        retval = ("unsafe", err)
        return retval
    retval = (data.get("decision", "unsafe"), data.get("reason", ""))
    return retval


# The probe, and the choice matters (#182). It used to be `cat /dev/null`, a
# read, asserted to come back `safe` -- which is precisely the assertion #177
# removed: under voitta-yolt 2.0.x every ordinary read is `unknown`, delegated
# to a host classifier this agent does not have, and the read-only set now lives
# in grant.READ_VERBS instead. So the probe stopped asking "do you still call
# reads safe" and started asking the question we actually depend on: "do you
# accept --cwd".
#
# It asks with a command no version has ever called anything but unsafe. A
# classifier predating 2.0.1 takes its command from the first non-flag argument,
# so `--cwd` becomes the command and the verdict is `unknown | no rule: --cwd` --
# a verdict about a flag string, with the `rm` never examined. That is the same
# family as handing `--no-user-allow` to a pre-1.2.0 classifier, and it fails
# closed and silent: every command in every channel parks, with nothing saying
# why. From 2.1.0 the classifier rejects the unknown flag outright and exits
# non-zero, which `_classify_raw` now reports with its stderr.
_PROBE = "rm -rf /tmp/shmobster-preflight-probe"
_PROBE_CWD = "/"


def preflight():
    """Warnings for a YOLT this agent cannot run on.

    Three failure modes, all silent, all ending in "every command parks":

    An older classifier takes its command from argv[1], so a flag it does not
    know lands there and every verdict becomes a verdict about that string. One
    that accepts the flags and inherits the allow-lists anyway is worse -- the
    old auto-run surface with nothing to show for it, which is why the count has
    to be reported and has to be zero.

    And one that does not accept `--cwd`, which this agent depends on for a
    reason no verdict reveals: without it voitta-yolt 2.0.x's git-state
    predicates judge whichever directory this process is in rather than the
    channel's, and a `deny` layer asked about the wrong repository does not
    error or warn, it simply never denies (#182)."""
    retval = []
    data, err = _classify_raw(_PROBE, cwd=_PROBE_CWD)
    if err:
        retval.append(err)
        return retval
    if data.get("decision") != "unsafe":
        retval.append(
            f"yolt called {_PROBE!r} {data.get('decision')!r} rather than unsafe when asked "
            f"with --cwd, so it is classifying the flag instead of the command and every "
            f"command in every channel will park. This yolt predates --cwd (2.0.1+); "
            f"upgrade it"
        )
    elif "allow_patterns" not in data:
        retval.append(
            f"yolt does not report allow_patterns, so {_NO_USER_ALLOW} cannot be confirmed; "
            "the auto-run set may still be inherited from ~/.claude/settings.json. "
            "Upgrade voitta-yolt to 1.2.0+"
        )
    elif data["allow_patterns"]:
        retval.append(
            f"yolt loaded {data['allow_patterns']} user allow pattern(s) despite "
            f"{_NO_USER_ALLOW}; the auto-run set is wider than YOLT's own rules"
        )
    else:
        logging.info("yolt: 0 inherited allow patterns; 'safe' means YOLT's own rules (#148)")
    return retval


def is_read_only(command, cwd=None):
    decision, _ = classify(command, cwd=cwd)
    retval = decision == "safe"
    return retval
