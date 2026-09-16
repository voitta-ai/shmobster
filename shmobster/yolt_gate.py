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


def _classify_raw(command, flags=(_NO_USER_ALLOW,)):
    """(dict, error). The dict is YOLT's parsed output; error is a string when
    it could not be obtained."""
    path = config.YOLT_CLASSIFIER
    if not path:
        return (None, "yolt not configured (exec.yolt_classifier)")
    try:
        proc = subprocess.run(
            [sys.executable, path, *flags, command],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return (json.loads(proc.stdout), None)
    except Exception as exc:
        return (None, f"yolt error: {exc}")


def classify(command):
    data, err = _classify_raw(command)
    if err:  # fail closed -> mutating
        retval = ("unsafe", err)
        return retval
    retval = (data.get("decision", "unsafe"), data.get("reason", ""))
    return retval


# The probe command, and the choice matters (#177). `echo` is one of three
# things still classified `safe` by voitta-yolt 2.0.0, whose Phase 3 cut
# rules/shell.json from 136 entries to 28 -- so a preflight probing `echo`
# passes on a classifier under which `cat`, `ls`, `grep`, `git status` and
# `gh pr list` all come back `unknown` and every ordinary read in a channel
# parks for a card. `cat` is the probe because it is the read this agent
# actually runs most, and because a classifier that cannot call it read-only
# is one this agent cannot use, whatever its version string says.
_PROBE = "cat /dev/null"


def preflight():
    """Warnings for a YOLT this agent cannot run on.

    Three failure modes, all silent, all ending in "every command parks":

    An older classifier takes its command from argv[1], so `--no-user-allow`
    lands there and every verdict becomes a verdict about that string. One that
    accepts the flag and inherits the allow-lists anyway is worse -- the old
    auto-run surface with nothing to show for it, which is why the count has to
    be reported and has to be zero.

    And one that no longer answers "is this read-only" for ordinary reads
    (#177). That is not a malfunction upstream: for the PreToolUse hook `safe`
    and `unknown` are the same silent exit, so delegating a command costs
    nothing there. Here they are opposite verdicts, so the probe asks about a
    command that was delegated rather than one that survived."""
    retval = []
    data, err = _classify_raw(_PROBE)
    if err:
        retval.append(err)
        return retval
    if data.get("decision") != "safe":
        retval.append(
            f"yolt called {_PROBE!r} {data.get('decision')!r} rather than safe, so every "
            "ordinary read in a channel will park for an approval card. Either this yolt "
            f"predates {_NO_USER_ALLOW} (1.2.0+) and classified the flag instead of the "
            "command, or it is 2.0.0+, which delegates reads to the host instead of "
            "classifying them (#177). Use a yolt between 1.2.0 and 1.6.0 until #177 says "
            "otherwise"
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


def is_read_only(command):
    decision, _ = classify(command)
    retval = decision == "safe"
    return retval


def is_read_only(command):
    decision, _ = classify(command)
    retval = decision == "safe"
    return retval
