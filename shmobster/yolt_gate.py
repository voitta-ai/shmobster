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


def preflight():
    """Warnings for a YOLT that does not honor --no-user-allow.

    An older classifier takes its command from argv[1], so the flag lands there
    and the real command is never classified -- every verdict becomes a verdict
    about the string "--no-user-allow". That fails closed (everything parks),
    which is safe but unusable, and it is silent. Worse, a version that ignores
    the flag while still classifying correctly would go on inheriting the
    allow-lists with nothing to show for it. Both are caught here: the count of
    allow patterns in play has to be reported, and it has to be zero."""
    retval = []
    data, err = _classify_raw("echo preflight")
    if err:
        retval.append(err)
        return retval
    if data.get("decision") != "safe":
        retval.append(
            f"yolt does not understand {_NO_USER_ALLOW} (a read-only command came back "
            f"{data.get('decision')!r}); every command will park. Upgrade voitta-yolt to 1.2.0+"
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
