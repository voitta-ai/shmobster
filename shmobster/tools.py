"""Model-callable tools. Iter 1 ships one: run_shell, gated by YOLT and, since
Iter #4, by the per-channel policy (cwd / aws_profile / github_repos).

Read-only commands run in the channel's cwd (with its AWS_PROFILE) if they pass
the channel's github/aws scope. Mutating commands are NOT executed -- one "needs
approval" line. A real approval flow is a later iteration."""
import os
import subprocess

from . import config, policy as policy_mod, yolt_gate

RUN_SHELL = {
    "type": "function",
    "function": {
        "name": "run_shell",
        "description": (
            "Run a shell command and return its output. Read-only commands run "
            "immediately; mutating commands are blocked pending approval; commands "
            "outside this channel's scope are blocked. Prefer read-only inspection."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to run.",
                }
            },
            "required": ["command"],
        },
    },
}

TOOLS = [RUN_SHELL]

_MAX_OUTPUT = 4000


def run_shell(command, policy):
    decision, reason = yolt_gate.classify(command)
    if decision != "safe":
        retval = f"NOT RUN (needs approval -- {reason}): {command}"
        return retval
    ok, why = policy_mod.check(command, policy)
    if not ok:
        retval = f"BLOCKED by channel policy: {why}"
        return retval
    env = os.environ.copy()
    prof = policy.get("aws_profile")
    if prof:
        env["AWS_PROFILE"] = prof
    # Per-channel extra credentials (e.g. VERCEL_TOKEN, HEROKU_API_KEY). Values
    # live in the gitignored shmobster-policies.json; injected only for this
    # channel's commands.
    for _k, _v in (policy.get("env") or {}).items():
        env[_k] = _v
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=policy_mod.cwd_for(policy),
            timeout=config.EXEC_TIMEOUT,
            env=env,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if len(out) > _MAX_OUTPUT:
            out = out[:_MAX_OUTPUT] + "\n...[truncated]"
        retval = out.strip() or f"(exit {proc.returncode}, no output)"
    except Exception as exc:
        retval = f"exec error: {exc}"
    return retval


def dispatch(name, args, policy):
    if name == "run_shell":
        retval = run_shell(args.get("command", ""), policy)
    else:
        retval = f"unknown tool: {name}"
    return retval
