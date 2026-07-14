"""Model-callable tools. Iter 1 ships one: run_shell, gated by YOLT.

Read-only commands run immediately. Mutating commands are NOT executed -- they
return a single "needs approval" line (no dozen "did not run" cards). A real
approval flow arrives with per-channel policy (Iter 2) + multi-user (Iter 4)."""
import subprocess

from . import config, yolt_gate

RUN_SHELL = {
    "type": "function",
    "function": {
        "name": "run_shell",
        "description": (
            "Run a shell command and return its output. Read-only commands run "
            "immediately; mutating commands are blocked pending approval, so "
            "prefer read-only inspection."
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


def run_shell(command):
    decision, reason = yolt_gate.classify(command)
    if decision != "safe":
        retval = f"NOT RUN (needs approval -- {reason}): {command}"
        return retval
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=config.EXEC_CWD,
            timeout=config.EXEC_TIMEOUT,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if len(out) > _MAX_OUTPUT:
            out = out[:_MAX_OUTPUT] + "\n...[truncated]"
        retval = out.strip() or f"(exit {proc.returncode}, no output)"
    except Exception as exc:
        retval = f"exec error: {exc}"
    return retval


def dispatch(name, args):
    if name == "run_shell":
        retval = run_shell(args.get("command", ""))
    else:
        retval = f"unknown tool: {name}"
    return retval
