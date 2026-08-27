"""Model-callable tools. Iter 1 ships one: run_shell, gated by YOLT and, since
Iter #4, by the per-channel policy (cwd / aws_profile / github_repos).

Read-only commands run in the channel's cwd (with its AWS_PROFILE) if they pass
the channel's github/aws scope. A mutating command is parked as a pending
approval request (#48) and runs only once a trusted user approves it by id.

Every disposition is logged (#97): ran, blocked by policy, or -- via approvals
-- parked. #94 gave the queue a record and left the other two silent, so "did
it try X and get blocked, or never try?" stayed unanswerable, which is the same
question that made #94 take an hour. Commands are scrubbed at the emission site
for the reason approvals gives: argv carries credentials and a log outlives the
channel it was posted to."""
import logging
import os
import subprocess

from . import approvals, config, policy as policy_mod, redact, yolt_gate

RUN_SHELL = {
    "type": "function",
    "function": {
        "name": "run_shell",
        "description": (
            "Run a shell command and return its output. Read-only commands run "
            "immediately; a mutating command is parked with a request id and runs "
            "only after a trusted user approves it (approve_command) -- relay that "
            "id to the user instead of retrying; commands outside this channel's "
            "scope are blocked. Prefer read-only inspection."
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


def run_shell(command, policy, channel=None):
    decision, reason = yolt_gate.classify(command)
    if decision != "safe":
        req_id = approvals.add(command, channel, reason)
        # The short form here, not the queue key: this text is what a human
        # reads and types back as `approve 4`, and approvals.canonical() puts
        # the boot nonce back on before any lookup (#109).
        short_id = approvals.short(req_id)
        retval = (
            f"NOT RUN -- pending approval [{short_id}] ({reason}): {command}\n"
            f"Tell the user: a trusted user can approve it by asking you to "
            f"approve request {short_id} (approve_command). Do not retry the "
            f"command; it will run on approval."
        )
        return retval
    retval = execute(command, policy)
    return retval


def execute(command, policy):
    """Run a command that has already cleared the YOLT gate or been approved.
    The channel policy is still enforced here -- approval is permission, policy
    is scope, and both must pass."""
    # repr, not the bare string: a command carrying a newline would
    # otherwise write extra lines into a line-oriented log and forge
    # entries -- "run_shell: exit 0: <something that never ran>" -- in the
    # exact record this logging exists to be trusted as.
    safe_cmd = repr(redact.scrub(command))
    ok, why = policy_mod.check(command, policy)
    if not ok:
        # The reason gets the same treatment as the command, because it is
        # partly built from it: the aws guard quotes the --profile value it
        # rejected and the exclude guard quotes the offending path token.
        logging.info("run_shell: blocked by policy (%s): %s", repr(redact.scrub(why)), safe_cmd)
        retval = f"BLOCKED by channel policy: {why}"
        return retval
    # Logged before the subprocess, not only after: a command that hangs to the
    # timeout, or one running when the watchdog (#66) restarts us, has to leave
    # a trace too. The exit line repeats the command rather than relying on
    # adjacency -- Bolt handles events concurrently, so two turns interleave.
    logging.info("run_shell: running: %s", safe_cmd)
    env = os.environ.copy()
    prof = policy.get("aws_profile")
    if prof:
        env["AWS_PROFILE"] = prof
    # A name any channel scopes through its policy env is not a global (#106).
    # Drop every such name from the inherited copy first, then add back only
    # this channel's -- otherwise a token another channel declares is readable
    # here with a plain `printenv`, since a ${VAR} policy value has to be in the
    # process environment to expand and every subprocess starts from a copy of
    # it. Scoping that only holds while nobody looks is not scoping.
    for _name in config.SCOPED_ENV_NAMES:
        env.pop(_name, None)
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
        logging.info("run_shell: exit %s: %s", proc.returncode, safe_cmd)
        out = (proc.stdout or "") + (proc.stderr or "")
        if len(out) > _MAX_OUTPUT:
            out = out[:_MAX_OUTPUT] + "\n...[truncated]"
        retval = out.strip() or f"(exit {proc.returncode}, no output)"
    except Exception as exc:
        # The exception text is scrubbed too, not only the command: a
        # TimeoutExpired renders as "Command '<cmd>' timed out after Ns", so the
        # raw argv comes back around through the one field safe_cmd never
        # covered. Same reason the return value below is scrubbed downstream.
        logging.info("run_shell: failed (%s): %s", repr(redact.scrub(str(exc))), safe_cmd)
        retval = f"exec error: {exc}"
    return retval


def dispatch(name, args, policy, channel=None):
    if name == "run_shell":
        retval = run_shell(args.get("command", ""), policy, channel)
    else:
        retval = f"unknown tool: {name}"
    return retval
