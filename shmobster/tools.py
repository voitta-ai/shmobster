"""Model-callable tools. Iter 1 ships one: run_shell, gated by YOLT and, since
Iter #4, by the per-channel policy (cwd / aws_profile / github_repos).

Read-only commands run in the channel's cwd (with its AWS_PROFILE) if they pass
the channel's github/aws scope. So does a mutating command the grant layer
(#117, grant.py) vouches for -- a write the sandbox keeps in the tree, a commit
on the user's own worktree branch. Any other mutating command is parked as a
pending approval request (#48) and runs only once a trusted user approves it
by id.

Every disposition is logged (#97): ran, blocked by policy, or -- via approvals
-- parked. #94 gave the queue a record and left the other two silent, so "did
it try X and get blocked, or never try?" stayed unanswerable, which is the same
question that made #94 take an hour. Commands are scrubbed at the emission site
for the reason approvals gives: argv carries credentials and a log outlives the
channel it was posted to.

Every command that does run, runs under sandbox-exec confined to the channel's
tree (#116, sandbox.py): approval says whether, policy says what scope, the
sandbox says where."""
import logging
import os
import subprocess

from . import approvals, config, cost as cost_mod, gitcfg, grant, policy as policy_mod, redact, sandbox, skills, trajectory, yolt_gate

RUN_SHELL = {
    "type": "function",
    "function": {
        "name": "run_shell",
        "description": (
            "Run a shell command and return its output. Read-only commands run "
            "immediately, and so do writes inside this channel's tree (cp, mv, "
            "mkdir, tee, cat > file, sed -i, git add, git commit on your own "
            "worktree branch). Any other mutating command is parked with a "
            "request id and runs only after a trusted user approves it "
            "(approve_command) -- relay that id to the user instead of retrying; "
            "commands outside this channel's scope are blocked. Prefer read-only "
            "inspection."
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

DESCRIBE = {
    "type": "function",
    "function": {
        "name": "describe_capabilities",
        "description": (
            "Report what you can actually do in THIS channel: the working "
            "directory, the git/AWS scope, which hosts you may reach without an "
            "approval card, which credential names are injected (names only -- "
            "never values), which skills are loadable here, and what runs without "
            "a card. Call this before answering any question about your own "
            "access, files, permissions or scope, instead of describing yourself "
            "from memory."
        ),
        "parameters": {"type": "object", "properties": {}},
    },
}

REPORT_COST = {
    "type": "function",
    "function": {
        "name": "report_cost",
        "description": (
            "What this thread and this channel have cost in model calls today. "
            "Use it when someone asks what a turn, a thread or the day cost -- "
            "do not estimate from token counts or model prices, which is "
            "guessing at a number this can answer. Takes no arguments: it "
            "reports the thread and channel of the current turn and cannot be "
            "pointed at another."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
}

TOOLS = [RUN_SHELL, DESCRIBE, REPORT_COST]

_MAX_OUTPUT = 4000


def run_shell(command, policy, channel=None):
    decision, reason = yolt_gate.classify(command, cwd=policy_mod.cwd_for(policy))
    # Read-only to YOLT is not the same as harmless: `curl`/`wget` leave the
    # box, and a fetch to a host this channel was not given is a mutation of
    # the world even when it reads nothing here (#149). Demote it to mutating
    # and let the rest of this function do what it does with a mutation -- the
    # grant layer will not vouch for a fetch, so it parks for a card.
    if decision == "safe":
        allowed, why = policy_mod.check_egress(command, policy)
        if not allowed:
            decision, reason = "unsafe", why
    if decision != "safe":
        # A refusal is not a question (#172). voitta-yolt 2.0.0 upgrades an
        # already-unsafe verdict to "deny" when a git-state predicate refuses
        # outright -- it has looked at the repository and said no. The grant
        # layer decides on the verb, so without this an `rm` or `tee` the
        # classifier refused would come back "in-tree write" and run with no
        # card, vouched for by the layer that never asked why it was refused.
        # The better-informed gate wins; the human still gets the last word,
        # through a card that says what it is.
        refused = decision == "deny"
        granted, why = (False, reason) if refused else grant.check(command, policy)
        if granted:
            logging.info(
                "run_shell: granted in %s (%s): %s",
                channel, repr(redact.scrub(why)), repr(redact.scrub(command)),
            )
            retval = execute(command, policy)
            return retval
        req_id = approvals.add(command, channel, reason, refused=refused)
        # The whole id, nonce and all (#109). It is what a human types back, and
        # a shortened one would mean a different request after the next restart
        # while reading identically on the card they typed it from.
        # What happens next, stated exactly (#169). The old wording -- "it will
        # run on approval" -- was true and incomplete: the command ran, its
        # output landed on the card, and nothing resumed the turn, so every
        # reply that promised "approve and I'll give you the answer" was a
        # promise the system did not keep (#134). It keeps it now, and the
        # instruction is to stop rather than to wait, because the turn ends
        # here either way.
        headline = "REFUSED by the classifier" if refused else "NOT RUN -- pending approval"
        retval = (
            f"{headline} [{req_id}] ({reason}): {command}\n"
            + ("Say plainly that the classifier refused this one outright rather than "
               "merely asking, and why. A trusted user can still override it, but do "
               "not present that as routine.\n" if refused else "")
            + f"Tell the user: a trusted user can approve it with the card's button "
            f"or by asking you to approve request {req_id} (approve_command), "
            f"quoting the id exactly. Do not retry the command. End your turn now: "
            f"once it is approved and runs, you are continued automatically with "
            f"its output and can finish the task from there."
        )
        return retval
    retval = execute(command, policy)
    return retval


# The floor every child environment is built up from (#112). The old code
# copied os.environ and subtracted the names some channel had declared, which
# could only ever remove what something declared: every other variable the
# operator exported rode into every channel -- 192 of them on the live box,
# 49 credential-shaped. `printenv SOME_TOKEN` is read-only, so it runs with no
# card, and a bare token has no shape the redactor can catch. So the child
# environment is built from an allowlist instead, the same inversion #116 made
# for reads and #122 for secrets: a channel's own `env` and `env_passthrough`
# are the only routes from the machine's environment into a command.
#
# The floor is what the toolchain genuinely needs, and holds no credential.
# SSH_AUTH_SOCK is deliberately absent: it is a capability, not a value, and
# git here runs over https (gitcfg.py).
_BASE_ENV_NAMES = ("PATH", "HOME", "USER", "LANG", "TERM", "TMPDIR", "SHELL")
_BASE_ENV_PREFIXES = ("LC_",)


def child_env(policy):
    """The environment a channel's command runs with: the floor, git's config,
    the channel's AWS profile, and what its policy declares -- nothing else."""
    retval = {
        k: v for k, v in os.environ.items()
        if k in _BASE_ENV_NAMES or k.startswith(_BASE_ENV_PREFIXES)
    }
    # Git over https with gh's keychain token, so no channel ever needs to
    # read ~/.ssh (gitcfg.py). Per process: the operator's config is untouched.
    retval.update(gitcfg.env())
    prof = policy.get("aws_profile")
    if prof:
        retval["AWS_PROFILE"] = prof
    # The rare host variable a channel's toolchain needs that is not a
    # credential. Policy file only -- set_policy over chat cannot add one --
    # so a name here is as deliberate as an `env` entry, written by a trusted
    # user in the same file.
    for _name in policy.get("env_passthrough") or ():
        if _name in os.environ:
            retval[_name] = os.environ[_name]
    # Per-channel extra credentials (e.g. VERCEL_TOKEN, HEROKU_API_KEY). Values
    # live in the gitignored shmobster-policies.json; injected only for this
    # channel's commands.
    retval.update(policy.get("env") or {})
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
    env = child_env(policy)
    try:
        # Confined to the channel's tree at the kernel (#116). sandbox.wrap
        # raises when the sandbox is unavailable; that lands in the except
        # below as "exec error" -- never a fallback to running unconfined.
        proc = subprocess.run(
            sandbox.wrap(command, policy),
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
    except subprocess.TimeoutExpired as exc:
        # Its str() is "Command '<argv>' timed out", and since #116 argv
        # carries the whole seatbelt profile -- a screenful per line. The
        # command is already on the line, scrubbed; keep only the fact.
        logging.info("run_shell: failed (timed out after %ss): %s", exc.timeout, safe_cmd)
        retval = f"exec error: timed out after {exc.timeout}s"
    except Exception as exc:
        # The exception text is scrubbed too, not only the command: an OSError
        # can quote the argv, so the raw command comes back around through the
        # one field safe_cmd never covered. Same reason the return value below
        # is scrubbed downstream.
        logging.info("run_shell: failed (%s): %s", repr(redact.scrub(str(exc))), safe_cmd)
        retval = f"exec error: {exc}"
    return retval


def _listed(values, none):
    retval = ", ".join(str(v) for v in values) if values else none
    return retval


def capabilities(policy, channel=None):
    """What this channel's envelope actually is, read from the policy (#9).

    The improvisation this replaces was not a lie the model chose to tell: asked
    what files it could reach, it had nothing to read but its own prose, so it
    answered from the persona. The #134 spine rules cover the honesty half --
    do not assert what you have not read -- and this is the other half: something
    to read.

    Names, never values. A policy `env` entry exists to inject a credential, so
    the value is exactly what must not be reported; the name is what makes the
    answer useful ("you have a VERCEL_TOKEN here"). Same for `env_passthrough`.
    Nothing here reveals another channel's envelope."""
    lines = [f"Capabilities in this channel ({channel or 'unknown'}), read from its policy:"]
    lines.append(f"- working directory: {policy_mod.cwd_for(policy)}")
    lines.append("- git and gh: " + _listed(
        policy.get("github_repos"), "no repo restriction"))
    lines.append("- AWS: " + (f"profile {policy['aws_profile']}" if policy.get("aws_profile")
                              else "no profile; no AWS credentials unless a command brings its own"))
    lines.append("- network without a card: " + _listed(
        policy.get("allow_domains"),
        "no hosts -- every curl, wget or git remote fetch parks for approval"))
    lines.append("- credentials injected (names only, values never shown): " + _listed(
        sorted(policy.get("env") or {}), "none"))
    lines.append("- host variables passed through (names only): " + _listed(
        sorted(policy.get("env_passthrough") or []), "none"))
    lines.append("- readable beyond the tree: " + _listed(policy.get("allow_read"), "nothing"))
    lines.append("- writable beyond the tree: " + _listed(policy.get("allow_write"), "nothing"))
    lines.append("- kept off-limits inside it: " + _listed(policy.get("exclude"), "nothing"))
    lines.append("- skills loadable here: " + _listed(skills.names(channel), "none"))
    lines.append(
        "- runs with no approval card: read-only commands; writes inside the tree "
        f"({_listed(sorted(grant.FS_VERBS), 'none')}); a commit on a worktree branch "
        "you authored. Everything else parks for a trusted user to approve by id."
    )
    lines.append(
        "- always enforced: commands run under a sandbox confined to this tree, "
        "this deployment's own config is unreachable, and every reply is scrubbed "
        "for credentials."
    )
    retval = "\n".join(lines)
    return retval


def dispatch(name, args, policy, channel=None, thread_ts=None):
    if name == "run_shell":
        retval = run_shell(args.get("command", ""), policy, channel)
    elif name == "report_cost":
        retval = report_cost(channel, thread_ts)
    elif name == "describe_capabilities":
        retval = capabilities(policy, channel)
    else:
        retval = f"unknown tool: {name}"
    return retval


def report_cost(channel, thread_ts=None):
    """This thread's and this channel's spend today (#190).

    Deliberately takes no channel argument. #151 is the precedent: a reporting
    tool that accepts a target is a tool that reports on somewhere else, and
    the turn already knows where it is.

    The current turn is included from the in-flight accumulator rather than
    from the trajectory, because the turn has not been recorded yet -- asking
    "what did this cost" mid-turn and being told about every turn but this one
    is the obvious wrong answer."""
    if not channel:
        retval = "no channel in this turn, so there is nothing to total."
        return retval
    in_flight = cost_mod.peek()
    today = trajectory.day(channel)
    day_calls = [c for rec in today for c in (rec.get("calls") or [])]
    lines = []
    if thread_ts:
        thread_recs = [r for r in today if r.get("thread_ts") == thread_ts]
        thread_calls = [c for rec in thread_recs for c in (rec.get("calls") or [])]
        lines.append(
            f"This thread today: {cost_mod.summarize(thread_calls + in_flight)}"
            f" (including this turn so far)."
        )
    lines.append(f"This channel today: {cost_mod.summarize(day_calls + in_flight)}.")
    by_vendor = {}
    for c in day_calls + in_flight:
        by_vendor.setdefault(c.get("vendor") or "unknown", []).append(c)
    if len(by_vendor) > 1:
        lines.append("By vendor today: " + "; ".join(
            f"{v}: {cost_mod.summarize(cs)}" for v, cs in sorted(by_vendor.items())))
    retval = "\n".join(lines)
    return retval
