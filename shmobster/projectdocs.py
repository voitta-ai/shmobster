"""The channel repo's own instructions, as standing context (#259).

A repo usually documents how it wants to be worked on, and the agent standing
in that repo never read it. The case that produced this: `seeds-of-doubt` has
`docs/BRANCHING-STRATEGY.md` and `docs/PERSONAL_BRANCHES.md`, both committed,
both saying that a collaborator's branch is what deploys to their subdomain.
Six weeks of UX work sat on a feature branch instead, invisible, and when asked
why, the agent read `git log` for one branch, found nothing, and reported the
work had never been done. The answer was a file in the tree it was standing in.

That is the agent's job rather than the collaborator's, and it is the reason
this deployment exists: the architect sets up the workflow, and the people in
the channel are specialists -- a UX designer describing a screen should not
have to know which branch makes it appear.

**Read from a commit, never from the working tree.** This is the whole safety
argument, and it is why `memory.py`'s rule could not simply be reused. Memory
refuses any file under a writable root, because the grant layer runs an in-tree
write with no card and a writable prompt file lets one `cat > FILE` become the
next turn's instructions. The file wanted here is INSIDE the channel's tree by
definition. So the content comes from `git show <rev>:<path>` -- an uncommitted
edit, which is what a turn can make silently, steers nothing.

A turn can still commit, and in an unattended channel (#253) it can do so with
no card. That is deliberate and bounded: a commit is a reviewable object with
an author and a diff, in the channel's own repo, which is the scope its
operator already drew. The distinction being preserved is between an edit that
leaves a trace and one that does not.
"""
import logging
import os
import subprocess


# Conventional names first, then whatever the channel names for itself. The
# conventions are the ones agent tooling already writes: a repo that has one
# expects an agent to read it.
DEFAULT_PATHS = ("CLAUDE.md", "AGENTS.md", "docs/CLAUDE.md", "docs/AGENTS.md")

# A budget, not an archive. A repo's docs directory can be a book; the system
# prompt cannot. Truncation says where it stopped rather than trailing off.
_MAX_FILE = 6000
_MAX_TOTAL = 16000
_REV = "HEAD"


def _read(directory, path):
    """One file's contents at HEAD, or None.

    `--` separates the pathspec from revisions so a file named like a ref
    cannot be read as one, and a path outside the repo simply fails: `git show`
    resolves against the repository root, not the filesystem."""
    if not path or path.startswith("/") or ".." in path.split("/"):
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", directory, "show", f"{_REV}:{path}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    # Bytes, decoded here rather than by subprocess: git will hand back
    # whatever is in the blob, and a document that is not valid UTF-8 would
    # raise UnicodeDecodeError on EVERY turn -- this runs before the model
    # call, so one bad commit would take the channel down until someone
    # changed it (Codex adversarial review, #261). Replacement characters in a
    # prompt are survivable; a channel that cannot answer is not.
    retval = proc.stdout.decode("utf-8", "replace")
    return retval


def files(policy):
    """[(path, text)] for this channel's project docs, in order.

    The defaults plus whatever `project_docs` names: `docs/BRANCHING-STRATEGY.md`
    is the file that mattered here and no convention would have guessed it."""
    # An explicit cwd, never `cwd_for`'s fallback. Without this a channel that
    # names no directory reads the DEPLOYMENT's own repo -- shmobster's
    # CLAUDE.md, which is written for the people who develop the agent -- into
    # a Slack channel's prompt. Caught by the self-check, and it would have
    # been invisible in production because the block reads plausibly.
    directory = policy.get("cwd")
    directory = os.path.expanduser(os.path.expandvars(directory)) if directory else None
    if not directory or not os.path.isdir(directory):
        return []
    # Named files first, conventions second. `project_docs` is an operator
    # saying "this one matters"; the defaults are a guess that a file with a
    # conventional name is worth reading. Spending the budget on the guess and
    # starving the instruction the channel exists to follow is the wrong way
    # round -- and it is what happened here before review (#261).
    named = [p for p in (policy.get("project_docs") or [])]
    wanted = named + [p for p in DEFAULT_PATHS if p not in named]
    retval, total, omitted = [], 0, []
    for path in wanted:
        body = _read(directory, path)
        if not body or not body.strip():
            continue
        if len(body) > _MAX_FILE:
            body = body[:_MAX_FILE] + f"\n...[truncated at {_MAX_FILE} characters]"
        if total + len(body) > _MAX_TOTAL:
            # Keep going rather than stopping: one oversized file must not hide
            # every smaller one after it. What is dropped is named in the
            # prompt, so the reader knows the set is incomplete.
            logging.info("projectdocs: %s omitted, budget spent", path)
            omitted.append(path)
            continue
        total += len(body)
        retval.append((path, body))
    if omitted:
        retval.append(("(omitted)", "These were not included, the budget was "
                       "spent: " + ", ".join(omitted) + ". Read them with a "
                       "command if the answer might be in one."))
    return retval


def _fence(body):
    """A fence longer than any run of backticks inside, so a doc containing a
    code block cannot end the block it is quoted in."""
    longest = 0
    run = 0
    for ch in body:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    retval = "`" * max(3, longest + 1)
    return retval


def prompt_block(policy):
    """The project-instructions block, or "" when the repo carries none."""
    found = files(policy or {})
    if not found:
        retval = ""
        return retval
    parts = [
        "## How this project asks to be worked on\n",
        "These files are committed in this channel's own repository, read at "
        f"`{_REV}`. They are the project's instructions -- the working "
        "agreements the people here rely on, such as which branch deploys "
        "where -- and following them is part of doing the work correctly. Cite "
        "the file when you apply a rule from it, so anyone can check you.\n",
        "Read from the last commit, not the working copy, so an uncommitted "
        "edit cannot change what you are told mid-task.\n",
    ]
    for path, body in found:
        fence = _fence(body)
        parts.append(f"### {path}\n\n{fence}\n{body.rstrip()}\n{fence}\n")
    retval = "\n".join(parts)
    return retval
