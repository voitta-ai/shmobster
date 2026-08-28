"""Repository-state predicates for the grant layer (#117).

"Does this command mutate anything?" has no good answer for `git commit`:
committing to a shared branch and committing to a worktree branch you opened
five minutes ago are different acts with identical argv. Answering it needs
repository state, so this shells out to read-only `git`.

Vendored from voitta-yolt's closed PR #82 (`hooks/git_policy.py` on branch
`feature/git-worktree-allow`), which built these predicates to upgrade
`unsafe` to `safe` inside YOLT and was closed because YOLT stopped granting
anything. The predicates were right; the host is where the grant belongs.

Three facts about a directory, all deterministic and reproducible:

- linked_worktree -- `--git-dir` != `--git-common-dir`: not the primary
  checkout. Under the repo-on-default + `<repo>.worktrees/<branch>`
  convention this alone says "branch work".
- non_default_branch -- default from `origin/HEAD`, else whichever of
  `init.defaultBranch` / main / master actually resolves in THIS repo.
  `init.defaultBranch` is a global preference for repos yet to be created,
  so it is a candidate and never an answer. Detached HEAD never qualifies.
- solo_author -- every commit in `<default>..HEAD` was authored AND
  committed by `git config user.email`. A branch with no commits of its own
  is vacuously solo: that is the state the moment before the first commit,
  which is exactly the case this exists to allow.

Every probe failure -- no git, not a repo, timeout, unparseable output --
reads as "predicate not satisfied". A failed probe must never grant."""
import os
import subprocess

# Read-only probes, but a hung git (network filesystem, index.lock
# contention, a filter process) must not hang the turn.
_GIT_TIMEOUT_SECONDS = 3

_DEFAULT_BRANCH_FALLBACKS = ("main", "master")


def _run_git(directory, args):
    """Run a read-only git command. Returns stdout, or None on any failure."""
    retval = None
    try:
        proc = subprocess.run(
            ["git", "-C", directory, "--no-pager"] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
        if proc.returncode == 0:
            retval = proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        retval = None
    return retval


class GitProbe:
    """Read-only `git` queries about one directory, memoized per instance.
    One command may be `git add ... && git commit ...`, which asks the same
    questions of the same directory twice; memoizing keeps it at one round."""

    def __init__(self, runner=None):
        self._runner = runner or _run_git
        self._cache = {}

    def state(self, directory):
        """Facts about `directory`, or None if it is not a git working tree."""
        retval = None
        if directory is not None:
            key = os.path.abspath(directory)
            if key not in self._cache:
                self._cache[key] = self._probe(key)
            retval = self._cache[key]
        return retval

    def _probe(self, directory):
        if not os.path.isdir(directory):
            return None
        out = self._runner(
            directory,
            ["rev-parse", "--git-dir", "--git-common-dir", "--abbrev-ref", "HEAD"],
        )
        if out is None:
            return None
        lines = out.splitlines()
        if len(lines) < 3:
            return None
        git_dir, git_common_dir, branch = lines[0], lines[1], lines[2]
        # In a linked worktree these differ: --git-dir is <main>/.git/worktrees/<name>,
        # --git-common-dir is <main>/.git. In the primary checkout they are the same.
        linked = os.path.realpath(os.path.join(directory, git_dir)) != os.path.realpath(
            os.path.join(directory, git_common_dir)
        )
        retval = {
            "directory": directory,
            "branch": branch,
            "detached": branch == "HEAD",
            "linked_worktree": linked,
            "default_branch": self._default_branch(directory),
            "user_email": self._config(directory, "user.email"),
        }
        return retval

    def _default_branch(self, directory):
        out = self._runner(directory, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        if out:
            head = out.strip()
            if head.startswith("origin/"):
                return head[len("origin/"):]
        candidates = []
        configured = self._config(directory, "init.defaultBranch")
        if configured:
            candidates.append(configured)
        candidates.extend(c for c in _DEFAULT_BRANCH_FALLBACKS if c not in candidates)
        for candidate in candidates:
            for ref in ("refs/remotes/origin/" + candidate, "refs/heads/" + candidate):
                if self._runner(directory, ["rev-parse", "--verify", "--quiet", ref]) is not None:
                    return candidate
        return None

    def _config(self, directory, key):
        out = self._runner(directory, ["config", "--get", key])
        retval = (out.strip() or None) if out else None
        return retval

    def solo_author(self, directory):
        """(ok, reason): every commit on this branch beyond the default branch
        was authored and committed by the configured user."""
        st = self.state(directory)
        if st is None:
            return (False, "not a git working tree")
        email = st.get("user_email")
        if not email:
            return (False, "git user.email is not configured")
        default = st.get("default_branch")
        if not default:
            return (False, "cannot determine the default branch")
        base = None
        for ref in ("origin/" + default, default):
            if self._runner(directory, ["rev-parse", "--verify", "--quiet", ref]) is not None:
                base = ref
                break
        if base is None:
            return (False, f"no {default} ref to compare against")
        out = self._runner(directory, ["log", "--format=%ae%n%ce", f"{base}..HEAD"])
        if out is None:
            return (False, "cannot read branch history")
        others = {line.strip() for line in out.splitlines() if line.strip() and line.strip() != email}
        if others:
            return (False, "branch has commits by " + ", ".join(sorted(others)))
        retval = (True, "solo author")
        return retval

    def commit_allowed(self, directory):
        """(ok, reason) for `git commit` in `directory`: linked worktree, on a
        non-default branch, every commit so far the user's own."""
        st = self.state(directory)
        if st is None:
            return (False, "not a git working tree")
        if not st["linked_worktree"]:
            return (False, "primary checkout, not a linked worktree")
        if st["detached"]:
            return (False, "detached HEAD")
        default = st.get("default_branch")
        if not default:
            return (False, "cannot determine the default branch")
        if st["branch"] == default:
            return (False, f"on the default branch {default}")
        ok, why = self.solo_author(directory)
        if not ok:
            return (False, why)
        retval = (True, f"linked worktree on {st['branch']}, {why}")
        return retval
