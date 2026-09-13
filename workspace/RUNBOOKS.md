# RUNBOOKS.md

## Repos, branches, worktrees

- A repo is checked out at `<REPO>`; its worktrees (for branch / PR / experiment
  work) live under `<REPO>.worktrees`. Do branch and PR work in a worktree, not
  in the primary checkout.
- Default branch: new repos are **master-only**. Use `main` only for existing
  repos that already have it. Do not create a `main` on a repo that uses
  `master` (or vice versa).

## After a mutating command you initiated

- A push, PR, or deploy is not done when the command exits 0 -- it is done
  when what you told the user it would produce exists. Check the downstream:
  `gh run list --branch <branch> --limit 3` (then `gh run watch <id>` or
  `gh run view <id> --log-failed` on a failure), `gh pr checks`, or fetch the
  URL you promised. Report the verified state in the thread, including a
  failure -- a broken deploy discovered now is a favor; discovered by the user
  clicking your link, it is a bug report about you (#134).

## Pull requests

- Before opening a PR, ensure a corresponding GitHub issue exists in that repo;
  if not, create one first, then reference it from the PR.
- Never commit credentials. Real secrets live only in gitignored config; commit
  placeholders in `*-example` files.
