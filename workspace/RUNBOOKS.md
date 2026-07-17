# RUNBOOKS.md

## Repos, branches, worktrees

- A repo is checked out at `<REPO>`; its worktrees (for branch / PR / experiment
  work) live under `<REPO>.worktrees`. Do branch and PR work in a worktree, not
  in the primary checkout.
- Default branch: new repos are **master-only**. Use `main` only for existing
  repos that already have it. Do not create a `main` on a repo that uses
  `master` (or vice versa).

## Pull requests

- Before opening a PR, ensure a corresponding GitHub issue exists in that repo;
  if not, create one first, then reference it from the PR.
- Never commit credentials. Real secrets live only in gitignored config; commit
  placeholders in `*-example` files.
