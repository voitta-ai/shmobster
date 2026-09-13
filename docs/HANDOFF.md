# Handoff: what to do next, and why

Written 2026-09-13, after the backlog triage that followed v0.7.2. This is the
plan for the next several work items, in the order they should be taken and
with the reasoning that ranked them -- so the next session (or the next person)
starts from the argument, not from a bare issue list.

Current state: **v0.7.2** is live on the first instance. The exec path is
YOLT -> grant layer (#117) -> seatbelt sandbox (#116) -> approval card (#48),
every command is recorded (#129), and a channel can load its own learned
skills (#130). Eleven issues are open.

## The order

| # | Issue | Size | Why here |
|---|---|---|---|
| 1 | #112 env inheritance | M | The largest remaining hole, and it is a credential hole |
| 2 | #123 security posture review | M | Re-audit the surface that changed under it; #112 is its first finding, already known |
| 3 | #9 report real capabilities | S | Half-done by the #134 spine rules; the factual half is small and improves every turn |
| 4 | #23 DM events | S | The last ingest gap in Slack; self-contained |
| 5 | #62 web-fetch tool | M | Real capability gain, no dependency on the above |
| 6 | #140 per-channel memory | L | Deliberately last: it is the piece with the injection surface |

Then decide, do not implement: #24, #16, #6, #1, #51 (see **Decide, do not
build**).

## 1. #112 -- commands inherit the whole machine environment

**The hole, measured on the live box 2026-09-13:** a channel command sees
**192 environment variables, 49 of them credential-shaped**
(`*_TOKEN`, `*_API_KEY`, `*_SECRET*`) -- every vendor key the operator has
ever exported, Jira, Confluence, Figma, Heroku, GitHub PATs, other channels'
AWS keys. `tools.execute` starts from `os.environ.copy()` and removes only
`config.SCOPED_ENV_NAMES` -- the handful of names some policy declares (#106).
Everything else rides along. A read-only `printenv` runs without a card, so
this is a one-command exfiltration path that no gate touches: the sandbox
confines the filesystem, not the environment.

**The shape of the fix, consistent with the rest of the system:** invert it.
Build the child environment from an allowlist instead of subtracting from the
parent -- the same move #116 made for reads (deny `/Users`, carve back) and
#122 made for secrets (keychain and policy `env`, never a readable file).

- A small built-in floor the toolchain genuinely needs: `PATH`, `HOME`,
  `USER`, `LANG`/`LC_*`, `TERM`, `TMPDIR`, `SHELL`, plus what `gitcfg.env()`
  already injects.
- Per-channel `env` (#104) stays exactly as it is: `${VAR}` references,
  resolved at load, injected only for that channel.
- A per-channel `env_passthrough` list of names for the rare case a tool needs
  a host variable that is not a credential.
- The interpolation source stays `os.environ` in the parent process -- config
  loading is unaffected; only the *child* environment narrows.

**Risks to check before merging:** `gh` needs `HOME` and the keychain (works,
#122 proved it); `node`/`npm` want `HOME` and the caches already allowed in
the sandbox profile; `aws` reads `AWS_*` from the policy `env`; anything that
breaks does so loudly at the first command, which is why this wants a day of
live use before a release. Verify with a `printenv | wc -l` in a channel
before and after -- the number is the test.

**Definition of done:** a channel command sees a two-digit variable count with
no credential-shaped name it was not given deliberately; selfcheck asserts a
planted `SECRET_TOKEN` in the parent is absent from a child environment, and
that a name in `env_passthrough` does arrive; README documents both keys.

## 2. #123 -- security posture review

The surface changed underneath this issue: sandbox (#116), grant layer (#117),
git over https with no `~/.ssh` (#122), the learning loop (#129/#130), and the
authoritative hold (#105). A re-audit is due, and it should be written as a
findings list with an issue per finding, not as one sprawling ticket.

Known going in, so do not re-derive:

- #112 above -- environment inheritance. It is finding number one; do it first
  so the audit records it as closed.
- The grant layer's boundary is the sandbox's *write roots*, which include
  `/tmp` and the toolchain caches -- documented and deliberate (#121 review),
  worth re-confirming rather than rediscovering.
- `~/.config/gh` is readable in every channel; `hosts.yml` is denied when it
  holds a token (#122). Re-check that `gh auth token` still cannot be read
  from the file on this host.
- The redactor (voitta-yolt `secret_redact`) misses bare AWS secret-access-key
  values and Slack webhook URLs in prose -- known, layered behind
  "bodies are never logged" in the xs wrapper, but it bounds what redaction
  can promise anywhere else.

Fresh ground worth covering: dependency freshness (litellm, slack-bolt,
tree-sitter pins); whether a skill body can reach the tool-call path in any
way other than the model choosing to (it should not -- skills are prompt
text); what an approval card leaks to a channel member who is not trusted;
and whether `trajectories/` needs a retention policy now that it grows per
turn.

## 3. #9 -- report real capabilities

The #134 spine rules cover the honesty half ("do not assert what you have not
read"). The remaining half is factual: the agent should be able to answer
"what can you do here?" from the policy rather than from prose -- channel
`cwd`, `github_repos`, whether an `aws_profile` or policy `env` exists (names
only, never values), which skills are on this channel's menu, and what the
grant layer will run without a card. A single read-only tool returning that
dict, or a block appended to the system prompt per turn. Small, and it makes
every "can you..." exchange one turn instead of three.

## 4. #23 -- DM events

`message.im` is unhandled: `_ignore_message` acks and drops. The work is
plumbing (route DMs to `handler.handle` with the DM's channel id, which
already resolves to `D...` policies -- one exists in the live policy file
today), plus deciding whether a DM's trust tier differs from a channel's. It
does not: `trusted_users` is per user, so a DM inherits the same authz.

## 5. #62 -- web-fetch tool

Firecrawl or similar, so a URL pasted into a channel can be read. Note two
constraints that already exist: the sandbox blocks nothing network-wise (this
is an API call from the agent process, not a channel command), and a fetched
page is untrusted text -- it must reach the model as content, never as
instructions, which is the same rule #140 will need for memory.

## 6. #140 -- per-channel memory

Deferred by decision 4 on #100 and kept last on purpose. When it is taken:
per-channel `MEMORY.md` in the same `channels/<channel>/` dir of the private
catalog, written only through the propose -> PR -> merge gate (#129), injected
as a clearly-labelled reference block, never into the tool-call path. The
threat model is #52's memory-poisoning section and it has not changed.

## Decide, do not build

- **#24** per-channel binary allow-list -- likely superseded. The sandbox says
  *where*, the grant layer says *what runs uncarded*, YOLT says *what mutates*.
  A fourth axis needs a case; close unless one appears.
- **#16** multiple instances -- `SHMOBSTER_CONFIG`, per-instance logs and the
  README section exist. Confirm whether the per-instance launchd `Label` work
  in `deploy/` is done, then close or scope the remainder.
- **#6** Iter-4 multi-user register, **#1** design tracker -- umbrellas whose
  concrete content shipped. Keep #1 if it is still the standing tracker; close
  #6 or replace it with what remains.
- **#51** remaining Router knobs (context-window fallback, budgets) -- real but
  low: the two that mattered (#80 parking, first-429 cooldown) are in, and
  #125 took the timeout. Pick it up only when a live failure asks for it.

## How the work is done here

Conventions that the last several PRs followed and that keep this repo
predictable:

1. A worktree per change under `shmobster.worktrees/<branch>`; cleanup runs
   from the main clone (a `cd`-into-worktree chain that removes the worktree
   kills the rest of the chain).
2. An issue exists before the PR, and the PR closes it.
3. `selfcheck.py` covers the new behavior -- it is the whole test surface and
   it runs offline.
4. `scripts/check-sensitive-terms.sh` before pushing.
5. An adversarial review on the PR (`codex-adversarial-pr-review`), findings
   answered in a follow-up commit, review posted to the PR.
6. A release is its own commit that bumps `shmobster/__init__.py` and adds
   `docs/release-notes/vX.Y.Z.md`; CI tags and publishes it.
7. Upgrading pulls **voitta-yolt**, **skillz**, and **skillz-private** before
   this repo -- the runtime reads all three.
