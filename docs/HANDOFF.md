# Handoff: what to do next, and why

Written 2026-09-13 after the backlog triage that followed v0.7.2; **revised the
same day**, once items 1 and 2 were done and item 2 turned one ticket into ten.
This is the plan for the next several work items, in the order they should be
taken and with the reasoning that ranked them -- so the next session (or the
next person) starts from the argument, not from a bare issue list.

Current state: **v0.7.2** is live on the first instance. The exec path is
YOLT -> grant layer (#117) -> seatbelt sandbox (#116) -> approval card (#48),
every command is recorded (#129), a channel can load its own learned skills
(#130), and a command's environment is now built from an allowlist rather than
inherited (#112). Twenty-one issues are open -- ten of them are the security
re-audit's findings, filed one per finding.

## Done since this plan was written

- **#112, environment inheritance** -- PR #146. A command's environment is built
  from a floor (`PATH`, `HOME`, `USER`, `LANG`/`LC_*`, `TERM`, `TMPDIR`,
  `SHELL`) plus git's per-process config, the channel's `AWS_PROFILE`, its
  policy `env`, and a new `env_passthrough` list of host variable *names*.
  `SCOPED_ENV_NAMES` is gone: with a floor there is nothing to subtract.
  Measured on the live host: **152 variables -> 20, 29 credential-shaped -> 0**.
- **#123, security posture review** -- re-audited and split. Ten findings, one
  issue each (#147-#156); #123 is now the tracker and carries the re-audit
  comment. Closed by the surface that had moved under it: every dotfile read
  (`~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.codex/auth.json`,
  `~/.claude/settings.json`, `gh auth token` -- all denied under #116), the
  environment route (#112), the AWS half of its Finding 4, and out-of-scope
  `git clone <url>`. The #122 re-check passes: `hosts.yml` holds no
  `oauth_token` on this host and `gh auth token` is denied inside the sandbox.

## The order

| # | Issue | Size | Why here |
|---|---|---|---|
| 1 | #147 deployment config writable from a channel | S | The re-audit's own new finding, and the only one where the agent widens its own envelope. Small, contained, and it undercuts every other guard while it stands |
| 2 | #148 own the exec allow-list | M | 123 inherited `Bash()` patterns decide what auto-runs; `codex exec *`, `gh api*`, `gh pr merge*` classify `safe` today. The sandbox does not touch these -- they are network effects |
| 3 | #149 egress allow-list | M | Caps what any successful injection can achieve, and settles what #62 should be before #62 is built |
| 4 | #9 report real capabilities | S | Half-done by the #134 spine rules; the factual half is small and improves every turn |
| 5 | #23 DM events | S | The last ingest gap in Slack; self-contained |
| 6 | #62 web-fetch tool | M | Real capability gain. Take it after #149, which decides whether it is a tool or a policy |
| 7 | #140 per-channel memory | L | Deliberately last: it is the piece with the injection surface |

Running in the background, no order among them: #150 (`github_repos` is a text
guard -- document or enforce), #151 (ungated `slack_post`), #152 (lockfile,
stale litellm/aiohttp), #153 (attachment bearer on redirect), #154 (repo
governance), #155 (log perms, trajectory retention), #156 (telemetry flag).
Each is self-contained and none blocks the seven above.

Then decide, do not implement: #24, #16, #6, #1, #51 (see **Decide, do not
build**).

## 1. #147 -- a channel can rewrite the deployment's own policy file

The grant layer runs an in-tree write with no card and the sandbox's write root
is the tree. When a channel's `cwd` is the directory shmobster is deployed
from, that tree holds `shmobster-policies.json` -- the file that defines `cwd`,
`allow_read`, `allow_write`, `exclude`, `env` and `env_passthrough`. Measured
against `grant.check`: `tee`, `sed -i` and `cp` onto that filename all return
`(True, 'in-tree write')`.

So the agent can widen its own envelope, including naming a host credential,
with no human in the path; it takes effect at the next `reload_policies()` or
restart, and the watchdog makes restarts routine.

**Shape of the fix:** the two paths are already known at load
(`config._PATH`, `config._POLICIES_PATH`). Deny both in the sandbox profile and
refuse them in `grant.check`, so the disposition is a card rather than a silent
write. Reading the policy file is a separate question and probably fine -- since
#104 it holds `${VAR}` references, not values.

**Done when:** a write to either path from a channel whose cwd contains them
parks for approval instead of running, and selfcheck asserts it.

## 2. #148 -- the exec gate inherits someone else's allow-list

`grammar_classifier.py` promotes a command to `safe` on a `Bash()` pattern read
from `~/.claude/settings.json`, `<cwd>/.claude/settings.json` and
`<cwd>/.claude/settings.local.json`. `yolt_gate.classify` subprocesses it with
the agent's own cwd, so the operator's interactive Claude Code permissions --
and the repo's own `.claude/settings.local.json` -- decide what the Slack agent
auto-runs. 123 patterns on the deployment host.

**Shape of the fix:** pass the classifier an explicit settings list, or a flag
that disables discovery, and give shmobster its own allow-list in its config
where it is reviewable. Log the resolved pattern set at boot either way -- the
auto-run surface should be readable, not implicit.

## 3. #149 -- egress is auto-run

`curl` and `wget` are read-only to the gate. The read half of the old exfil
chain is closed (the sandbox denies every credential file outside the tree,
#112 closed the environment), so what is left to exfiltrate is what the channel
may legitimately read: the tree. A project `.env` or `terraform.tfvars` in the
working copy is one auto-run `cat` plus one auto-run `curl` away.

**Shape of the fix:** a per-channel domain allow-list, enforced in the gate for
`curl`/`wget` and inherited by whatever #62 becomes. An off-list host should be
*mutating* -- a card, not a block -- so the legitimate case still works with a
human in the path.

## 4. #9 -- report real capabilities

The #134 spine rules cover the honesty half ("do not assert what you have not
read"). The remaining half is factual: the agent should be able to answer
"what can you do here?" from the policy rather than from prose -- channel
`cwd`, `github_repos`, whether an `aws_profile` or policy `env` exists (names
only, never values), which skills are on this channel's menu, and what the
grant layer will run without a card. A single read-only tool returning that
dict, or a block appended to the system prompt per turn. Small, and it makes
every "can you..." exchange one turn instead of three.

## 5. #23 -- DM events

`message.im` is unhandled: `_ignore_message` acks and drops. The work is
plumbing (route DMs to `handler.handle` with the DM's channel id, which
already resolves to `D...` policies -- one exists in the live policy file
today), plus deciding whether a DM's trust tier differs from a channel's. It
does not: `trusted_users` is per user, so a DM inherits the same authz.

## 6. #62 -- web-fetch tool

Firecrawl or similar, so a URL pasted into a channel can be read. Note three
constraints that already exist: the sandbox blocks nothing network-wise (this
is an API call from the agent process, not a channel command); a fetched page
is untrusted text -- it must reach the model as content, never as instructions,
which is the same rule #140 will need for memory; and the agent already has
unrestricted outbound GET through auto-run `curl`, which is why #149 comes
first. If #149 lands a per-channel domain allow-list, this issue is largely
"give the existing capability a tool-shaped front door that obeys it".

## 7. #140 -- per-channel memory

Deferred by decision 4 on #100 and kept last on purpose. When it is taken:
per-channel `MEMORY.md` in the same `channels/<channel>/` dir of the private
catalog, written only through the propose -> PR -> merge gate (#129), injected
as a clearly-labelled reference block, never into the tool-call path. The
threat model is #52's memory-poisoning section and it has not changed.

## Decide, do not build

- **#24** per-channel binary allow-list -- revisit after #148. The sandbox says
  *where*, the grant layer says *what runs uncarded*, YOLT says *what mutates*;
  a fourth axis needed a case, and #148 is arguably it, since owning the
  allow-list is the same question asked at the deployment level instead of the
  channel level. Decide #24 as part of #148 rather than on its own.
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
