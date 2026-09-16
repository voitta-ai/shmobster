# Handoff: what to do next, and why

Written 2026-09-13 after the backlog triage that followed v0.7.2; revised that
same day when items 1 and 2 turned into ten issues, and **revised again
2026-09-14**, with the first four of the new order done and a release owed.
This is the plan for the next several work items, in the order they should be
taken and with the reasoning that ranked them -- so the next session (or the
next person) starts from the argument, not from a bare issue list.

Current state: **v0.7.2 is what is released; master is ahead of it and owes a
release** (see below). The exec path is YOLT (its own rules only, #148) ->
egress allow-list (#149) -> grant layer (#117) -> seatbelt sandbox (#116) ->
approval card (#48). A command's environment is built from an allowlist (#112),
the deployment's own config is unreachable from a channel (#147), every command
is recorded (#129), a channel can load its own learned skills (#130), and the
agent can report its envelope rather than improvise it (#9). 17 issues are
open; seven of them are the security re-audit's remaining findings.

## Before the next release

**The release waits on voitta-yolt 2.0.0.** Decided 2026-09-15: the
`feature/auto-mode-realignment` pivot is landing over there, it carries a major
bump, and rather than release against 1.2.0 and re-release a week later we pin
the major and cut behind it. The yolt session pings this one when it is tagged.

What we depend on across that bump, and what it costs if either half goes:

- `grammar_classifier.py --no-user-allow '<command>'` is how every command is
  classified. **Flag rejected or removed** -> the classifier reads the flag as
  the command, every verdict becomes a verdict about the string, and every
  command in every channel parks. Fail-closed and useless, with one startup
  warning naming the version.
- The JSON's `allow_patterns`, asserted `0` at boot. **Key dropped, flag kept**
  -> preflight logs `cannot be confirmed` and the agent runs on. Degraded, not
  broken.

Both are on the yolt side's reconciliation list for 2.0.0: the flag accepted as
a no-op, the key retained and honestly `0` (the allow path is deleted there, so
zero is true rather than a placeholder).

A third thing crosses that bump, and it is not a failure mode but a new value:
**2.0.0 emits a fourth verdict, `deny`** -- an already-unsafe command that a
git-state predicate refuses outright. Every consumer here compares against
`"safe"`, so it parks rather than falling through; #172 then made the handling
deliberate (a refusal skips the grant layer, and its card says it was refused
rather than queued). The general shape is worth remembering beyond this bump:
**a new verdict nobody handles sends the most restrictive answer down the least
restrictive path**, which is why the comparison is against `"safe"` and not
against `"unsafe"`.

**Before cutting, with 2.0.0 in hand:**

1. Re-verify #172 against the real classifier rather than the stubbed verdict:
   a genuinely denied command parks, is not offered to the grant layer, and
   renders as a refusal.
2. Read the yolt side's unsafe-to-safe list. Anything moving *to* `safe` starts
   auto-running in a channel with no card, so it is judged per command, not per
   release. They send it before tagging, not after.
3. Then the three operator notes below.

**The release notes have to carry three things, or an upgrade breaks a channel
quietly.** All are consequences of what shipped 2026-09-14 and 2026-09-15:

1. **`allow_domains` must be added to each channel's policy** (#149). A channel
   with no list cards *every* `curl`, `wget`, `git fetch`, `git pull` and
   `git ls-remote`. That is the correct default for a channel nobody has
   thought about, and a surprise for a channel whose normal work pulls from
   GitHub -- so the notes give the shape:
   `"allow_domains": ["github.com", "api.github.com", "*.githubusercontent.com"]`.
2. **The required voitta-yolt version, by release number** (#148). shmobster
   passes `--no-user-allow`, which landed in voitta-yolt 1.2.0
   (voitta-ai/voitta-yolt#126) -- but per the hold above this release pins
   **2.0.0**. Link the yolt release, not just the number.
3. **`logging.path`, and one `chmod 600` of the existing log** (#155). With the
   key set the agent owns a rotated 0600 file; without it, nothing changes and
   the launchd-redirected log keeps growing -- it was **185 MB, mode 0644** on
   the live box when this was written. launchd's `Umask` (now in the plist
   sample) only applies to files it creates, so the existing log keeps its mode
   until someone chmods or deletes it. Trajectories are pruned to
   `learning.trajectory_days` (default 14) at startup, which needs no action
   but is worth naming, since the first restart after this deletes files.

Also worth a line: after this release, commands that used to run silently ask
first -- `gh pr create`, `gh pr merge`, `git push`, `codex exec`, and any fetch
to a host not in `allow_domains`. That is the change, not a fault, and saying so
in the notes is cheaper than answering it once per channel.

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

### 2026-09-14

- **#147, the deployment's own config** -- PR #158. `config.SELF_FILES` is
  refused by `policy.check` with a reason and denied `file-read*`/`file-write*`
  in the sandbox profile. The write deny covers rename, unlink and link:
  `mv`, `cp`, `sed -i`, `rm`, `ln -sf`, hardlink-then-rename and the `$var` and
  `sh -c` forms all fail with the file byte-identical.
- **#148, the exec allow-list** -- PR #159, and voitta-ai/voitta-yolt#126
  upstream first. `classify()` passes `--no-user-allow`; `yolt_gate.preflight()`
  asserts at boot that `allow_patterns` came back `0`. 123 inherited patterns
  before, 0 after; `gh pr merge` and `codex exec` now park.
- **#149, egress** -- PR #160. A fetch runs uncarded only when every host it
  names is in the channel's `allow_domains`. Enforced in `run_shell` *and* in
  the grant layer's read-only fallback, which otherwise handed back the grant
  the demotion had just refused. Covers the git subcommands that contact a
  remote, which the adversarial review caught and I had missed.
- **#9, report real capabilities** -- this PR. A `describe_capabilities` tool
  reads the channel's envelope out of the policy; the persona points every
  "what can you do" question at it. Names, never values.

## The order

| # | Issue | Size | Why here |
|---|---|---|---|
| 1 | #23 DM events | S | The last ingest gap in Slack; self-contained, and the smallest thing left |
| 2 | #62 web-fetch tool | M | Take it now that #149 decided its shape: a tool-shaped front door that obeys `allow_domains` |
| 3 | #140 per-channel memory | L | Deliberately last: it is the piece with the injection surface |

Running in the background, no order among them: #150 (`github_repos` is a text
guard -- document or enforce), #151 (ungated `slack_post`), #152 (lockfile,
stale litellm/aiohttp), #153 (attachment bearer on redirect), #154 (repo
governance), #155 (log perms, trajectory retention), #156 (telemetry flag).
Each is self-contained and none blocks the three above.

Then decide, do not implement: #24, #16, #6, #1, #51 (see **Decide, do not
build**).

## Done: #9 -- report real capabilities

Shipped as `describe_capabilities` (tools.py): a read-only tool returning the
channel's `cwd`, `github_repos`, `aws_profile`, `allow_domains`, the **names**
of its policy `env` and `env_passthrough`, its `allow_read`/`allow_write`/
`exclude`, its skill menu, and what the grant layer runs without a card. A tool
rather than a per-turn prompt block, so the standing prompt pays nothing for it;
SOUL.md carries the one line that sends the question there.

## 1. #23 -- DM events

`message.im` is unhandled: `_ignore_message` acks and drops. The work is
plumbing (route DMs to `handler.handle` with the DM's channel id, which
already resolves to `D...` policies -- one exists in the live policy file
today), plus deciding whether a DM's trust tier differs from a channel's. It
does not: `trusted_users` is per user, so a DM inherits the same authz.

## 2. #62 -- web-fetch tool

Firecrawl or similar, so a URL pasted into a channel can be read. Note three
constraints that already exist: the sandbox blocks nothing network-wise (this
is an API call from the agent process, not a channel command); a fetched page
is untrusted text -- it must reach the model as content, never as instructions,
which is the same rule #140 will need for memory; and the agent already has
unrestricted outbound GET through auto-run `curl`, which is why #149 comes
first. If #149 lands a per-channel domain allow-list, this issue is largely
"give the existing capability a tool-shaped front door that obeys it".

## 3. #140 -- per-channel memory

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
