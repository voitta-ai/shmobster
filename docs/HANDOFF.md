# Handoff: what to do next, and why

Written 2026-09-13 after the backlog triage that followed v0.7.2; revised that
same day when items 1 and 2 turned into ten issues, revised again 2026-09-14
with the first four of the new order done, revised 2026-09-15 when the owed
release was cut as v0.8.0, and **revised 2026-09-16, when #177 resolved the
other way and the voitta-yolt 2.0.x hold came off**.
This is the plan for the next several work items, in the order they should be
taken and with the reasoning that ranked them -- so the next session (or the
next person) starts from the argument, not from a bare issue list.

Dated records of individual sessions live in `docs/handoff/`; the most recent
is `docs/handoff/2026-09-17.md`, which carries the credential-scrub state and
the corrections that session made to its own earlier claims.

Current state: **v0.22.0 is cut; the live box is on v0.8.0 until someone
upgrades it** -- and that upgrade is now two versions and one inverted
instruction behind, so read `docs/release-notes/v0.9.0.md` before doing it. The
exec path is YOLT (its own rules only, #148) -> egress allow-list (#149) ->
grant layer (#117) -> seatbelt sandbox (#116) -> approval card (#48). A
command's environment is built from an allowlist (#112), the deployment's own
config is unreachable from a channel (#147), git's own directory is unwritable
(#184), the slack tools reach only this channel unless the policy says
otherwise (#151), every command is recorded (#129), a channel can load its own
learned skills (#130), and the agent can report its envelope rather than
improvise it (#9).

**The read-only set is ours now (#177).** voitta-yolt 2.0.x answers `unknown`
for every ordinary read, by design, so `grant.READ_VERBS` and its git/gh/aws
companions decide what auto-runs -- consulted only on `unknown`, never over
`unsafe` or `deny`. The supported voitta-yolt range is `>= 2.0.1`, which
reverses what v0.8.0 shipped.

**The security re-audit is closed.** #123 and all ten of its findings are
resolved, along with #184 and #186, which the re-audit did not find and the
adversarial reviews did. What remains is #191 and #208. #23 closed with v0.13.0; #140 and #190 with
v0.14.0; #62 and #206 with v0.15.0; #213 with v0.16.0; #215 with v0.17.0; #219 with v0.18.0; #222 with v0.19.0; #211, #210 and #227 with v0.20.0; #233 with v0.21.0; #231 with v0.22.0. **Ten releases in a
row added no config key, and v0.20.0 adds one optional, defaulted key** -- criterion 1 -- and #62 did not reset it after all: stdlib
urllib reads a pasted link without a vendor or a token. #1 closed as superseded by the README and this file.

## The v0.8.0 release, and the range it pinned

**Cut 2026-09-15 against voitta-yolt `>= 1.6.0, < 2.0.0`** -- that is option 3
of the checklist below, taken deliberately, and not a resolved #177. 2.0.0 was
tagged and measured: adopting it would make every ordinary read in a channel
park for an approval card, so the hold on adoption stands, tracked as #177
against voitta-yolt#144; the yolt session pings this one either way. **Adopting
2.0.x is the next release's question, not a debt this one left behind.**

The rest of this section is why that range is the supported one. It is what the
next release inherits, so it stays.

Phase 3 cut `rules/shell.json` from 136 entries to 28 -- the file now carries
only what YOLT refuses to delegate. For the PreToolUse hook that costs nothing,
because `safe` and `unknown` are both a silent exit. Here they are opposite
verdicts, so `cat`, `ls`, `grep`, `head`, `git status`, `git diff`, `gh pr
list`, `aws s3 ls` and `curl` all moved off the auto-run tier; `pwd`, `echo`
and `python3 -c` are what is left. Measured end to end: `cat README.md | head
-1` -> `NOT RUN -- pending approval`.

The one-sentence version, which is the part worth carrying: **2.0.0 collapses
"we deliberately delegate this" and "we could not classify this" into one
`unknown`, and a consumer that must fail closed on the second has no choice but
to fail closed on the first.**

**Superseded 2026-09-16: the supported range is now `>= 2.0.1`, and #177
resolved by deciding the question rather than by waiting for an answer.** The
paragraph below is what v0.8.0 shipped against, kept because the floor argument
still holds; the ceiling argument does not.

The reason the hold came off is that the thing it was waiting for cannot
arrive. voitta-yolt's `rules/shell.json` says delegation is defined by the
*absence* of a rule -- so `cat` and a command it never heard of are one
`unknown`, upstream cannot tell them apart either, and separating them would
mean restoring the list 2.0.0 deleted. The read-only set therefore moved here,
as `grant.READ_VERBS`, consulted only on `unknown` and never over `unsafe` or
`deny`. It is deliberately not parity with 1.6.0's `safe` set, which called
`git branch -D x`, `git remote add`, `git config <k> <v>` and `gh api` safe.
The new floor is 2.0.1 rather than 2.0.0 because `--cwd` arrived there, and
without it 2.0.x's `deny` predicates judge whichever directory the agent
process is in (#182).

Historically, until #177 resolved, the supported range was **voitta-yolt >=
1.6.0 and < 2.0.0**. The floor is 1.6.0, not the 1.2.0 where `--no-user-allow` landed: four
write-target holes closed in between, and voitta-yolt#128 (1.3.0) is the one
that mattered here -- before it, `echo x > $HOME/.ssh/authorized_keys`
classified *safe*, which on this side means auto-run with no card. Startup says
so: the preflight probe is `cat /dev/null`, a command
Phase 3 delegated, rather than the `echo` it used to be -- `echo` is one of the
three things 2.0.0 still calls safe, so the old probe would have passed on a
classifier that cards every read.

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

The number was **v0.8.0** (see **Versioning** below for why it was not 1.0.0).

**The pre-cut checklist, as it ran:**

1. ~~Re-verify #172 against the real classifier~~ -- done, and it found
   something else: `deny` is unreachable from `run_cli()`, which builds the
   classifier without `policy=`, so `git push` on the default branch returns
   `unsafe` rather than `deny` (voitta-yolt#143). #172's handling is correct
   and inert until that is wired. Not a blocker; the direction is safe.
2. ~~Read the yolt side's unsafe-to-safe list~~ -- done, and the question was
   the wrong one. Nothing moved *to* `safe`; everything useful moved *off* it.
   Ask both directions next time.
3. ~~#177 resolved, or a decision to ship against `>= 1.6.0, < 2.0.0` and
   adopt 2.0.x later~~ -- the decision, not the resolution. #178 made the range
   a startup probe rather than a pin nobody checks, and #179 corrected the
   floor to 1.6.0.
4. ~~Then the three operator notes~~ -- done, in the release notes.

**The release notes carry the three things that break a channel quietly**, and
`docs/release-notes/v0.8.0.md` is where they now live rather than here, so the
two copies cannot drift: `allow_domains` in every channel policy (#149), the
supported voitta-yolt range with the reason 2.0.0 is excluded (#148, #177), and
`logging.path` plus one `chmod 600` of the existing log (#155). The notes also
say the thing that is a change rather than a fault: after this release
`gh pr create`, `gh pr merge`, `git push`, `codex exec` and any fetch to a host
outside `allow_domains` ask first.

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
| 0 | ~~#177 + #182 yolt 2.0.x~~ | M | **Done 2026-09-16.** The read-only set is ours now; `--cwd` passed so `deny` judges the channel's repo |
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

## Versioning: what each number means here

Settled 2026-09-15, while deciding whether the release after v0.7.2 was 0.8.0
or 1.0.0. It was 0.8.0. Writing the argument down so the next release does not
re-run it.

- **PATCH** (`0.7.1` -> `0.7.2`) -- nothing an operator has to do or notice. A
  fix, a doc, a log line.
- **MINOR** (`0.7.2` -> `0.8.0`) -- new behavior, including behavior that
  breaks an existing deployment. While this is 0.x that is the normal case, and
  the release notes carry the operator's to-do list rather than the version
  number doing it. v0.8.0 requires a dependency bump, needs a new policy key in
  every channel, and turns several commands that used to run silently into
  cards -- all of it minor.
- **MAJOR** (`0.x` -> `1.0.0`) -- **not a bigger changelog: a promise.** That
  the config schema and the gate contract are stable enough that the next break
  costs a major. Everything after 1.0 inherits that promise.

### What 1.0.0 is waiting for

Four things, all checkable, none of them "it feels ready":

1. **A release cycle that adds no config key.** v0.8.0 added four in seven days
   -- `env_passthrough` (#112), `allow_domains` (#149), `logging.*` and
   `learning.trajectory_days` (#155). A schema still moving that fast is not
   one to freeze.
2. **voitta-yolt 2.0.0 running live underneath it** for a couple of weeks. We
   are pinning a version that is not tagged yet and implementing its `deny`
   semantics from a description; declaring our own contract stable on top of a
   contract still being written is a promise about someone else's work.
3. **The re-audit's remaining findings closed or explicitly accepted** --
   #150, #151, #152 and the rest of #123's list. Shipping 1.0 with the security
   review's own list open is a claim the review does not support.
4. **The deployment actually on the released build.** The live box is on
   v0.8.0; v0.12.0 is cut. A contract that has never run is not stable, it is
   untested -- and v0.8.0 pins voitta-yolt `< 2.0.0`, so criterion 2's clock
   has not started either. Both of those are the same action.

   *(Corrected 2026-09-16: this said v0.7.2 through several releases. The
   number was carried forward from the 2026-09-13 triage and never
   re-checked -- including by me, into four sets of release notes.)*

The argument *for* 1.0 is real and worth recording too: the security model
arrived this cycle -- five gates, each documented and covered by selfcheck,
self-modification closed at the config (#147) and at the prompt (#174),
governance enabled (#154). That is the thing 1.0 would be declaring. It earns
the number after it survives contact with the live box, not before.

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
