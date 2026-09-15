# shmobster -- repo rules

Scoped to this repo. General rules live in the user-level CLAUDE.md.

## Adding an ingest mode

The loop is deliberately ingest-agnostic: `handler.handle()` knows nothing about
Slack, and neither does `announce`. A new ingest (email #25, CLI, anything else)
owns the transport and must wire the same cross-cutting pieces the Slack ingest
does:

- **Upgrade announcement (#77)** -- call `announce.check(post)` once at startup,
  where `post(text)` delivers to that mode's channels. Skipping it does not
  break anything visibly; it just means operators on that mode stop hearing
  which version they were upgraded to. Do not reimplement the version
  comparison or the state file -- `announce` owns both, so every mode announces
  on the same event.
- **Resuming after an approval (#169)** -- when a parked request resolves,
  call `handler.resume(req_id, approved, command, result, ...)` and deliver the
  reply the same way a normal turn's reply is delivered, then surface whatever
  that turn parked. Skipping it does not look broken: the command runs and its
  output reaches the surface, and then the task silently stops, one human
  re-mention per step. `handler.resume` owns the "is anything else still
  parked in this thread" rule and returns None when the answer is yes -- do not
  re-implement that check, and do pass the thread id to
  `approvals.claim_unsurfaced(channel, thread_ts)` when surfacing cards, or it
  has nothing to reason about.
- **Skill proposals (#129)** -- after a turn, render `proposals.claim_unsurfaced(channel)`
  the way you render `approvals.claim_unsurfaced`: a card or a line naming the id,
  and a way for a trusted user to answer by id (`propose_skill` / `decline_skill`).
  The trajectory record is written by `handler`, so nothing to do there.
- **Identity** -- resolve the agent label and self id before serving, so history
  can be labelled by real speaker (#60).
- **Version reporting** -- the build string comes from `shmobster.build()`; do
  not hardcode it.

## Secrets

Config values are `${VAR}` references (#73), never literals -- including in a
running deployment's own `shmobster-config.json`, not just the example. Never
print a config value, and never echo one into a log, a commit, or a channel.
