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

## One Socket Mode consumer per Slack app

Nothing but this process may connect with this deployment's app-level token
(`slack.app_token`). Slack hands each event to one of an app's open Socket Mode
connections, so a second consumer silently takes a share of the mentions. On
2026-10-06 an agents-framework approval-button listener configured with this
app's `xapp-` token acked and dropped them. The miss looks like the #66 wedge,
but the watchdog stays green, because this process's own connection is fine.
When wiring any other tool that needs inbound Slack events or button clicks
(approvals, cards, listeners), give it its own app; never point it at this one.
The README's "Create the Slack app" note has the symptom and the check.

## Posting into a channel on an operator's behalf

Never post through this agent's own Slack token when the point of the message is
to make the agent act. Slack does not deliver `app_mention` for a message posted
by the same app, so the mention never reaches `on_mention` and the turn simply
never happens -- and the post reads as the agent talking about itself. An
incoming webhook belonging to this app is the same identity and fails the same
way. A bot or webhook post also carries no human `user`, so `identity.speaker`
reads it as another agent and it can never satisfy a `trusted_users` check.

A Slack MCP server or helper script on the deployment host is usually configured
with this agent's app, so check whose token it holds before using it. Post as
the person instead (the `slack-xoxc-session-client` skill), or hand them the
text to paste. The full reasoning and the verification steps are in the
`slack-agent-cannot-wake-itself` skill.

## Secrets

Config values are `${VAR}` references (#73), never literals -- including in a
running deployment's own `shmobster-config.json`, not just the example. Never
print a config value, and never echo one into a log, a commit, or a channel.
