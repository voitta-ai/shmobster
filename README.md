# shmobster

Standalone Slack agent, built bottom-up. Two features force it to exist:
**multi-vendor API waterfall** (rate limits) and **multi-user Slack authz**
(collaborators). Everything else is borrowed or transplanted.

## Own / rent / delegate

- **Own:** orchestration loop, Slack door + socket reliability, authz.
- **Rent:** LiteLLM (multi-vendor waterfall), voitta-yolt (exec classifier,
  reused as a library).
- **Delegate:** browser work to `claude -p` (has claude-in-chrome); do not
  waterfall browser tasks.
- **Transplant:** the openclaw-workspace `.md` spine
  (SOUL/USER/CALIBRATION/RUNBOOKS/TOOLS/memory) is runtime-agnostic; the loop
  boots by reading it.

## Operating principle: 0, 1, 2, 3, many

Each axis sits at its own cardinality; architect each to its number; advance
only when that count actually increments.

- vendors = **many** -> rented (LiteLLM, config list)
- owners = **2** -> hardcoded pair
- collaborators = **0 -> 1** -> binary owner/non-owner, no RBAC
- workspace / tenant = **1** -> hardcoded, no multi-tenant
- channels = **many** -> per-channel policy is config

Generalize only when someone else wants in. Not before.

## Authz = f(user, channel)

- **YOLT** answers *is this command mutating?* (read-only -> run; mutating -> gate)
- **Channel policy** answers *is this in scope?* -- a config map
  `channel_id -> {cwd_allow, github_allow, aws_profile, extra_allowlist, owner_only}`

## Iterations

See issues. 0 skeleton -> 1 exec-gate (YOLT) -> 2 per-channel policy ->
3 waterfall hardening -> 4 multi-user.

## Config & run

One JSON config, no `.env`. Copy the example and fill it in:

    cp examples/shmobster-config-example.json shmobster-config.json
    chmod 600 shmobster-config.json   # holds secrets; gitignored

`shmobster-config.json` fields:

- `slack.bot_token` / `slack.app_token` -- from a Slack app (see
  `deploy/slack-app-manifest.yaml`) or the existing @Shmobster bot.
- `slack.channels` -- list of `{name, id}` channels Shmobster responds in
  (Iter 0: just m-and-a). `name` is for humans; `id` is what Slack matches.
- `agent.workspace` -- path to the `.md` spine (point at an openclaw-workspace
  clone, or use the bundled `./workspace`).
- `waterfall` -- ordered vendor list, first = primary. Each entry: `name`,
  `model` (LiteLLM id), `api_key`, optional `api_base` (for OpenAI-compatible
  endpoints like openrouter / nvidia).

Run:

    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    .venv/bin/python selfcheck.py            # offline sanity check
    .venv/bin/python -m shmobster.slack_app  # start the agent
