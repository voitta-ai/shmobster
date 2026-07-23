# shmobster

Standalone Slack agent, built bottom-up. Two features force it to exist:
**multi-vendor API waterfall** (rate limits) and **multi-user Slack authz**
(collaborators). Everything else is borrowed or transplanted.

## Contents

- [Own / rent / delegate](#own--rent--delegate)
- [Operating principle: 0, 1, 2, 3, many](#operating-principle-0-1-2-3-many)
- [Authz = f(user, channel)](#authz--fuser-channel)
- [Iterations](#iterations)
- [New instance setup](#new-instance-setup)
- [Create the Slack app](#create-the-slack-app)
- [Trust model](#trust-model)
- [Config & run](#config--run)
- [Running as a service (launchd, macOS)](#running-as-a-service-launchd-macos)
- [Running multiple instances](#running-multiple-instances)
- [License](#license)

## Own / rent / delegate

- **Own:** orchestration loop, Slack door + socket reliability, authz.
- **Rent:** LiteLLM (multi-vendor waterfall), voitta-yolt (exec classifier,
  reused as a library).
- **Delegate:** browser work to `claude -p` (has claude-in-chrome); do not
  waterfall browser tasks.
- **Transplant:** the `.md` spine (SOUL/USER/CALIBRATION/RUNBOOKS/TOOLS/memory)
  is adapted from [OpenClaw](https://github.com/openclaw/openclaw)'s
  openclaw-workspace (MIT -- see
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)) and is runtime-agnostic; the
  loop boots by reading it.

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
  `channel_id -> {cwd_allow, github_allow, aws_profile, extra_whitelist, owner_only}`

## Iterations

See issues. 0 skeleton -> 1 exec-gate (YOLT) -> 2 per-channel policy ->
3 waterfall hardening -> 4 multi-user.

## New instance setup

One instance per machine (each its own Slack app + config):

1. Clone this repo and [voitta-ai/voitta-yolt](https://github.com/voitta-ai/voitta-yolt)
   (the exec classifier).
2. `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`
3. Create the Slack app (below) -> bot + app tokens.
4. `cp examples/shmobster-config-example.json shmobster-config.json` and fill:
   Slack tokens, `agent.label`, `channels`, `waterfall` keys, and
   `exec.yolt_classifier` (path to voitta-yolt's `hooks/grammar_classifier.py`).
   Then `chmod 600 shmobster-config.json`. For per-channel policy,
   `cp examples/shmobster-policies-example.json shmobster-policies.json` and fill.
5. `.venv/bin/python selfcheck.py` (offline sanity).
6. Run under launchd (see below).

## Create the Slack app

Shmobster connects over Socket Mode, so it needs its own Slack app (a bot token
and an app-level token). A workspace can host more than one -- e.g. a
`Shmobster Dev` app for testing next to a live one -- so give each a distinct
name and, ideally, a dedicated test channel to avoid cross-talk.

1. Edit [`deploy/slack-app-manifest.yaml`](deploy/slack-app-manifest.yaml): set `display_information.name` and
   `features.bot_user.display_name` to the name you want (e.g. `Shmobster Dev`).
2. https://api.slack.com/apps -> **Create New App** -> **From a manifest** ->
   pick the workspace -> paste [the manifest](deploy/slack-app-manifest.yaml) -> **Create**.
3. **OAuth & Permissions** -> **Install to Workspace** -> Allow. Copy the
   **Bot User OAuth Token** (`xoxb-...`) into `slack.bot_token`.
4. **Basic Information** -> **App-Level Tokens** -> **Generate Token and Scopes**
   -> add scope `connections:write` -> **Generate**. Copy the token
   (`xapp-...`) into `slack.app_token`.
5. In Slack, invite the bot: `/invite @<app name>` in your test channel.
6. Get the channel ID: right-click the channel -> **Copy link** and take the
   `C...` segment. Put `{ "name": "...", "id": "C..." }` into `slack.channels`.
7. Run (below) and mention `@<app name>` in that channel.

> One app = one running process. Two processes on the same app fight over Slack's
> per-app socket connection cap, so use a *separate* app for dev vs. the live bot.

> The manifest includes `reactions:write` (for the `:eyes:` "on it" ack). Apps
> created from the manifest get it automatically; an app that predates the scope
> must **reinstall** to grant it (OAuth & Permissions -> add the scope ->
> Reinstall to Workspace) -- until then the reaction just no-ops.

## Trust model

Assumes **private channels and trusted invitees -- no bad actors.** The agent
responds to any @mention in any channel it's in (invite = permission to talk).
Two tiers:

- **Any invited user** -- the agent responds and acts, bounded by the channel's
  policy (default restricted: cwd / github repos / aws profile / tools).
- **Trusted users** (`trusted_users` in config: a list of Slack user IDs) -- may
  ask the agent to change a channel's restrictions via chat (the `set_policy`
  tool) and to approve parked mutating commands (the `approve_command` tool).
  Only they can widen scope; the `trusted_users` list itself is
  **file-only** (the agent can't grant trust -- no escalation). A non-trusted
  user who tries is refused loudly and all trusted users are tagged.

The `trusted_users` gate protects **config changes and approvals**, not general
use.

## Approving mutating commands (#48)

Two independent gates, deliberately separate:

- **Approval** answers *may this run at all* -- YOLT says a command is mutating,
  so a human has to say yes.
- **Channel policy** answers *is this in scope* -- cwd / github repos / aws
  profile. It is enforced on approved commands too; widening `github_repos` does
  not auto-approve anything.

When the agent hits a mutating command it parks it and posts **Approve / Deny**
buttons in the thread (#50):

    :lock: Needs approval [3] (mutating)
    ```gh issue create ...```
    [ Approve ]  [ Deny ]

A trusted user clicks; the command runs under the channel's policy and the
message is rewritten in place with the outcome, so the buttons can't be
re-clicked. Talking works too -- `@agent approve 3` calls the same
`approve_command` tool -- which is the fallback when the buttons aren't
available.

The click is authorized by the Slack user id on the interaction, never by
anything the model says, so the agent cannot approve its own request. A
non-trusted click is refused loudly and tags the trusted users, same as
`set_policy`. Note that a click bypasses the model entirely: the command output
is posted raw, not summarized.

Requests are in-memory and channel-scoped: a restart clears them (re-ask rather
than run a stale approval), and an approval in one channel cannot release a
command parked in another.

Buttons need **Interactivity** enabled on the Slack app. Apps created from the
current [`deploy/slack-app-manifest.yaml`](deploy/slack-app-manifest.yaml) get it;
an older app needs **Interactivity & Shortcuts** -> toggle on -> reinstall.
Over Socket Mode there is no request URL to fill in and no extra OAuth scope.

## Config & run

One JSON config, no `.env`. Copy the example and fill it in:

    cp examples/shmobster-config-example.json shmobster-config.json
    chmod 600 shmobster-config.json   # holds secrets; gitignored

`shmobster-config.json` fields:

- `slack.bot_token` / `slack.app_token` -- from your Slack app (see
  **Create the Slack app** above).
- `slack.channels` -- list of `{name, id}` channels Shmobster responds in
  (Iter 0: just m-and-a). `name` is for humans; `id` is what Slack matches.
- `agent.label` -- name shown in the post marker `[agent: <label>]`. Leave empty
  (or omit) to auto-derive from the Slack app's display name on boot (#8), so the
  label matches whatever you named the app.
- `agent.workspace` -- path to the `.md` spine (point at an openclaw-workspace
  clone, or use the bundled `./workspace`).
- `waterfall` -- ordered vendor list, first = primary. Each entry: `name`,
  `model` (LiteLLM id), `api_key`, optional `api_base` (for OpenAI-compatible
  endpoints like openrouter / nvidia).
- `exec` -- shell-exec gate (Iter 1). `yolt_classifier`: path to
  [voitta-yolt](https://github.com/voitta-ai/voitta-yolt)'s
  `hooks/grammar_classifier.py` -- read-only commands auto-run, mutating ones
  park for a trusted user's approval (see **Approving mutating commands**).
  `cwd`: working dir for commands. `timeout_sec`: per
  command. (Clone voitta-yolt first; its `tree-sitter` + `tree-sitter-bash` deps
  are in requirements.txt.)
Per-channel policy lives in its own file, not in `shmobster-config.json` --
policies are machine-specific but not secret, so they are versioned separately
from the token/key config:

    cp examples/shmobster-policies-example.json shmobster-policies.json

`shmobster-policies.json` (gitignored; path overridable via `SHMOBSTER_POLICIES`):

- `channel_policies` / `default_policy` -- per-channel capability envelope
  (Iter #4). Channels not listed use `default_policy`. Each policy:
  - `cwd` -- commands run here (a channel scoped to a project points at that
    project's dir). A *free-for-all* channel is just `{ "cwd": ... }` with no
    further keys -- nothing to restrict.
  - `github_repos` -- git/gh limited to these `owner/repo` globs (e.g.
    `["your-org/*"]` or a single `["org/repo"]`). Omit for no repo restriction.
  - `aws_profile` -- sets `AWS_PROFILE` for the channel's commands; a command
    overriding to another profile is blocked. Omit for no AWS.
  - `env` -- extra environment variables injected only for this channel's
    commands, e.g. a per-project `VERCEL_TOKEN` or `HEROKU_API_KEY`. These are
    **secrets**: they live only in the gitignored `shmobster-policies.json`
    (keep it `chmod 600`); the example file carries placeholders only.

Because `env` may hold secrets, treat `shmobster-policies.json` like the main
config: gitignored, `chmod 600`. For back-compat, inline `channel_policies` /
`default_policy` in the main config are still honored when no
`shmobster-policies.json` exists.

Run:

    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    .venv/bin/python selfcheck.py            # offline sanity check
    .venv/bin/python -m shmobster.slack_app  # start the agent (foreground)

## Running as a service (launchd, macOS)

For anything but a quick foreground test, run it under launchd so it stays up
across restarts/sleep, independent of any shell. First time, make your own
(gitignored) plist from the sample and set the paths:

    cp deploy/ai.shmobster.plist.sample deploy/ai.shmobster.plist
    # edit deploy/ai.shmobster.plist: replace /Users/CHANGE_ME/path/to/shmobster
    deploy/service.sh install

Then:

    deploy/service.sh restart       # after `git pull`, to load new code
    deploy/service.sh update        # after editing the plist, re-copy + restart
    deploy/service.sh status        # pid / state
    deploy/service.sh logs          # tail logs/shmobster.err.log
    deploy/service.sh uninstall     # stop + remove

The real `deploy/ai.shmobster.plist` is gitignored (paths are machine-specific);
`deploy/ai.shmobster.plist.sample` is the committed template. The plist sets
`KeepAlive` + `ThrottleInterval=10` (respawn backoff -- the anti-crash-loop
guard). Logs go to `logs/shmobster.{out,err}.log`.

It also sets `PATH` explicitly, which matters more than it looks (#50): launchd
gives a process only `/usr/bin:/bin:/usr/sbin:/sbin`, so without it the agent
cannot see `gh`, `aws`, `node` or anything else under `/opt/homebrew/bin`, and
those commands fail with exit 127 `command not found` -- easy to misread as the
approval gate blocking them. If your plist predates this, copy the
`EnvironmentVariables` block from the sample and run `deploy/service.sh update`.
Check what the running agent actually has:

    ps eww "$(launchctl print gui/$(id -u)/ai.shmobster.agent | awk '/pid =/{print $3}')" | tr ' ' '\n' | grep ^PATH=

## Running multiple instances

Each instance is one config file + one process. `shmobster` is just the project
name; name each instance via `agent.label` (or let it auto-derive from the app).

- **Different machines** (e.g. Barrymore here, Cosima elsewhere): nothing
  special -- each machine has its own gitignored `shmobster-config.json` and
  plist, and the default launchd Label doesn't collide across machines.
- **Ad-hoc / a second config:**
  `SHMOBSTER_CONFIG=/path/other.json .venv/bin/python -m shmobster.slack_app`.
- **Two instances on the *same* machine** additionally need distinct launchd
  Labels, log paths, and `SHMOBSTER_CONFIG` per plist -- not yet parameterized.

## License

MIT -- see [LICENSE](LICENSE).
