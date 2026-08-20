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
- [Slack scopes](#slack-scopes)
- [Trust model](#trust-model)
- [Config & run](#config--run)
- [Skills (#74)](#skills-74)
- [Running as a service (launchd, macOS)](#running-as-a-service-launchd-macos)
- [Versioning & releases (#76)](#versioning--releases-76)
- [Upgrade announcements (#77)](#upgrade-announcements-77)
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

## Slack scopes

Every bot scope the loop actually uses, all granted by
[the manifest](deploy/slack-app-manifest.yaml):

| Scope | Buys |
|---|---|
| `app_mentions:read` | receive the `app_mention` events the agent answers |
| `chat:write` | post replies, and rewrite approval-button messages |
| `channels:history` | read thread / channel context in public channels |
| `groups:history` | the same, in private channels |
| `im:history`, `mpim:history` | the same, in DMs and group DMs |
| `reactions:write` | the `:eyes:` "on it" ack |
| `files:read` | download image and text attachments on a mention (#68) |

One the manifest deliberately leaves out:

- **`users:read`** -- only needed if you leave `agent.label` empty and want the
  label auto-derived from the app's display name (#8). Without it that lookup
  fails and the label falls back to the bot handle, usually the same string.
  Set `agent.label` and you never need this scope.

`channels:read` / `groups:read` are **not** needed -- nothing calls
`conversations.info`. That has one consequence when debugging: you cannot use
`conversations.info` to check whether the bot is in a channel. Call
`conversations.history` instead and read the error -- `channel_not_found` there
means **not a member**, not a bad token and not a bad channel ID. Fix it with
`/invite @<app name>` in that channel.

### Attachments (#68)

Mention the agent with a file attached and it reads it: images go to the model
as images, text files as text. Anything else comes back as a one-line note in
the reply saying what was skipped and why -- the agent never silently answers as
though the message were text-only.

Only files on the *mentioning* message are read. Attachments earlier in the
thread are not, because every reply in that thread would re-download them.

An app created before `files:read` landed in the manifest must **reinstall** to
grant it (same flow as `reactions:write` above). Until it does, attachments come
back as `got Slack's sign-in page instead of the file` -- Slack answers an
unauthorized file fetch with a **200 and the HTML login page**, not an error, so
that string is the scope being missing rather than a network problem.

## Trust model

Assumes **private channels and trusted invitees -- no bad actors.** The agent
responds to any @mention in any channel it's in (invite = permission to talk).
Two tiers:

- **Any invited user** -- the agent responds and acts, bounded by the channel's
  policy (default restricted: cwd / github repos / aws profile / tools).
- **Trusted users** (`trusted_users` in config: a list of Slack user IDs) -- may
  ask the agent to change a channel's restrictions via chat (the `set_policy`
  tool), to approve parked mutating commands (the `approve_command` tool), and
  to re-scan the skills catalog (the `reload_skills` tool, see **Skills**).
  Only they can widen scope; the `trusted_users` list itself is
  **file-only** (the agent can't grant trust -- no escalation). A non-trusted
  user who tries is refused loudly and all trusted users are tagged.

The `trusted_users` gate protects **config changes and approvals**, not general
use.

### Multiple instances in one channel (#60)

Two instances (e.g. a bot per machine) can share a channel. Each is its own
Slack app with a distinct bot user id (`config.BOT_USER_ID`, resolved from
`auth.test` at startup), so history is labeled by *who actually posted*: an
instance's own messages show as `<label> (me)`, a sibling's as
`<name> (another agent)`, humans as `user <id>`. This is what stops an agent
from mistaking a sibling's (or its own) posts for impersonation. `SOUL.md`
tells the agent siblings are normal collaborators, not spoofing.

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
- `skills.paths` -- directories of skills to load (see **Skills** below). Omit
  for none.

### Secrets: reference the environment, don't paste keys (opinionated)

Any string value in the config may contain `${VAR}`, expanded from the process
environment at load time -- e.g. `"api_key": "${ANTHROPIC_API_KEY}"`,
`"bot_token": "${SLACK_BOT_TOKEN}"`. A referenced variable that is **unset fails
startup loudly** (it never sends an empty credential). Prefer this over literal
keys so the config file holds no secrets. Don't like it? Send a PR.

Values are **never logged**: shmobster logs no credential, and the LiteLLM router
is pinned to non-verbose + WARNING so it can't dump request params (which carry
`api_key`). See [voitta-yolt#84](https://github.com/voitta-ai/voitta-yolt/issues/84)
for why that matters.

**macOS launchd caveat:** launchd does **not** read `~/.bash_profile`, so a
service-run shmobster won't see your shell's exports. Put the vars in the
launchctl environment (`launchctl setenv VAR value`, or osx-env-sync, which syncs
`~/.bash_profile` -> launchctl) or in the plist's `EnvironmentVariables`.
Otherwise `${VAR}` expansion fails loudly at boot.
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
    further keys -- nothing to restrict. `~` and `$VARS` are expanded at
    exec-time, so `"~/g/project"` works.
  - `github_repos` -- git/gh limited to these `owner/repo` globs (e.g.
    `["your-org/*"]` or a single `["org/repo"]`). Omit for no repo restriction.
  - `aws_profile` -- sets `AWS_PROFILE` for the channel's commands; a command
    overriding to another profile is blocked. Omit for no AWS.
  - `exclude` -- paths under `cwd` to keep off-limits, e.g.
    `["~/g/OneDrive"]`. A command whose (expanded) tokens resolve under an
    excluded path is blocked. **Best-effort only, not a sandbox:** `cwd` just
    sets the working dir, so an absolute path elsewhere, a symlink, or a shell
    resolving paths at runtime can still reach an excluded tree. It stops the
    obvious textual cases (`cat ~/g/OneDrive/x`, `cd <excluded>`) to raise the
    bar; true containment needs OS-level sandboxing (a separate, larger change).
    Omit for no exclusions.
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

## Skills (#74)

A skill is a directory holding a `SKILL.md`: YAML frontmatter with `name` and
`description`, then a Markdown body of steps. That is the format
[skillz](https://github.com/voitta-ai/skillz) already publishes for the `claude`
and `codex` hosts; shmobster is a third host and reads the same files unchanged,
so a procedure written once reaches the agent that is actually in the channel
with you.

Point at one or more catalogs:

    "skills": {
      "paths": [
        "~/g/manda/git/skillz-private/skills",
        "~/g/git.voitta/skillz/skills"
      ]
    }

Each path is a directory of `<name>/SKILL.md`. **Order is precedence** -- the
first path that defines a name wins, so a private catalog listed first shadows
the public one; shadowed entries are logged at boot, not silently dropped.

**How they reach the model.** Two stages, because the system prompt is paid on
every turn by every vendor in the waterfall:

1. **The menu** -- one line per skill in the system prompt: name plus the first
   sentence of its description, capped. The 44-skill public catalog costs about
   7KB standing. Full descriptions inline would be ~25KB; names alone would never
   be searched for, since the model cannot search for what it does not know.
2. **The body** -- a `load_skill(name)` tool the model calls when a request
   matches a menu line, returning that `SKILL.md` in full (capped at 20k chars).

With no `skills.paths` configured there is no menu and no tool -- the feature
costs nothing when unused.

**Refresh.** The index is built at boot. A trusted user can say "reload your
skills" to re-scan after pulling a catalog; the `reload_skills` tool sits behind
the same trust gate as `set_policy` (see **Trust model**). Reading files is not a
mutation, but it changes which instructions the agent will follow, which is
exactly the thing the gate is for.

**Scope.** A skill is instructions, not permission. Anything a skill tells the
agent to run still goes through YOLT and the channel policy, so a skill cannot
widen what a channel can do.

## Running as a service (launchd, macOS)

For anything but a quick foreground test, run it under launchd so it stays up
across restarts/sleep, independent of any shell. First time, make your own
(gitignored) plist from the sample and set the paths:

    cp deploy/ai.shmobster.plist.sample deploy/ai.shmobster.plist
    # edit deploy/ai.shmobster.plist: replace /Users/CHANGE_ME/path/to/shmobster
    deploy/service.sh install

Then:

    deploy/service.sh restart       # after `git pull`, to load new code (kickstart)
    deploy/service.sh update        # after editing the plist, re-copy + full reload
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

### Liveness watchdog (#66)

`KeepAlive` only reacts to a process that exits, and the nastiest Socket Mode
failure does not exit: the client reconnects forever without ever receiving
anything (handshake 101, no `hello`, no pong, server drops the socket ~20s
later, EPIPE, reconnect, repeat). Every error is caught and logged, so launchd
sees a healthy service while the agent is deaf. One instance sat like that for
13 days.

So the process watches itself. A daemon thread exits nonzero -- letting
`KeepAlive` restart it -- once the connection has looked broken for
`watchdog_timeout_sec` (default 120, minimum 90, `0` disables) by either of two
measures:

- **No stable session.** In the wedge no session survives ~21s; a healthy one
  lives for hours. The watchdog wants some session to reach 60s.
- **No ping/pong.** Covers a session that stays up but goes quiet. Pongs land
  every ~10s (`ping_interval`) no matter how busy the workspace is.

Both have to look healthy, and neither is *delivered events*: a bot in quiet
channels legitimately receives none for days. Reconnect logs are not a signal
either -- the wedged instance emitted 52,707 of them in 13 days.

The floor of 90s exists because the SDK heals ordinary stalls by itself: it
tears a session down at `ping_interval * 4` (40s) and needs another cycle to
re-establish. A shorter timeout turns that self-healing into a restart loop.

Two costs, both accepted. A genuine network outage restarts the agent every
timeout until the network returns (`ThrottleInterval=10` bounds the churn), and
each restart clears the in-memory approval queue, so a command parked before the
restart has to be asked again -- the same "safe direction" `approvals` already
takes on any restart.

## Versioning & releases (#76)

`shmobster.__version__` is the anchor. An instance reports `<version>+<short-sha>`
-- ask it which build it is and it answers from `build()`, the same string it
logs at boot and selfcheck prints. Between tags the sha is the only thing that
tells two running instances apart, which matters when each machine pulls on its
own schedule.

**Cutting a release.** Feature PRs leave the version alone. A release is its own
commit that bumps `__version__`; on master, `.github/workflows/release.yml` sees
a version with no matching tag and creates `vX.Y.Z` plus the GitHub release.
Nothing else is keyed on the version, so there is no per-PR bump gate (unlike
[skillz](https://github.com/voitta-ai/skillz), where the version *is* the plugin
cache key and a missed bump silently freezes every install).

**Notes.** `docs/release-notes/vX.Y.Z.md` is used when it exists; otherwise the
release is generated from merged PR titles. Curated notes are the norm for
anything an operator has to act on -- see
[v0.1.0](docs/release-notes/v0.1.0.md). Give each one an **Upgrading** section
naming new config keys and dependencies, since every operator holds their own
`shmobster-config.json` and a `git pull` will not fix it for them.

**0.x** holds until the config schema is stable enough that someone else's config
survives an upgrade.

**CI** (`.github/workflows/checks.yml`) runs `selfcheck.py`, parses the example
configs, and runs a structural sensitive-term gate ported from skillz
(`scripts/check-sensitive-terms.sh` -- token and key shapes, account ids, private
IPs, internal domains). The name-wordlist half of that gate stays off CI on
purpose; it reads a private out-of-repo file, see the script header.

### Upgrade announcements (#77)

An instance announces itself in its channels the first time it boots on a new
version:

> :sparkles: upgraded to **shmobster v0.2.0** (from v0.1.0) -- [release notes](https://github.com/voitta-ai/shmobster/releases/tag/v0.2.0). Now running `0.2.0+b698870`.

The trigger is a *version change*, not a boot -- the watchdog and launchd restart
this process often, and none of that is worth a message. The last announced
version lives in `shmobster-state.json` (gitignored, path from `SHMOBSTER_STATE`).

An instance with **no** recorded version announces too, without claiming where it
came from:

> :sparkles: now running **shmobster v0.2.0** -- [release notes](https://github.com/voitta-ai/shmobster/releases/tag/v0.2.0). Build `0.2.0+b698870`.

That case is a deployment installed before the state file existed *or* a brand
new one -- indistinguishable from inside the process. Staying quiet would skip
the first upgrade to any version that has this feature, which is the rollout it
was written for; the cost is one extra message on a new install, which tells that
channel which build just joined it.

A failed post is not recorded, so the next boot retries rather than losing the
announcement.

`announce` knows nothing about Slack -- it takes a `post(text)` callable. A new
ingest mode wires its own poster; see [CLAUDE.md](CLAUDE.md).

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
