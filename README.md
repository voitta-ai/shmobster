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
- [Free-tier fallbacks](#free-tier-fallbacks)
- [When a vendor runs out of budget (#80)](#when-a-vendor-runs-out-of-budget-80)
- [Codex subscription as a rung (#35)](#codex-subscription-as-a-rung-35)
- [Skills (#74)](#skills-74)
- [Credential redaction (#72)](#credential-redaction-72)
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

    :lock: Needs approval [a1b2c3d4-3] (mutating)
    ```gh issue create ...```
    [ Approve ]  [ Deny ]

A trusted user clicks; the command runs under the channel's policy and the
message is rewritten in place with the outcome, so the buttons can't be
re-clicked. Talking works too -- `@agent approve a1b2c3d4-3` calls the same
`approve_command` tool -- which is the fallback when the buttons aren't
available.

The id is unique per boot (#109): a counter, prefixed with a nonce drawn fresh
at every start. A card is a Slack message and outlives the process -- and
restarts are routine, since the #66 watchdog exits on a wedged socket and the
supervisor brings it straight back -- while the counter alone restarts at 1. So
without the nonce, acting on an old card after a restart would release whichever
command had since inherited its number: the human approves what the card shows
them and something else runs, with both the channel scope and the trust check
satisfied.

The nonce is on the id the card *prints*, not only on the value its button
carries, because a card that has gone stale still shows its number and still
invites someone to type it. Both routes have to fail, so a bare `approve 3` is
not completed into this boot's request 3 -- it resolves to nothing, and says so.

The refusal says how many requests are parked here, never which. That reply is
another turn in the model's tool loop, so an id in it is an id the agent can
approve on its own initiative, for a command no human quoted -- the same
boundary from the other side. The id lives on the card, where the human is.

The click is authorized by the Slack user id on the interaction, never by
anything the model says, so the agent cannot approve its own request. A
non-trusted click is refused loudly and tags the trusted users, same as
`set_policy` -- but the card itself is left alone (#94), because a refusal
resolves nothing: the buttons stay live for a trusted user, and the command
stays visible instead of being overwritten by the refusal. The refusal names
who clicked, which button, which command it did not run, and says the buttons
are still there to be used (#107) -- without that it reads as though the click
consumed the request. Unlike the
`set_policy` refusal it makes no allowance for the agent having acted on its
own, because a button press can only have come from a human. Note that a click
bypasses the model entirely: the command output is posted raw, not summarized.

Every command's disposition is logged to `logs/shmobster.err.log` (#97), so a
parked command survives the loss of its card and "did it try that and get
blocked, or never try?" has an answer:

    approvals: parked [a1b2c3d4-3] in C0... (mutating): 'gh issue create ...'
    approvals: claimed [a1b2c3d4-3] in C0...: 'gh issue create ...'
    run_shell: running: 'git log --oneline -5'
    run_shell: exit 0: 'git log --oneline -5'
    run_shell: blocked by policy (repo 'x/y' not in channel whitelist ['a/b']): 'gh repo view x/y'

Commands are scrubbed at the emission site, not by the formatter the Slack
ingest installs -- `approvals` and `tools` are reachable without it, and a log
outlives the channel a command was posted to. They are written as `repr`, so a
command containing a newline cannot forge a line in the record it appears in.

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
- `budget_park_sec` -- how long to skip a vendor that reported no budget
  (default 3600; 0 disables). See **When a vendor runs out of budget**.
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
service-run shmobster won't see your shell's exports and `${VAR}` expansion fails
loudly at boot. Put the vars in the launchctl environment (`launchctl setenv VAR
value`, or a sync tool such as osx-env-sync) or in the plist's
`EnvironmentVariables`. Three things about that are easy to get wrong, and each
one looks like a missing variable:

- **A running service does not see a later `setenv`.** Its environment is a
  snapshot taken when the service was bootstrapped, and `launchctl kickstart -k`
  (what `deploy/service.sh restart` uses) reuses the loaded definition. A new
  variable needs `bootout` + `bootstrap` -- `deploy/service.sh update` -- before
  the process can see it. Check what the service actually has:

      launchctl print gui/$(id -u)/ai.shmobster.agent | sed -n '/environment/,/}/p'

- **`launchctl getenv` exits 0 whether or not the variable is set**, so
  `getenv X && echo present` always says present. Measure the output instead:
  `launchctl getenv X | wc -c` -- 0 bytes means unset.

- **A sync tool that greps `^export` out of one profile misses sourced files.**
  If `~/.bash_profile` does `. ~/.bash_profile_extra.sh`, a text scan never sees
  what that file defines, and those variables silently never sync. Compare
  `grep -c '^export' ~/.bash_profile` against `bash -lc 'compgen -e' | wc -l`; if
  they differ, deriving the list from the live login environment is the fix.
- `exec` -- shell-exec gate (Iter 1). `yolt_classifier`: path to
  [voitta-yolt](https://github.com/voitta-ai/voitta-yolt)'s
  `hooks/grammar_classifier.py` -- read-only commands auto-run, mutating ones
  park for a trusted user's approval (see **Approving mutating commands**).
  `cwd`: working dir for commands. `timeout_sec`: per
  command. (Clone voitta-yolt first; its `tree-sitter` + `tree-sitter-bash` deps
  are in requirements.txt.)
Per-channel policy lives in its own file, not in `shmobster-config.json`, so a
machine's channel layout is versioned separately from the token/key config:

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
    commands, e.g. a per-project `VERCEL_TOKEN` or `HEROKU_API_KEY`. Write them
    as `${VAR}` references like everything else (#104), not literals:

        "env": { "FIGMA_TOKEN": "${FIGMA_TOKEN}" }

    This is also how you give one channel an API token *without* handing it to
    every channel. A name that appears in any channel's `env` is treated as
    channel-scoped: it is stripped from the environment every command inherits,
    and added back only for the channel that declares it. So the `${VAR}` the
    process needs in order to expand the reference is not readable from another
    channel with a plain `printenv`. And a
    command that can read the credential it needs from its environment is a
    plain read-only command -- no `source`, so nothing trips the mutating gate
    and nothing needs approving.

Because `env` may hold secrets, treat `shmobster-policies.json` like the main
config: gitignored, `chmod 600`. For back-compat, inline `channel_policies` /
`default_policy` in the main config are still honored when no
`shmobster-policies.json` exists.

Run:

    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    .venv/bin/python selfcheck.py            # offline sanity check
    .venv/bin/python -m shmobster.slack_app  # start the agent (foreground)

## Free-tier fallbacks

The waterfall exists for rate limits, so the slots below the primary should be
things that keep answering when the primary will not. Free-tier models on the
routers below cost nothing and are **rate-limited independently of each other**,
which is the property that matters: one throttled route does not take the rest
down with it. Observed directly -- `google/gemma-4-31b-it` returns 429 on
OpenRouter's free tier while the same model answers through Requesty.

Two rules before adding any fallback:

**1. It must actually do tool calls.** The loop is a tool-calling loop
(`run_shell`, the Slack tools, approvals). A model that answers prose but ignores
tool schemas does not error -- it replies without ever calling a tool, and the
agent looks lobotomized rather than broken. *Declared* support is not enough;
send a real tool schema and assert a `tool_calls` came back:

    import litellm
    TOOLS = [{"type": "function", "function": {
        "name": "run_shell", "description": "Run a shell command.",
        "parameters": {"type": "object",
                       "properties": {"command": {"type": "string"}},
                       "required": ["command"]}}}]
    r = litellm.completion(model="...", api_key="...", timeout=45,
                           messages=[{"role": "user", "content":
                                      "Use run_shell to run: uname -a"}],
                           tools=TOOLS)
    assert r.choices[0].message.tool_calls   # prose here == unusable fallback

**2. Pass a `timeout`.** A free endpoint that hangs is worse than one that
fails: without a timeout the whole turn blocks, and the Slack ack just spins.
NVIDIA's direct NIM endpoint answers plain completions but timed out twice at 45s
on a tool-schema request, which is why it is not in the example config.

### Finding free, tool-capable models

**OpenRouter** -- free ids end in `:free`; the catalogue lists capabilities:

    curl -s https://openrouter.ai/api/v1/models | python3 -c '
    import json,sys
    for m in json.load(sys.stdin)["data"]:
        p = m.get("pricing", {})
        if p.get("prompt") in ("0","0.0") and "tools" in (m.get("supported_parameters") or []):
            print(m["id"], m.get("context_length"))'

Config: `"model": "openrouter/<id>"`, `"api_key": "${OPENROUTER_API_KEY}"`.

**Requesty** -- `input_price` / `output_price` of 0, and `supports_tool_calling`:

    curl -s https://router.requesty.ai/v1/models -H "Authorization: Bearer $REQUESTY_API_KEY"       | python3 -c '
    import json,sys
    for m in json.load(sys.stdin)["data"]:
        if float(m.get("input_price") or 0) == 0 and m.get("supports_tool_calling"):
            print(m["id"], m.get("context_window"))'

litellm has no `requesty/` provider prefix, but the endpoint is OpenAI-compatible:
`"model": "openai/<id>"` plus `"api_base": "https://router.requesty.ai/v1"`.

**NVIDIA NIM** -- `https://integrate.api.nvidia.com/v1/models` lists what a key
can reach, but note two traps: that endpoint answers `200` to *any* bearer token,
so it cannot tell you whether a key is valid; and model ids are retired without
notice (`meta/llama-3.1-405b-instruct` now 404s). The same NVIDIA models are
reachable through OpenRouter and Requesty, which is the easier path.

### Verified working

| Route | Model | Tool calls |
|---|---|---|
| Requesty | `nvidia/nemotron-3-super-120b-a12b`, `nvidia/nemotron-3.5-lightning-30b-a3b`, `nvidia/nemotron-3-ultra-550b-a55b`, `google/gemma-4-31b-it` | yes |
| OpenRouter | `z-ai/glm-5.2:free`, `nvidia/nemotron-3-super-120b-a12b:free` | yes |
| Gemini | `gemini-flash-latest` | yes |
| Codex subscription | `chatgpt/gpt-5.5` (see below) | yes |
| NVIDIA direct | `meta/llama-3.3-70b-instruct` | **times out** -- not usable |

Model ids retire. `gemini-2.0-flash` and `meta/llama-3.1-405b-instruct` both went
404 during this round of testing, so prefer an alias like `gemini-flash-latest`
where the provider offers one, and expect to re-run the probe above periodically.

### Codex subscription as a rung (#35)

Every other rung is an `api_key` HTTP row that LiteLLM can dial from config
alone. A **codex subscription** is not: it authenticates with the ChatGPT OAuth
tokens the codex CLI keeps in `~/.codex/auth.json`, and it speaks the Responses
API rather than chat/completions. `shmobster/codex_llm.py` is the bridge that
makes it look like any other rung -- an in-process `litellm.CustomLLM`, so there
is **no second process** to run under launchd.

Config is one keyless row:

    {"name": "codex", "model": "codex/chatgpt/gpt-5.5"}

Three things about that string:

- **No `api_key`.** The credential is the CLI's token file. `CODEX_HOME` is
  honoured if you set it.
- **The `chatgpt/` segment is required, not decoration.** LiteLLM dispatches on
  the model name *before* it dispatches on the custom provider, so a row of
  `codex/gpt-5.5` leaves it holding the bare `gpt-5.5`, recognising that as an
  OpenAI model, and quietly billing a platform API key -- the bridge is never
  reached. The segment is stripped back off before the request goes out.
- **The model must be one your ChatGPT plan allows.** `gpt-5.5` works;
  `gpt-5.1-codex` is refused with *"not supported when using Codex with a
  ChatGPT account"*.

It is a full participant, not a text-only last resort: **tool calls work**, so
it can sit anywhere in the chain.

**Token rotation is yours, not ours.** `auth.json` is re-read on every call, so
any rotation the codex CLI performs is picked up without a restart -- and the
access token is a ~10-day JWT that the CLI rotates whenever it runs. shmobster
deliberately does **not** refresh it: that would mean writing back to `auth.json`
and racing the CLI over a refresh token that may be single-use, and breaking the
operator's actual codex login is far worse than one dead rung. Instead:

- within 24h of expiry, every call logs `codex: the ChatGPT token expires in ~Nh`
  (at most hourly, so a busy channel does not turn it into spam);
- once expired, the rung returns 401, LiteLLM cools it, and the chain falls
  through.

Either way the fix is `codex login` -- or just using the codex CLI for anything,
which rotates the file as a side effect.

Why read the token rather than drive the binary (`codex exec`, or the
`codex app-server` protocol OpenClaw's codex extension speaks): both of those
keep the token out of our hands, but both hand us an *agent* -- codex brings its
own tool set, sandbox and approval policy, and shmobster already owns that loop
(handler + YOLT gate + channel policy). Nesting a second agent inside one
waterfall rung buys nothing here.

### When a vendor runs out of budget (#80)

LiteLLM decides cooldowns by HTTP status and cools only 429/401/408/404. Budget
exhaustion is none of those -- Anthropic answers a usage cap with **400**,
OpenRouter answers no-credit with **402** -- so out of the box a vendor that is
dead for a month is re-dialled on every single turn, failing before the waterfall
falls through. (Filed upstream as
[BerriAI/litellm#37592](https://github.com/BerriAI/litellm/issues/37592).)

shmobster parks it instead, hanging off litellm's **failure callback** rather
than an `except` around the call. This is the part that is easy to get wrong:
when a fallback covers the failure, the Router returns that answer and the
primary's exception never propagates, so an `except` only ever sees the case
where the *whole chain* is dead -- which is the one case parking cannot help.
The callback sees each deployment's failure regardless.

On a 4xx whose message names a spend problem, the vendor is dropped from the
chain and the Router is rebuilt without it, so it is never dialled again until
its window expires:

    waterfall: openrouter is out of budget; parked for 3600s
    waterfall: rebuilding, chain is now anthropic -> gemini -> requesty

- **The vendor is identified by its exact deployment string**, which litellm
  hands the callback as `litellm_params.metadata.deployment`. Not by
  `kwargs["model"]`: litellm strips the provider prefix there, so two vendors
  reached through different routers both report `openai/gpt-4o` and the wrong
  one gets parked. An ambiguous match parks nothing.
- **Status alone is not enough.** A 400 is also "your request was malformed", and
  parking a vendor for an hour over one bad prompt would be worse than the
  problem. The message has to name money too.
- **A stated recovery date wins.** Anthropic says `You will regain access on
  YYYY-MM-DD`; that date is used instead of the window. A date that fails to
  parse falls back to the window rather than being trusted -- a mis-parse could
  park a vendor for a year.
- **The window is `budget_park_sec`** (default 3600). `0` disables parking.
- **It survives restarts.** Expiries live in `shmobster-state.json`; the watchdog
  restarts this process routinely, and an in-memory park would be re-learned
  every few minutes.
- **A vendor comes back on its own**, with no timer: expired entries are pruned
  whenever the chain is read, so the first turn after the window rebuilds with
  that vendor back in place.
- **A fully parked chain still tries.** Refusing to answer is worse than one
  wasted call, and every park is ultimately a guess about someone else's billing.
- **The turn that discovers the exhaustion is still answered** -- park, rebuild,
  retry once -- rather than surfacing the error to whoever happened to ask.

Rate limits are the other half and LiteLLM does handle those: `allowed_fails=0`
now cools a deployment on the *first* 429 rather than after a threshold (#51).
A Slack agent's traffic is bursty and low-volume, so by the time a threshold is
reached the burst is over and every failure in it was a wasted round-trip.

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

## Credential redaction (#72)

Everything this agent says is scrubbed before it leaves the process. The bug
class is the one that bit [voitta-yolt](https://github.com/voitta-ai/voitta-yolt)
(#84, #91): anything returning command output verbatim hoards every credential
that rides through it. `run_shell` hands output straight to a channel, and `cat`,
`env` and `printenv` are read-only -- they clear the YOLT gate and run with no
approval.

Two layers:

- **Known shapes** -- detection is voitta-yolt's `secret_redact` (v1.0.0+),
  imported from the same tree as the classifier this instance already uses. One
  source of truth, not a second pattern list that drifts. Markers name the shape
  (`[REDACTED:github-token]`) so a redacted record stays diagnosable.
- **Known values** -- the one thing YOLT cannot know: this process's own secrets.
  Every Slack token, waterfall `api_key` and per-channel policy `env` value is
  matched exactly, so a credential in a format nobody anticipated is still caught
  when it is one of ours.

Scrubbing happens **at collection** -- the tool result, before it enters the
model's context -- so every downstream copy inherits it: the vendor's logs, the
thread, and anything the model later quotes. The final reply and the
approval-button messages are scrubbed again on the way out, since a parked
command carries its own argv.

Deliberately not included: a generic "40 characters of base64" rule. It matches a
git SHA, so it would redact half of any `git log`. A redactor that mangles
ordinary output gets switched off, and then it protects nothing.

**Fails loudly, never open.** With `secret_redact` unavailable the agent refuses
to start rather than posting unredacted output -- posting a secret is worse than
not booting. That makes voitta-yolt v1.0.0+ a hard requirement, not just for the
exec gate.

> Redaction is best-effort on shapes it knows plus values it holds. It is a
> backstop for accidents, not a licence to put secrets where the agent can read
> them. Config values stay `${VAR}` references (#73).

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
