# Giving a channel the Vercel CLI

The README's `vercel` policy key says what the grant allows. This is the setup
that makes the CLI work inside a channel at all. Each step below closes a
failure that looks like something else, so the error each one prevents is
quoted.

The examples use a channel whose tree deploys to the Vercel project
`scrooge-banking` in the team `acme-enterprises`.

## 1. A team token, not a project token

Create the token in Vercel under Account Settings -> Tokens. **Scope** asks for
a team, then for a project: pick the team (`acme-enterprises`), then **All
Projects**.

Picking a single project instead gives a project-scoped token. The REST API
accepts it, so `curl` checks pass, but the CLI loads the token's user
(`GET /v2/user`) before every command, and for a project token that is a 404:

    Error: User not found (404)

`--scope`, `VERCEL_ORG_ID` and `VERCEL_PROJECT_ID` do not get past it. In the
token list, a project-scoped token shows the project's name and framework icon
under Scope; a team token shows the team.

An account-wide token also works, but reaches every team the account is in.
The grant still confines the channel to its projects, but the token is the
backstop if the grant is wrong, so keep it to the one team.

Put it in the environment under a per-channel name and reference it from the
channel's policy, like every other secret:

    "env": {"VERCEL_TOKEN": "${VERCEL_TOKEN_ACME}"}

Check it from a shell without printing it -- 200 means the CLI will accept it:

    curl -s -o /dev/null -w '%{http_code}\n' \
      -H "Authorization: Bearer $VERCEL_TOKEN_ACME" https://api.vercel.com/v2/user

## 2. `--scope` on every command, and the IDs in `env`

A team token does not make that team the CLI's default. The CLI uses the
account's default team, and a command that names a team or project fails:

    Error: Not authorized: Trying to access resource under scope "<another-team>".
    You must re-authenticate to this scope or use a token with access to this scope.

Nothing in the environment changes that default. `VERCEL_ORG_ID` and
`VERCEL_PROJECT_ID` stand in for a linked directory, so they only steer the
commands that act on the current directory's project -- `deploy`, and `ls`
with no project name. `project ls` and `ls <project>` ignore them. Writing
`currentTeam` into the CLI's global `config.json` (what `vercel switch` does)
does not work either: with a team token the CLI answers `forbidden` and drops
the setting. So every command carries `--scope <team>`. The agent is told this
in its system prompt whenever the channel has a `vercel` policy and a
`VERCEL_TOKEN` in `env`, so it does not have to discover it per turn.

Still set both IDs in the channel's `env`, copied from its `vercel` block (the
CLI ignores one without the other), so `deploy` and `ls` from any checkout
reach the right project:

    "env": {
      "VERCEL_TOKEN": "${VERCEL_TOKEN_ACME}",
      "VERCEL_ORG_ID": "team_...",
      "VERCEL_PROJECT_ID": "prj_..."
    }

Do not rely on `.vercel/project.json` (`vercel link`) for that instead.
`.vercel/` is gitignored, so a link made in the channel's tree is missing from
every `.worktrees/` checkout the agent creates. The grant reads both the env and
the link as evidence of where vercel will go, and parks if either names
something outside the `vercel` block.

## 3. Give the CLI a writable global directory

The CLI writes its global config on every run, under the XDG data directory
(`~/Library/Application Support/com.vercel.cli` on macOS). That is outside the
sandbox's writable roots, so the command fails with `EPERM` before it does
anything. Point `XDG_DATA_HOME` at a directory inside one of them -- the
channel's `.worktrees` sibling is the natural one:

    "env": {"XDG_DATA_HOME": "/path/to/tree.worktrees/.vercel-cli"}

and create that directory once. Do not open the real global directory to the
sandbox instead: it holds the operator's own `vercel login`, which a channel
must never use. Each channel gets its own directory, so one channel's CLI state
never reaches another.

## Verify

Restart, then in the channel ask the agent to run:

    vercel project ls --scope acme-enterprises --token "$VERCEL_TOKEN"
    vercel ls scrooge-banking --scope acme-enterprises --token "$VERCEL_TOKEN"

Both should run with no approval card and exit 0. A card means the grant
refused the command (see the README's `vercel` key) -- most often a missing
`--token "$VERCEL_TOKEN"`; a CLI error means one of the three steps above.
