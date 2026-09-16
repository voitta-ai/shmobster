# Bringing up shmobster on another machine

Written 2026-09-15 for a session that has none of the context from the day that
produced the current master. The README is the reference; this is the delta --
what is true right now, what will surprise you, and what not to do.

One instance per machine, each with its own Slack app and its own gitignored
config. Different machines need nothing special from each other (same-machine
pairs do, and that is #16, still open).

## State of the tree

- **Master is ahead of the last release.** `v0.7.2` is what is tagged; master
  carries eleven merged changes since, including four security fixes. The next
  release is **v0.8.0** and it is held -- see **The version hold** below.
- `docs/HANDOFF.md` is the standing plan: what is next, why in that order, what
  the release owes operators, and what `1.0.0` is waiting for.
- `selfcheck.py` is the whole test surface and runs offline. Run it before and
  after anything.

## The version hold, and the one thing you must not do

**voitta-yolt must be `>= 1.6.0` and `< 2.0.0`.** Both ends are load-bearing.

**Do not upgrade voitta-yolt to 2.x on this machine**, and do not let
`claude plugin update` do it for the copy shmobster points at. 2.0.0's Phase 3
cut `rules/shell.json` from 136 entries to 28 -- it now carries only what YOLT
refuses to delegate. For the Claude Code hook that costs nothing, because
`safe` and `unknown` are both a silent exit. Here they are opposite verdicts:
`safe` means run without asking, anything else parks. Under 2.x, `cat`, `ls`,
`grep`, `git status`, `git diff`, `gh pr list` and `curl` all return `unknown`,
so **every ordinary read in a channel would wait for a human**. Three commands
still classify safe: `pwd`, `echo`, and `python3 -c`.

The floor is 1.6.0 rather than 1.2.0 (where `--no-user-allow` landed) because
four write-target fixes closed in between. One mattered here: voitta-yolt#128
(1.3.0) read `$HOME/...` as a redirect target -- before it, `echo x >
$HOME/.ssh/authorized_keys` classified **safe**, which in this agent means
auto-run with no card.

Check both ends before you start:

    grep '"version"' /path/to/voitta-yolt/.claude-plugin/plugin.json     # expect 1.6.0
    python3 /path/to/voitta-yolt/hooks/grammar_classifier.py \
        --no-user-allow 'cat /dev/null'                                  # expect "safe"

The second is the real check: startup runs it too (`yolt_gate.preflight`), and
a classifier that cannot call `cat` read-only is one this agent cannot use,
whatever its version string says. Tracked as #177; when upstream ships a way to
point the CLI at a read-only rules file, adoption is one PR.

## Install

Follow **New instance setup** in the README. Nothing in it has changed. The
parts worth knowing before you get there:

- `gh` must be logged in **with a working keychain**, not a token in
  `~/.config/gh/hosts.yml`. Every channel's git runs over https using `gh auth
  git-credential`; a file-backed token is denied to every channel on purpose
  (the sandbox would otherwise let a read-only `cat` post it into Slack), and
  startup warns when it finds one.
- `gh auth status` reports a broken token when run **inside** a channel's
  sandbox on some hosts. Ignore it: test `git ls-remote` instead, which is the
  path that actually matters.
- Secrets in both config files are `${VAR}` references, never literals, and an
  unset one fails startup loudly. Under launchd that means `launchctl setenv`
  (or the plist's `EnvironmentVariables`) -- launchd does not read
  `~/.bash_profile`.

## Config keys this machine will need that older notes do not mention

In `shmobster-policies.json`, per channel:

- **`allow_domains`** -- hosts this channel's `curl`, `wget` and remote-contacting
  `git` subcommands may reach without an approval card, as globs. **A channel
  with no list cards every fetch.** That is the right default for a channel
  nobody has thought about and a surprise for one whose work pulls from GitHub,
  so set it deliberately:
  `"allow_domains": ["github.com", "api.github.com", "*.githubusercontent.com"]`.
- `env` -- credentials injected only for that channel, as `${VAR}` references.
- `env_passthrough` -- **names** of host variables the channel may inherit. A
  command's environment is built from a floor, not inherited, so anything not
  named here is absent. Check with `printenv | wc -l` in a channel: expect a
  two-digit number.
- `skills` -- must not resolve under the channel's writable tree, or it is
  ignored with a warning (a granted write could otherwise plant instructions).

In `shmobster-config.json`:

- **`logging.path`** -- set it. Without it, logging goes to stderr and launchd's
  redirect grows forever: the first deployment reached 185 MB at mode 0644. With
  it, the agent owns a 0600 file in a 0700 directory, rotated by size. If you
  adopt it on a machine that already has a log, `chmod 600` that file once --
  the plist's `Umask` only governs files launchd creates.
- `learning.trajectory_days` -- default 14, pruned at startup. The first restart
  after enabling it deletes older day files.

## First boot: what the log should say

    agent: <label> (<bot id>) -- shmobster 0.7.2+<sha>
    yolt: 0 inherited allow patterns; 'safe' means YOLT's own rules (#148)

If instead you see any of these, stop and fix before using it:

| line | meaning |
|---|---|
| `yolt called 'cat /dev/null' 'unknown' rather than safe` | yolt is 2.x (or predates 1.2.0). Every read will park. Use 1.6.0 |
| `yolt does not report allow_patterns` | yolt predates 1.2.0; the opt-out cannot be confirmed |
| `git preflight: gh is not logged in` | every channel's `git push` will fail |
| `gh keeps its token in ~/.config/gh/hosts.yml` | re-run `gh auth login` on a host with a working keychain |
| `skills: <channel> ignores its skills entry` | that path resolves under a writable root; point it at the catalog clone |

## Smoke test, in a channel, in this order

1. `@agent what can you do here?` -- it calls `describe_capabilities` and
   answers from the policy: cwd, repo and AWS scope, allow_domains, the **names**
   of injected credentials, the skill menu, what runs without a card. If it
   improvises prose instead, the tool is not reaching it.
2. `@agent show me the first line of the README` -- a read; should just run.
3. `@agent create a file called scratch.txt with "hello"` -- an in-tree write;
   the grant layer runs it with no card.
4. `@agent delete scratch.txt` -- mutating; parks with an id and a card.
   **Approve it** and watch the turn continue on its own (#169). If the card
   shows the output and nothing else happens, the ingest is not calling
   `handler.resume`.
5. `@agent fetch https://example.com` -- cards unless `example.com` is in that
   channel's `allow_domains`.

## Behavior that surprises people

- **Mutating commands park, including ones that used to run silently elsewhere:**
  `gh pr create`, `gh pr merge`, `git push`, `codex exec`. That is #148 -- the
  auto-run set is YOLT's own rules, no longer whatever the operator allowed
  themselves in a terminal.
- **An approval continues the task.** Approving runs the command *and* resumes
  the turn with its output; a denial resumes too, saying it did not run. When one
  turn parks several commands, the thread resumes once, on the click that leaves
  nothing parked.
- **A refusal looks different from a question.** If the classifier refuses
  outright it renders as `:no_entry: Refused by the classifier`, skips the grant
  layer, and still keeps both buttons -- a human remains the last word.
- **The deployment cannot edit itself.** `shmobster-config.json`,
  `shmobster-policies.json` (#147) and the `workspace/*.md` spine (#174) are
  refused by policy and denied in the kernel. Reads of the spine are fine;
  reads of the config are not.
- **`printenv` is short.** 20 variables, not 150 (#112).

## Do not

- Upgrade voitta-yolt past 1.6.0 (above).
- Write `~/.claude/yolt/shell.json` to change this agent's behavior -- it is the
  operator's own global config and changes their interactive hook too.
- Put a channel's `skills` directory inside that channel's writable tree.
- Paste a literal secret into either config file; both take `${VAR}`.

## Where to look next

`docs/HANDOFF.md` for what is next and why, `README.md` for how any of it works,
and the open issues -- #177 (the yolt hold), #23, #62, #140 (the queue), and
#150-#152, #155's siblings (the security re-audit's remainder).
