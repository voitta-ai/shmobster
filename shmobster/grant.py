"""Grant layer (#117): run in-tree writes and self-authored commits without a card.

YOLT answers "does this mutate anything?" and every yes used to park for a
human -- including `cp x app/index.html && git add ... && git commit ...`
inside the channel's own worktree, the work the channel exists for. That
relief cannot come from YOLT: it is being narrowed to deny-only
(voitta-yolt#98) and its reasons are about Claude Code as host. shmobster is
an executor with its own approval flow and no classifier in front of it
(voitta-yolt#114, tier 2), so the grant lives here, next to the only party
that knows the channel's tree.

A YOLT-unsafe command is granted when EVERY segment is one of:

- YOLT-safe on its own (`cd`, `diff`, `git status`, `git log`, ...);
- a filesystem verb (cp, mv, mkdir, touch, tee, ln, chmod, sed) -- granted
  on the verb, not the operands, so the boundary is exactly the sandbox's
  write roots (#116): the tree, its worktrees sibling, the temp dir and the
  toolchain caches. A write to /tmp runs without a card; a write anywhere
  else fails in the kernel. Without the sandbox this module must not grant;
- a local git write: `git add`, `git mv`, `git stash`, `git checkout -b`,
  `git switch -c`, and `git commit` when the tracked directory is a linked
  worktree on a non-default branch whose commits are all the user's own
  (gitstate.py, #82's predicates);
- one of the above with an output redirect (`cat > f <<EOF` is how an agent
  writes a file), as long as the target is not a device other than
  /dev/null, /dev/stdout, /dev/stderr.

Everything else parks as before. This is an allowlist, so the tree-local
destructive verbs are excluded by construction: rm, git reset, git clean,
git checkout -- <path>, git restore, git push, git branch -D, gh, aws, sudo,
env, bash -c, python. Committed work is reflog-recoverable; uncommitted work
was the operator's call, and the operator made it (#117): card.

The command is walked as a bash AST (tree-sitter, already a dependency via
YOLT), not tokenized: quoting, heredocs and continuation lines come out
right, and a node kind this module does not model -- subshell, command
substitution, variable assignment, for/if/while, function -- is refused
rather than guessed at. A literal `cd` moves the tracked directory in
source order, starting from the channel cwd; a `cd` that cannot be resolved
statically (`cd "$DIR"`, `cd -`) makes every later `git commit` ungrantable
rather than judged against the wrong tree. `git -C <path>` retargets one
segment the same way."""
import os

import tree_sitter
import tree_sitter_bash

import re

from . import gitstate, policy as policy_mod, yolt_gate

_LANG = tree_sitter.Language(tree_sitter_bash.language())

# Does the command itself name a URL? When it does, the ordinary egress check
# reads it; when it does not, an unattended git subcommand that contacts a
# remote resolves that remote's configured URL instead (#253).
_URL_IN_TEXT = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://")
_GIT_NET_SUBS_LOCAL = frozenset(("clone", "fetch", "pull", "push", "ls-remote", "submodule"))

# Filesystem writes the sandbox confines to the tree.
FS_VERBS = frozenset(("cp", "mv", "mkdir", "touch", "tee", "ln", "chmod", "sed"))

# Verbs an unattended channel runs without a card (#253), because their blast
# radius is the scope the operator already drew: `git` and `gh` are held to the
# channel's `github_repos` by `_check_github`, and the file verbs to its tree by
# the sandbox. `rm` is here and `cp` is in FS_VERBS for the same reason -- in an
# unattended channel the distinction between them stopped being interesting.
#
# What is NOT here matters more. Interpreters (`sh`, `bash`, `python3`, `node`,
# `perl`, `ruby`) stay carded although they cannot escape the tree, because the
# sandbox confines the filesystem and not the network: `python3 -c` with a
# socket is an uncarded fetch to anywhere, which would make `allow_domains`
# decorative. `curl` and `wget` keep their own rule for the same reason, and
# `sudo` is refused before this point.
UNATTENDED_VERBS = frozenset((
    "rm", "rmdir", "cp", "mv", "mkdir", "touch", "tee", "ln",
    "chmod", "chown", "sed", "truncate", "install", "patch",
))

# `git` and `gh` are NOT in the set above, and the reason is the whole safety
# of this mode. Granting them on the verb would skip the parsing that refuses
# `git -c alias.x='!curl https://anywhere'`, which git runs through a shell --
# an uncarded command with no repo and no host in it for either allowlist to
# see (Codex adversarial review, #253). So unattended changes the VERDICT those
# two handlers reach, never the parsing they do, and it reaches it only for a
# subcommand git or gh actually defines: an unknown word is an alias, and an
# alias is somebody else's command.
_UNATTENDED_GIT_SUBS = frozenset((
    "add", "am", "apply", "archive", "bisect", "branch", "cat-file",
    "cherry-pick", "clean", "commit", "describe", "diff", "fetch",
    "for-each-ref", "format-patch", "gc", "init", "log", "ls-files",
    "ls-remote", "ls-tree", "merge", "mv", "notes", "prune", "pull", "push",
    "rebase", "reflog", "remote", "reset", "restore", "revert", "rev-parse",
    "rm", "shortlog", "show", "stash", "status", "switch", "tag", "worktree",
    "blame", "checkout", "clone", "submodule",
))
# `config` is absent on purpose: `git config alias.x '!cmd'` writes the alias
# the paragraph above is about, and `core.fsmonitor` runs a command on the next
# ordinary read.

# gh's nouns, minus the ones that run code this layer cannot see: `extension`
# (runs a third-party binary), `alias` (same shape as git's), `codespace` (ssh
# into a remote machine), and `auth` (changes or prints the credential; `auth
# status` is already granted on its own terms).
_UNATTENDED_GH_NOUNS = frozenset((
    "pr", "issue", "repo", "run", "workflow", "release", "label", "api",
    "browse", "cache", "gist", "project", "org", "ruleset", "search",
    "secret", "variable", "status",
))

# Reads that stay reads whatever flags they are given (#177). voitta-yolt 2.0.x
# delegates every ordinary read to a host classifier this agent does not have,
# answering `unknown`, so without this list `cat README.md` parks for an approval
# card. The list is consulted only on the verb; `unsafe` and `deny` never reach
# here, so it can promote and never override.
#
# It is deliberately NOT parity with voitta-yolt 1.6.0, whose `safe` set this
# replaces. Measured against 1.6.0: `git branch -D x`, `git remote add`,
# `git config user.email x@y` and `gh api repos/o/r` were all `safe` there, and
# all four mutate. Reproducing that set would re-import the holes #148 closed.
#
# The bar for entry is that no flag turns the command into a write. That is why
# `sort` (-o), `uniq` (output positional), `date` (-s), `hostname` (sets it),
# `find` (-delete, -exec) and `xargs` (runs its argument) are absent, and why
# `awk` is absent despite reading: its program can call system(), and `tree` is
# absent because -o writes its output to a file. `sed` is in FS_VERBS already,
# as the writer -i makes it.
READ_VERBS = frozenset((
    "cat", "ls", "head", "tail", "wc", "file", "stat", "basename", "dirname",
    "realpath", "du", "df", "which", "diff", "grep", "egrep", "fgrep", "rg",
    "jq", "id", "uname", "printenv", "ps",
))

# Reads that stay reads unless a named flag turns them into something else
# (#219). READ_VERBS above is consulted on the verb alone, so its bar is that no
# flag can make the command write -- which is why `find` and `sort` are absent
# from it, and why a directory listing needed a human approval card.
#
# The bar can move for these because this layer is not verb-only any more: it
# parses argv and already refuses on flags for `git -c`, `gh api` and the `aws`
# value-flags. A flag-checked tier is the mechanism that is already here.
#
# On the shape of the risk, stated rather than glossed. This is a deny list, so
# a writing flag nobody enumerated would pass. That is survivable for the ones
# that write a FILE, because the sandbox confines the write to the channel's
# tree, which is the same risk already accepted for every verb in FS_VERBS --
# `tee out.txt` is granted today. It would NOT be survivable for a flag that
# RUNS something, because execution escapes the read/write framing entirely, so
# those are the entries to be sure of: find's four are the complete set in both
# BSD and GNU find.
_FIND_WRITES = frozenset((
    # run a command this layer cannot see
    "-exec", "-execdir", "-ok", "-okdir",
    # remove what it matched
    "-delete",
    # write the match list to a named file. GNU only -- BSD find answers
    # "-fprint: unknown primary or operator" -- and listed anyway, because
    # which find is on the box is not a security property. voitta-yolt's own
    # find rule omits these deliberately (its safe_write_targets would treat
    # the path as ordinary), so its `find: rules punt` cannot be promoted in
    # their place; see #219.
    "-fprint", "-fprint0", "-fprintf", "-fls",
))

FLAG_CHECKED_READS = frozenset(("find", "sort"))


def _find_refusal(texts):
    hit = next((t for t in texts if t in _FIND_WRITES), None)
    retval = f"find: flag {hit}" if hit else None
    return retval


def _sort_refusal(texts):
    """`sort` writes only through -o/--output, and every spelling of it.

    The attached and bundled forms are the point: `sort -o out f`, `sort -oout`
    and `sort -uo out` all redirect the result into a file, and only the first
    is caught by comparing against "-o". So any single-dash cluster containing
    an `o` is refused -- `-u`, `-n`, `-r` and the rest survive, and a cluster
    that merely looks unfamiliar is refused rather than guessed at."""
    retval = None
    for t in texts:
        if t == "--output" or t.startswith("--output="):
            retval = f"sort: flag {t.split('=')[0]}"
            break
        if t.startswith("-") and not t.startswith("--") and "o" in t[1:]:
            retval = f"sort: flag {t} redirects the result into a file"
            break
    return retval


_FLAG_REFUSAL = {"find": _find_refusal, "sort": _sort_refusal}

# Fetch verbs this layer can vouch for when the host is already allow-listed
# (#239). Only `curl`, which writes to stdout unless told otherwise; see
# `Walker.fetch` for why `wget` is not here.
EGRESS_READS = frozenset(("curl",))

# curl's ways of putting the response in a file instead of on stdout. `-J`
# takes the name from a header the server controls, which is why it is refused
# alongside the two that name the file locally.
_FETCH_WRITE_LONG = frozenset((
    "--output", "--remote-name", "--remote-name-all", "--remote-header-name",
    "--output-dir", "--create-dirs",
))
_FETCH_WRITE_LETTERS = frozenset("oOJ")


def _quoted_non_flag(raw):
    """True when this argument cannot be an option, although it expands.

    Two properties together, and neither alone is enough. The quotes mean the
    expansion produces ONE argument rather than splitting on whitespace, so
    `"$OPTS"` with OPTS=`-d@/etc/passwd` is a single word rather than a flag
    and its value -- and that single word IS an option, which is why the
    second property matters: the first character must be a literal that cannot
    begin one. `"X-Api-Key: $TOKEN"` starts with `X`; `"$OPTS"` starts with the
    expansion and is refused; `"-H"` starts with a dash and is refused."""
    if len(raw) < 3 or raw[0] not in "\"'" or raw[-1] != raw[0]:
        return False
    first = raw[1]
    retval = first.isalnum() or first in "/._:@%+"
    return retval


def _fetch_write_flag(texts):
    """The flag making this fetch write a file, or None.

    Clusters count: `-sO url` saves to a file as surely as `-O url`, and this
    is the same reasoning `_sort_refusal` spells out -- a single-dash cluster
    is a set of option letters, not a word.

    The three devices are not files, the same exception the redirect rule makes
    (`_DEV_OK`): `curl -o /dev/null -w '%{http_code}'` asks for a status code
    and keeps the body, which is the cheapest read there is and was costing a
    card. The destination is only trusted when it is the next word, attached
    (`-o/dev/null`) or after `=`; a cluster like `-sO` names no destination at
    all, so it stays refused."""
    retval = None
    for i, t in enumerate(texts):
        head = t.split("=", 1)[0]
        if head in _FETCH_WRITE_LONG or (t.startswith("-") and not t.startswith("--")
                                         and set(t[1:]) & _FETCH_WRITE_LETTERS):
            if _writes_device_only(t, texts[i + 1:], head):
                continue
            retval = head if head in _FETCH_WRITE_LONG else t
            break
    return retval


def _writes_device_only(token, after, head):
    """True when this output flag's destination is /dev/null or a standard
    stream, so nothing is written to a file after all.

    Only `-o` / `--output` name a destination this can read. `-O` takes the
    name from the URL and `-J` from a response header, so a token carrying
    either is never exempt however it is spelled.

    The short form is read the way curl reads it: in a cluster, `o` consumes
    the rest of the token if there is any (`-so/dev/null`, `-o/dev/null`) and
    otherwise the next word (`-so /dev/null`)."""
    if head == "--output" or token.startswith("--output="):
        dest = token.split("=", 1)[1] if "=" in token else (after[0] if after else None)
    elif token.startswith("-") and not token.startswith("--"):
        cluster = token[1:]
        if set(cluster) & set("OJ") or "o" not in cluster:
            return False
        tail = cluster.split("o", 1)[1]
        dest = tail if tail else (after[0] if after else None)
    else:
        return False
    retval = dest in _DEV_OK
    return retval


def _git_branch_refusal(rest):
    """Why this `git branch` is not a listing, or None when it is (#236).

    `rest` is the words after the subcommand, with None for any that is not a
    literal -- a branch name this layer cannot read is a branch name it cannot
    vouch for."""
    retval = None
    for t in rest:
        if t is None:
            retval = "git branch: an argument is not literal"
            break
        if not t.startswith("-"):
            # Every non-flag word is read as a branch name, including one that
            # is really the value of a preceding flag: `git branch --sort
            # committerdate` parks and `--sort=committerdate` does not. That
            # costs one spelling and closes the hole underneath it -- git's
            # optional-value flags (`--color`, `--column`, `--abbrev`, each
            # documented `[=<value>]`) do NOT consume the next word, so a
            # parser that skipped it would read `git branch --color newtopic`
            # as a listing when git reads it as a branch creation (Codex
            # adversarial review, #242).
            retval = f"git branch: {t!r} is a branch name, not a flag"
            break
        head = t.split("=", 1)[0]
        if head not in _GIT_BRANCH_READ_FLAGS:
            retval = f"git branch: flag {head}"
            break
    return retval


# git subcommands that cannot mutate the repository whatever follows them.
# `remote`, `config`, `tag`, `checkout` and `switch` are absent because a flag
# flips each into a write (add, a value, -d, --). `grep` is absent because
# `git grep -O<cmd>` opens matches in a pager of its choosing, which runs that
# command even when stdout is a pipe -- measured, not assumed. `branch` is
# handled below instead, by flags: it belongs here in spirit and not in this
# set, because `git branch -D x` deletes.
GIT_READ = frozenset((
    "status", "log", "show", "diff", "rev-parse", "ls-files", "blame",
    "describe", "shortlog", "cat-file", "ls-tree", "for-each-ref",
))

# `git branch`'s listing form, as an allowlist rather than a list of the ways
# it writes (#236). The deny-list shape used for `find` and `sort` is wrong
# here: those write a file the sandbox still confines, while the ways `branch`
# writes -- delete, rename, copy, retarget an upstream -- destroy repository
# state the sandbox has no opinion about, so an unlisted flag must park rather
# than pass. A positional argument is a write too: `git branch <name>` creates,
# and `git branch --list <pattern>` cannot be told apart from it here, so the
# pattern form parks and the plain listing does not.
_GIT_BRANCH_READ_FLAGS = frozenset((
    "-a", "--all", "-r", "--remotes", "-v", "-vv", "--verbose", "-l", "--list",
    "-q", "--quiet", "-i", "--ignore-case", "--show-current", "--color",
    "--no-color", "--column", "--no-column", "--sort", "--format",
    "--contains", "--no-contains", "--merged", "--no-merged", "--points-at",
    "--abbrev", "--no-abbrev",
))

# `gh auth status` reports which account is logged in; every other `gh auth`
# subcommand changes the credential, and `--show-token` prints it (#236).
#
# The flag is matched on its name, not on the whole token: gh's flags are
# cobra booleans, so `--show-token=true` is the same request as `--show-token`
# and an exact-token check let it through (Codex adversarial review, #242).
# Any single-dash cluster containing `t` goes with it -- `gh auth status` has
# no other short flag worth the distinction.
_GH_AUTH_READ = "status"
_GH_AUTH_REFUSED_LONG = frozenset(("--show-token",))
_GH_AUTH_REFUSED_LETTERS = frozenset("t")


def _gh_auth_refusal(texts):
    """Why this `gh auth status` is not a read, or None."""
    retval = None
    for t in texts:
        if t is None:
            retval = "gh auth status: an argument is not literal"
            break
        if t.split("=", 1)[0] in _GH_AUTH_REFUSED_LONG:
            retval = "gh auth status --show-token: prints the credential"
            break
        if t.startswith("-") and not t.startswith("--") and set(t[1:]) & _GH_AUTH_REFUSED_LETTERS:
            retval = "gh auth status -t: prints the credential"
            break
    return retval

# `gh <noun> <action>` pairs that only read. `api` is deliberately absent: it
# takes -X POST, and it reaches any repo the token reaches, which is the open
# scope question in #150.
GH_READ_NOUNS = frozenset(("pr", "issue", "repo", "run", "workflow", "release", "label"))
GH_READ_ACTIONS = frozenset(("list", "view", "status", "diff", "checks"))

# `aws <service> <operation>` where the operation only reads. Everything else,
# `cp`/`mv`/`rm`/`sync` included, falls through and parks.
AWS_READ_PREFIXES = ("list-", "get-", "describe-")

# ...except these, which are read-prefixed and still write a local file. The
# AWS CLI spells that destination as a bare trailing positional -- its own help
# for s3api get-object: "outfile (string) Filename where the content will be
# saved. Note that the outfile parameter is specified without an option name
# such as --outfile." Having no option name is exactly what makes it
# unfilterable by flag, so the operations are named instead.
#
# This is a deny set, not a proof: the sandbox is what bounds an operation not
# listed here, confining the write to the channel's tree the same as any
# FS_VERBS write. What the list buys is that the grant layer stops calling such
# a command "read-only" while it writes.
AWS_WRITES_OUTFILE = frozenset(("get-object", "get-object-torrent", "get-media"))

# ...and these, which read nothing on this machine and hand back credentials.
# They do not mutate, so calling them "not a read" needs the #149 argument
# rather than the mutation one: a fetch is read-only here while being an effect
# out there, and these are read-only here while putting secret material into a
# channel. The redactor is not a second line for this -- `tools.py` says it
# where it matters: "a bare token has no shape the redactor can catch" -- so a
# secret this layer auto-runs is a secret in the transcript, which no later
# denial undoes.
#
# Stricter than voitta-yolt 1.6.0 on purpose. Measured there: get-secret-value,
# get-login-password, get-session-token and get-parameter --with-decryption all
# classified `safe`, which on this side meant auto-run with no card. Inheriting
# that was defensible while the classifier owned the read-only list. Asserting
# it here is not.
AWS_RETURNS_SECRET = frozenset((
    "get-login-password", "get-authorization-token", "get-secret-value",
    "get-parameter", "get-parameters", "get-parameters-by-path",
    "get-session-token", "get-federation-token", "get-role-credentials",
))

# Global flags that take a separate value. Without these the value is read as
# the subcommand -- `gh --repo o/r pr list` looks like `gh o/r r...`, which then
# matches nothing and parks. That is the safe direction but it parks a real
# read, so the common ones are named. An unknown flag still misparses and still
# parks, which is why this list only ever adds working commands.
GH_VALUE_FLAGS = frozenset(("-R", "--repo", "--hostname"))
AWS_VALUE_FLAGS = frozenset((
    "--profile", "--region", "--endpoint-url", "--output", "--query",
    "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout", "--color",
))

# Local git writes that need no repository state.
GIT_LOCAL = frozenset(("add", "mv", "stash"))

# Structural nodes to descend through; their operator tokens are skipped.
_CONTAINERS = frozenset(("program", "list", "pipeline"))
_SKIP = frozenset(("&&", "||", ";", "|", "&", "\n", ";;", "comment"))

_DEV_OK = frozenset(("/dev/null", "/dev/stdout", "/dev/stderr"))

# `<` is the only redirect operator that does not write. Anything else, and
# anything unrecognized, counts as a write -- the fail-closed direction.
_READ_REDIRECT = frozenset(("<",))

# ...with one exception, and it is an exception about descriptors rather than
# about files (#213). `2>&1` opens nothing: it points one descriptor at
# another, and `2>&-` closes one. Neither names a path, so neither can write.
# Counting them as writes made `jq . big.json 2>&1 | head` park for an approval
# card -- a local read of a local file, refused for a reason unrelated to what
# it does.
_DUP_OPS = frozenset((">&", "<&"))
_CLOSE_OPS = frozenset((">&-", "<&-"))


def _fd_dup(node):
    """True when a file_redirect only moves or closes a descriptor.

    The distinction is bash's and it is genuinely ambiguous in the text:
    `>&word` duplicates a descriptor when `word` is a number, and redirects
    both streams into a *file* named `word` when it is not. So `>&2` writes
    nothing and `>&out.txt` writes a file, spelled with the same operator.

    We do not re-implement that rule -- tree-sitter has already applied it, and
    types the two destinations `number` and `word`. Reading the node type is
    therefore asking the parser what bash decided, rather than asking a regex
    what the string looks like. Anything that is neither (`$X`, unparsed, a
    destination we do not recognize) falls through to the write path, which is
    the fail-closed direction and where `&>file` stays too."""
    types = [c.type for c in node.children]
    if any(t in _CLOSE_OPS for t in types):
        retval = True
    else:
        retval = (any(t in _DUP_OPS for t in types)
                  and bool(node.children)
                  and node.children[-1].type == "number")
    return retval


def _reads_only(node):
    retval = any(c.type in _READ_REDIRECT for c in node.children)
    return retval


def _text(node, src):
    retval = src[node.start_byte:node.end_byte].decode("utf-8", "replace")
    return retval


def _static(node):
    """True when the node contains no expansion or substitution."""
    if node.type in ("simple_expansion", "expansion", "command_substitution", "process_substitution"):
        return False
    retval = all(_static(c) for c in node.children)
    return retval


def _no_substitution(node):
    """True when nothing under the node runs a command. `$VAR` is fine --
    it expands, it does not execute."""
    if node.type in ("command_substitution", "process_substitution"):
        return False
    retval = all(_no_substitution(c) for c in node.children)
    return retval


def _unquote(text):
    retval = text
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        retval = text[1:-1]
    return retval


def _resolve(target, tracked):
    """A literal path against the tracked directory, or None."""
    retval = None
    if tracked is not None and target not in ("-",):
        t = os.path.expanduser(target)
        retval = t if os.path.isabs(t) else os.path.join(tracked, t)
    return retval


class _Walker:
    def __init__(self, src, start_dir, policy=None):
        self.src = src
        self.tracked = start_dir
        self.start_dir = start_dir
        self.policy = policy or {}
        # File-only channel opt-in (#253), read once per walk. Not settable
        # through `set_policy`, so a channel cannot talk itself into it.
        self.unattended = bool(self.policy.get("unattended"))
        self.probe = gitstate.GitProbe()
        self.reasons = []
        # Raised while walking the body of a redirect that writes to a real
        # file, so a read verb under it is not granted as a read (#177).
        self.writes_file = False

    def walk(self, node):
        """(ok, reason) for the subtree. First refusal wins."""
        retval = (True, "")
        if node.type in _CONTAINERS:
            for c in node.children:
                if c.type in _SKIP:
                    continue
                retval = self.walk(c)
                if not retval[0]:
                    break
        elif node.type == "command":
            retval = self.segment(node)
        elif node.type == "redirected_statement":
            retval = self.redirected(node)
        elif node.type in _SKIP:
            retval = (True, "")
        else:
            retval = (False, f"{node.type} is not grantable")
        return retval

    def redirect_write(self, c):
        """One file_redirect judged: (refusal, writes_a_file).

        `refusal` is a reason string when the redirect cannot be judged at all,
        and None otherwise -- in which case the second value says whether it
        puts bytes in a file.

        Shared by both callers on purpose. A redirect can sit on either side of
        its command, and bash writes the file either way, so the two parse
        shapes have to reach the same verdict or the rule is decoration (#213).
        """
        # No path, nothing to judge: not a device, not in the tree, not a
        # write. Checked before the destination is read at all, because for
        # `2>&1` the "destination" is the number 1.
        if _fd_dup(c):
            return (None, False)
        dest = c.children[-1] if c.children else None
        if dest is None or not _static(dest):
            return ("redirect target is not a literal", None)
        target = _unquote(_text(dest, self.src))
        if target.startswith("/dev/") and target not in _DEV_OK:
            return (f"redirect to device {target}", None)
        # A read verb stops being a read when its output lands in a file
        # (#177). YOLT cannot tell us this -- `cat x`, `cat x > out.txt` and
        # `cat x > /usr/local/bin/foo` are one `unknown` to it, differing only
        # in a reason string nobody parses -- so the redirect is seen here or
        # not at all.
        retval = (None, not _reads_only(c) and target not in _DEV_OK)
        return retval

    def redirected(self, node):
        """A command, pipeline or list with redirects. The body is judged as
        usual; the redirect is an in-tree write the sandbox confines, unless
        it names a device other than the three harmless ones."""
        body = None
        writes = False
        for c in node.children:
            if c.type in ("command", "pipeline", "list"):
                body = c
            elif c.type == "file_redirect":
                refusal, redirect_writes = self.redirect_write(c)
                if refusal is not None:
                    return (False, refusal)
                writes = writes or redirect_writes
            elif c.type in ("heredoc_redirect", "herestring_redirect"):
                continue
            else:
                return (False, f"{c.type} under a redirect is not grantable")
        if body is None:
            return (False, "redirect without a command")
        before = len(self.reasons)
        saved = self.writes_file
        self.writes_file = self.writes_file or writes
        retval = self.walk(body)
        self.writes_file = saved
        if retval[0] and len(self.reasons) > before:
            self.reasons[-1] += " > redirect"
        return retval

    def argv(self, node):
        """(verb, args) with verb the basename of a literal command name, or
        (None, []) when the command name is not literal or has a prefix."""
        verb = None
        args = []
        for c in node.children:
            if c.type == "command_name":
                if not _static(c):
                    return (None, [])
                verb = os.path.basename(_unquote(_text(c, self.src)))
            elif c.type == "variable_assignment":
                return (None, [])
            elif c.type == "heredoc_body":
                continue
            elif c.type in ("file_redirect", "heredoc_redirect", "herestring_redirect"):
                continue
            else:
                args.append(c)
        retval = (verb, args)
        return retval

    def segment(self, node):
        """A redirect may sit before its command as well as after it.

        `>out.txt cat f` is `cat f > out.txt` with the words in the other
        order, and bash writes the file for both. Only the trailing form parses
        as a `redirected_statement`; the leading one is a `file_redirect` child
        of the command node, which `redirected()` never sees and `argv()`
        skips outright -- so `cat f > out.txt` parked while `>out.txt cat f`
        was granted as "cat: read-only", and the difference was word order
        (#213). Found reviewing the descriptor-dup change above; it predates
        it."""
        saved = self.writes_file
        try:
            retval = self._segment(node)
        finally:
            self.writes_file = saved
        return retval

    def _segment(self, node):
        text = _text(node, self.src)
        # Kept for the handlers that have to ask about reach: an unattended
        # `git push` is granted on its subcommand and still has to name a host
        # this channel was given (#253).
        self._seg_text = text
        for c in node.children:
            if c.type == "file_redirect":
                refusal, writes = self.redirect_write(c)
                if refusal is not None:
                    return (False, refusal)
                self.writes_file = self.writes_file or writes
        verb, args = self.argv(node)
        if verb is None:
            return (False, "command with a prefix or a non-literal name")
        # Nothing granted here may carry an argument that runs something:
        # `cp $(rm -rf x) b`, `cd $(curl ... | sh)`. The allowlisted verbs
        # and `cd` are judged on the verb alone, and YOLT only sees the
        # segments that fall through to it, so the check is unconditional.
        if not all(_no_substitution(a) for a in args):
            return (False, f"{verb}: command substitution in arguments")
        if verb == "cd":
            retval = self.cd(args)
        elif self.unattended and verb in UNATTENDED_VERBS:
            # The channel's scope is its boundary (#253). Inside its own repos
            # and its own tree, a card was protecting nobody from anything the
            # operator had not already allowed: the point of the channel is to
            # be an aide there. So `rm -rf build`, `git push --force` and
            # `gh pr merge` run -- `git` and `gh` still answer to
            # `_check_github` for WHICH repo, the file verbs to the sandbox for
            # which tree.
            #
            # Egress is still asked, because reach is the one thing the scope
            # does not describe: `git push` to a remote outside `allow_domains`
            # leaves the blast radius the operator drew, and leaving it is what
            # a card is still for.
            allowed, why = policy_mod.check_egress(text, self.policy)
            retval = (True, f"{verb}: unattended channel") if allowed else (False, why)
        elif verb in FS_VERBS:
            retval = (True, f"{verb}: in-tree write")
        elif verb == "git":
            retval = self.git(args)
        elif verb == "gh":
            retval = self.gh(args)
        elif verb == "aws":
            retval = self.aws(args)
        elif verb in EGRESS_READS and not self.writes_file:
            retval = self.fetch(verb, text, args)
        elif verb in READ_VERBS and not self.writes_file:
            retval = (True, f"{verb}: read-only")
        elif verb in FLAG_CHECKED_READS and not self.writes_file:
            retval = self.flag_checked(verb, args)
        else:
            retval = None
        # Why the read rule did not apply, kept for the refusal below (#213).
        # A read verb whose output lands in a file still goes to the classifier
        # -- it may know the command -- but when that also refuses, the card
        # used to read `no rule: jq`. Those are the classifier's words about
        # its own ruleset, and `jq` is in READ_VERBS right here; the human who
        # went to check the verb list found the verb already in it and learned
        # nothing about the redirect that actually caused the card.
        shadowed = (f"{verb} reads, but this segment redirects output to a file"
                    if retval is None and (verb in READ_VERBS or verb in FLAG_CHECKED_READS)
                    else None)
        if retval is None or (retval[0] is False and verb == "git"):
            # The directory this segment would run in, never the agent
            # process's (#182): 2.0.x's deny predicates read it, and a
            # `cd` to a target we could not resolve falls back to the
            # channel's root rather than to wherever this process sits.
            decision, reason = yolt_gate.classify(
                text, cwd=self.tracked or self.start_dir,
            )
            if decision == "safe":
                # "Read-only" is about this machine, and a fetch is read-only
                # here while being an effect out there (#149). Without this the
                # layer that exists to vouch for local writes would vouch for
                # `touch f && curl https://elsewhere/...`, one segment at a
                # time, and hand back the grant the egress check just refused.
                allowed, why = policy_mod.check_egress(text, self.policy)
                retval = (True, f"{verb}: read-only") if allowed else (False, why)
            elif retval is None:
                retval = (False, shadowed or reason)
        if retval[0]:
            self.reasons.append(retval[1])
        return retval

    def flag_checked(self, verb, args):
        """A read verb granted unless one of its own writing flags is present.

        Every argument must be a literal. `find . $F` with F=-delete is a
        deletion the deny list cannot see, and `_no_substitution` upstream does
        not catch it -- that rejects things that RUN a command, and `$F` merely
        expands. So an argument this layer cannot read is a refusal, not a
        guess: the verb goes back to punting, which is where it was before
        (#219)."""
        if not all(_static(a) for a in args):
            retval = (False, f"{verb}: an argument is not a literal, so its flags cannot be read")
            return retval
        texts = [_unquote(_text(a, self.src)) for a in args]
        why = _FLAG_REFUSAL[verb](texts)
        retval = (False, why) if why else (True, f"{verb}: read-only")
        return retval

    def fetch(self, verb, text, args):
        """A `curl` to a host the channel has already allow-listed (#239).

        The credential half of a channel and the network half never met: a
        policy could hold `api.example.com` in `allow_domains` and the token to
        use it in `env`, and every `curl` still parked, because this layer had
        no rule for fetch verbs and voitta-yolt 2.0.x delegates them here. The
        tool that does honour `allow_domains` -- `web_fetch` -- sends no
        headers, so the authenticated read had no uncarded path at all.

        Nothing about what may be reached moves: `check_egress` is the same
        function, with the same answers, and it already refuses a host that is
        not statically visible, a host outside the list, and the upload-shaped
        flags #222 added. What moves is that meeting those conditions is now a
        grant rather than a fall-through to a classifier that will punt.

        `wget` is deliberately not here. It writes the response to a file by
        default, so the no-output-flag rule below would have to be inverted for
        it, and an inverted default is how this kind of guard gets a hole."""
        texts = []
        for a in args:
            raw = _text(a, self.src)
            if _static(a):
                texts.append(_unquote(raw))
            elif _quoted_non_flag(raw):
                # The case this grant exists for: `-H "X-Api-Key: $TOKEN"`,
                # where the credential comes from the channel's `env` and never
                # appears in argv. Inside quotes an expansion cannot split into
                # further arguments, and a literal first character that is not
                # a dash cannot become an option -- so this word is a value,
                # whatever it expands to, and there is no flag here to read.
                continue
            else:
                retval = (False, f"{verb}: an argument is not a literal, so its flags cannot be read")
                return retval
        # Reach first, shape second. Both refuse, but `curl -sXPOST` carries an
        # option letter inside its attached value ("POST" holds an O), and the
        # cluster scan below cannot tell that from `-sO`. Asking check_egress
        # first means such a command is refused for carrying a request body,
        # which is what it does, rather than for a file it does not write.
        allowed, why = policy_mod.check_egress(text, self.policy)
        if not allowed:
            retval = (False, why)
            return retval
        hit = _fetch_write_flag(texts)
        if hit:
            # A fetch that also writes a file is two powers in one command, and
            # the file is the response body -- content from off the box landing
            # in the channel's tree under a name the command chose. That can
            # have its own card; reading to stdout is what this grants.
            retval = (False, f"{verb}: {hit} writes the response to a file")
            return retval
        retval = (True, f"{verb}: fetch to a host in allow_domains")
        return retval

    def cd(self, args):
        if not args:
            self.tracked = os.path.expanduser("~")
        elif len(args) == 1 and _static(args[0]):
            self.tracked = _resolve(_unquote(_text(args[0], self.src)), self.tracked)
        else:
            self.tracked = None
        retval = (True, "cd")
        return retval

    def git(self, args):
        directory = self.tracked
        sub = None
        rest = []
        config_override = False
        i = 0
        # Global options come before the subcommand: `-C <dir>` retargets,
        # `-c key=val` takes a value, anything else dashed is skipped. After
        # the subcommand every word is its own (`switch -c` is a branch, not
        # a config).
        while i < len(args):
            a = args[i]
            t = _text(a, self.src) if _static(a) else None
            if sub is not None:
                rest.append(t)
                i += 1
                continue
            if t is None:
                return (False, "git subcommand is not literal")
            if t == "-C" and i + 1 < len(args):
                directory = (
                    _resolve(_unquote(_text(args[i + 1], self.src)), directory)
                    if _static(args[i + 1]) else None
                )
                i += 2
                continue
            if t.startswith("-C") and len(t) > 2:
                directory = _resolve(t[2:], directory)
                i += 1
                continue
            # `git -c <key>=<value>` runs arbitrary commands through several
            # config keys, and the subcommand still looks like a read. Measured
            # against real git, each of these executed with stdout a pipe:
            #     -c diff.external=CMD  git log -p --ext-diff
            #     -c diff.external=CMD  git diff --ext-diff
            #     -c core.fsmonitor=CMD git status
            # The pager route does not fire (git pages only to a terminal), but
            # these do, so no git command carrying an override is granted here.
            if t == "-c" or t.startswith("-c") or t.startswith("--config-env"):
                config_override = True
                i += 2 if t == "-c" else 1
                continue
            if t.startswith("-"):
                i += 1
                continue
            sub = t
            i += 1
        # `--output=F` / `-O F` make a read write a file; git's diff family
        # accepts them after the subcommand.
        writes_flag = any(
            r == "-O" or r == "--output" or r.startswith(("-O", "--output="))
            for r in rest if r
        )
        if config_override:
            retval = (False, "git -c: a config override can run an arbitrary command")
        elif self.unattended and sub in _UNATTENDED_GIT_SUBS:
            # Reached only past the `-c` / `--config-env` refusal above, and
            # only for a subcommand git defines -- an unknown word here is an
            # alias, which runs whatever somebody put in a config file.
            # `push`, `fetch`, `clone` and friends still have to name a host
            # this channel was given: the scope says which repo, allow_domains
            # says which internet.
            retval = self._unattended_git(sub, rest, directory)
        elif sub in GIT_LOCAL:
            retval = (True, f"git {sub}: local")
        # Lowercase only: -B / -C reset an existing branch to HEAD, which is
        # a rewrite, not a creation.
        elif sub == "checkout" and "-b" in rest:
            retval = (True, "git checkout -b: new branch")
        elif sub == "switch" and "-c" in rest:
            retval = (True, "git switch -c: new branch")
        elif sub == "commit":
            if directory is None:
                retval = (False, "git commit: directory not statically known")
            else:
                ok, why = self.probe.commit_allowed(directory)
                retval = (ok, f"git commit: {why}")
        elif sub == "branch" and not self.writes_file and not writes_flag:
            why = _git_branch_refusal(rest)
            retval = (False, why) if why else (True, "git branch: listing")
        elif sub == "remote" and not self.writes_file and not writes_flag:
            # `git remote` and `git remote -v` list what is configured, from
            # the local config and nothing else. Every other form is a write
            # (`add`, `remove`, `rename`, `set-url`, `prune`) or a fetch
            # (`show`, `update`), and `remote` is in policy's network list, so
            # granting those here would also step around the egress check --
            # which `policy.check` does not repeat for a granted command.
            if all(t in ("-v", "--verbose") for t in rest):
                retval = (True, "git remote: listing")
            else:
                retval = (False, "git remote: only the bare listing is read-only")
        elif sub == "worktree" and not self.writes_file and not writes_flag:
            # `git worktree list` reads the same administrative file `git
            # worktree add` writes, and `add`, `remove`, `move`, `prune`,
            # `repair` and `lock` all write it or the filesystem. Named rather
            # than flag-checked, because the subcommand is the whole question.
            if rest[:1] == ["list"] and all(t in ("--porcelain", "-v", "--verbose", "-z")
                                            for t in rest[1:]):
                retval = (True, "git worktree list: listing")
            else:
                retval = (False, "git worktree: only `list` is read-only")
        elif sub in GIT_READ and not self.writes_file and not writes_flag:
            retval = (True, f"git {sub}: read-only")
        else:
            retval = (False, f"git {sub}: not a local write")
        return retval


    def _unattended_git(self, sub, rest, directory):
        """(ok, reason) for a git subcommand in an unattended channel (#253).

        Reach is the only question left: `github_repos` has already said which
        repo, the sandbox which tree. A URL in the command is read the way
        every other fetch is. A command with no URL -- `git push`, `git push
        origin master` -- is the usual case and names its destination in the
        repo's config instead, so that is where the host comes from. A remote
        that cannot be resolved is a refusal, not a pass: unknown is not
        allowed."""
        text = getattr(self, "_seg_text", "")
        if _URL_IN_TEXT.search(text):
            allowed, why = policy_mod.check_egress(text, self.policy)
            retval = (True, f"git {sub}: unattended channel") if allowed else (False, why)
            return retval
        if sub not in _GIT_NET_SUBS_LOCAL:
            retval = (True, f"git {sub}: unattended channel")
            return retval
        name = next((r for r in rest if r and not r.startswith("-")), "origin")
        url = self.probe.remote_url(directory, name)
        if not url:
            retval = (False, f"git {sub}: remote {name!r} does not resolve to a URL here")
            return retval
        host = policy_mod.host_of_url(url)
        if not host:
            retval = (False, f"git {sub}: remote {name!r} has no host this layer can read")
            return retval
        if not policy_mod.host_allowed(host, self.policy):
            retval = (False, f"fetch to '{host}' is not in this channel's allow_domains")
            return retval
        retval = (True, f"git {sub}: unattended channel, remote {name} on {host}")
        return retval

    def _words(self, args, value_flags=frozenset()):
        """Non-flag words, or None if any argument is not a literal. A verb
        whose subcommand this agent cannot read statically is not one it can
        vouch for, so it falls through to YOLT and parks."""
        retval = []
        skip = False
        for a in args:
            t = _text(a, self.src) if _static(a) else None
            if t is None:
                return None
            if skip:
                skip = False
                continue
            if t in value_flags:
                skip = True
                continue
            if not t.startswith("-"):
                retval.append(t)
        return retval

    def gh(self, args):
        """`gh <noun> <action>` when both only read. None otherwise, which falls
        through to YOLT -- and at 2.0.x that means the command parks."""
        words = self._words(args, GH_VALUE_FLAGS)
        retval = None
        if words is None or self.writes_file:
            return retval
        if len(words) >= 2 and words[0] in GH_READ_NOUNS and words[1] in GH_READ_ACTIONS:
            retval = (True, f"gh {words[0]} {words[1]}: read-only")
        elif self.unattended and words and words[0] in _UNATTENDED_GH_NOUNS:
            texts = [_unquote(_text(a, self.src)) if _static(a) else None for a in args]
            if any(t and t.split("=", 1)[0] == "--hostname" for t in texts):
                # A different GitHub host is a different set of repos, and
                # `github_repos` describes one host's namespace (#253).
                retval = (False, "gh --hostname: another host is outside this channel's scope")
            else:
                retval = (True, f"gh {words[0]}: unattended channel")
        elif len(words) >= 2 and words[0] == "auth" and words[1] == _GH_AUTH_READ:
            # Which account is logged in is a read; every other `gh auth`
            # subcommand changes the credential (#236). `--show-token` prints
            # it, and `_words` drops dashed tokens, so the flags are read from
            # the arguments themselves rather than from `words`.
            texts = [_unquote(_text(a, self.src)) if _static(a) else None for a in args]
            why = _gh_auth_refusal(texts)
            retval = (False, why) if why else (True, "gh auth status: read-only")
        return retval

    def aws(self, args):
        """`aws <service> <operation>` when the operation only reads. The scope
        of what it may reach is policy's question, not this one: `_check_aws`
        runs on every granted command the same as on an auto-run one."""
        words = self._words(args, AWS_VALUE_FLAGS)
        retval = None
        if words is not None and len(words) >= 2 and not self.writes_file:
            op = words[1]
            if op in AWS_WRITES_OUTFILE or op in AWS_RETURNS_SECRET:
                return None
            if op == "ls" or op.startswith(AWS_READ_PREFIXES):
                retval = (True, f"aws {words[0]} {op}: read-only")
        return retval


def check(command, policy):
    """(granted, reason). `reason` lists every segment's grounds when granted,
    or the first refusal when not."""
    src = command.encode("utf-8")
    tree = tree_sitter.Parser(_LANG).parse(src)
    if tree.root_node.has_error:
        return (False, "command does not parse")
    walker = _Walker(src, policy_mod.cwd_for(policy), policy)
    ok, why = walker.walk(tree.root_node)
    if ok and not walker.reasons:
        ok, why = (False, "empty command")
    retval = (True, "; ".join(walker.reasons)) if ok else (False, why)
    return retval
