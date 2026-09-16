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

from . import gitstate, policy as policy_mod, yolt_gate

_LANG = tree_sitter.Language(tree_sitter_bash.language())

# Filesystem writes the sandbox confines to the tree.
FS_VERBS = frozenset(("cp", "mv", "mkdir", "touch", "tee", "ln", "chmod", "sed"))

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

# git subcommands that cannot mutate the repository whatever follows them.
# `branch`, `remote`, `config`, `tag`, `checkout` and `switch` are absent because
# a flag flips each into a write (-D, add, a value, -d, --). `grep` is absent
# because `git grep -O<cmd>` opens matches in a pager of its choosing, which
# runs that command even when stdout is a pipe -- measured, not assumed.
GIT_READ = frozenset((
    "status", "log", "show", "diff", "rev-parse", "ls-files", "blame",
    "describe", "shortlog", "cat-file", "ls-tree",
))

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
                dest = c.children[-1] if c.children else None
                if dest is None or not _static(dest):
                    return (False, "redirect target is not a literal")
                target = _unquote(_text(dest, self.src))
                if target.startswith("/dev/") and target not in _DEV_OK:
                    return (False, f"redirect to device {target}")
                # A read verb stops being a read when its output lands in a
                # file (#177). YOLT cannot tell us this -- `cat x`,
                # `cat x > out.txt` and `cat x > /usr/local/bin/foo` are one
                # `unknown` to it, differing only in a reason string nobody
                # parses -- so the redirect is seen here or not at all.
                if not _reads_only(c) and target not in _DEV_OK:
                    writes = True
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
        text = _text(node, self.src)
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
        elif verb in FS_VERBS:
            retval = (True, f"{verb}: in-tree write")
        elif verb == "git":
            retval = self.git(args)
        elif verb == "gh":
            retval = self.gh(args)
        elif verb == "aws":
            retval = self.aws(args)
        elif verb in READ_VERBS and not self.writes_file:
            retval = (True, f"{verb}: read-only")
        else:
            retval = None
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
                retval = (False, reason)
        if retval[0]:
            self.reasons.append(retval[1])
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
        elif sub in GIT_READ and not self.writes_file and not writes_flag:
            retval = (True, f"git {sub}: read-only")
        else:
            retval = (False, f"git {sub}: not a local write")
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
        if (words is not None and len(words) >= 2 and not self.writes_file
                and words[0] in GH_READ_NOUNS and words[1] in GH_READ_ACTIONS):
            retval = (True, f"gh {words[0]} {words[1]}: read-only")
        return retval

    def aws(self, args):
        """`aws <service> <operation>` when the operation only reads. The scope
        of what it may reach is policy's question, not this one: `_check_aws`
        runs on every granted command the same as on an auto-run one."""
        words = self._words(args, AWS_VALUE_FLAGS)
        retval = None
        if words is not None and len(words) >= 2 and not self.writes_file:
            op = words[1]
            if op in AWS_WRITES_OUTFILE:
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
