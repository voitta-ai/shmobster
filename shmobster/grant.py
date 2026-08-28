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

# Local git writes that need no repository state.
GIT_LOCAL = frozenset(("add", "mv", "stash"))

# Structural nodes to descend through; their operator tokens are skipped.
_CONTAINERS = frozenset(("program", "list", "pipeline"))
_SKIP = frozenset(("&&", "||", ";", "|", "&", "\n", ";;", "comment"))

_DEV_OK = frozenset(("/dev/null", "/dev/stdout", "/dev/stderr"))


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
    def __init__(self, src, start_dir):
        self.src = src
        self.tracked = start_dir
        self.probe = gitstate.GitProbe()
        self.reasons = []

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
            elif c.type in ("heredoc_redirect", "herestring_redirect"):
                continue
            else:
                return (False, f"{c.type} under a redirect is not grantable")
        if body is None:
            return (False, "redirect without a command")
        before = len(self.reasons)
        retval = self.walk(body)
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
        else:
            retval = None
        if retval is None or (retval[0] is False and verb == "git"):
            decision, reason = yolt_gate.classify(text)
            if decision == "safe":
                retval = (True, f"{verb}: read-only")
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
            if t == "-c" and i + 1 < len(args):
                i += 2
                continue
            if t.startswith("-"):
                i += 1
                continue
            sub = t
            i += 1
        if sub in GIT_LOCAL:
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
        else:
            retval = (False, f"git {sub}: not a local write")
        return retval


def check(command, policy):
    """(granted, reason). `reason` lists every segment's grounds when granted,
    or the first refusal when not."""
    src = command.encode("utf-8")
    tree = tree_sitter.Parser(_LANG).parse(src)
    if tree.root_node.has_error:
        return (False, "command does not parse")
    walker = _Walker(src, policy_mod.cwd_for(policy))
    ok, why = walker.walk(tree.root_node)
    if ok and not walker.reasons:
        ok, why = (False, "empty command")
    retval = (True, "; ".join(walker.reasons)) if ok else (False, why)
    return retval
