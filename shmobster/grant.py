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
right, and a node kind this module does not model -- subshell, variable
assignment, if/while, function -- is refused rather than guessed at. A plain
`for` loop and a `--`-guarded command substitution are modelled, as reads only
(#373). A literal `cd` moves the tracked directory in
source order, starting from the channel cwd; a `cd` that cannot be resolved
statically (`cd "$DIR"`, `cd -`) makes every later `git commit` ungrantable
rather than judged against the wrong tree. `git -C <path>` retargets one
segment the same way."""
import json
import os

import tree_sitter
import tree_sitter_bash

import re

from . import gitstate, policy as policy_mod, trajectory, yolt_gate

_LANG = tree_sitter.Language(tree_sitter_bash.language())

# Does the command itself name a URL? When it does, the ordinary egress check
# reads it; when it does not, an unattended git subcommand that contacts a
# remote resolves that remote's configured URL instead (#253).
_URL_IN_TEXT = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://")
# `git config` that only reads, as an allowlist: a lookup or listing, with the
# scope and display options. A value, --unset, --add, --edit and the rest all
# write, and every option outside this set is refused rather than judged.
_GIT_CONFIG_SCOPE = frozenset((
    "--global", "--local", "--system", "--worktree", "--show-origin",
    "--show-scope", "--name-only", "--null", "-z", "--includes", "--no-includes",
    "--bool", "--int", "--path",
))
_GIT_CONFIG_GETS = frozenset(("--get", "--get-all", "--get-regexp"))


def _git_config_refusal(rest):
    """Why this `git config` is not a read, or None."""
    if None in rest:
        return "git config: an argument is not a literal"
    words = list(rest)
    mode = None
    if words[:1] in (["get"], ["list"]):  # git 2.46+ subcommand form
        mode = words.pop(0)
    positionals = []
    for w in words:
        if w in _GIT_CONFIG_GETS or w in ("--list", "-l"):
            mode = mode or w
        elif w in _GIT_CONFIG_SCOPE or w.startswith("--type="):
            continue
        elif w.startswith("-"):
            return f"git config: option {w}"
        else:
            positionals.append(w)
    if mode in ("list", "--list", "-l"):
        ok = not positionals
    elif mode is not None:
        ok = 1 <= len(positionals) <= 2
    else:
        ok = len(positionals) == 1
    retval = None if ok else "git config: only a lookup or a listing is a read"
    return retval
_GIT_NET_RISKY = frozenset((
    "--repo", "--upload-pack", "--receive-pack", "--exec", "--config",
    "--template", "--reference", "--separate-git-dir",
))
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
#
# `apply_patch` is the agent's own editor -- an Update/Add/Delete-File patch read
# from a heredoc -- and it only ever writes files, the same blast radius as
# `patch` and `tee` beside it, confined to the tree by the sandbox. It was the
# one verb a redesign turn in an unattended channel could not use without a card
# per edit, so the agent fell back to `python3 -c`/heredocs that park for a worse
# reason. It stays OUT of FS_VERBS (attended channels) on purpose: a patch can
# delete a file and FS_VERBS deliberately excludes `rm`; unattended already runs
# `rm`, so there the distinction stopped mattering.
UNATTENDED_VERBS = frozenset((
    "rm", "rmdir", "cp", "mv", "mkdir", "touch", "tee", "ln",
    "chmod", "chown", "sed", "truncate", "install", "patch", "apply_patch",
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
# `sort` (-o), `uniq` (output positional), `date` (-s; flag-checked below), `hostname` (sets it),
# `find` (-delete, -exec), `rg` (runs a preprocessor) and `xargs` (runs its
# argument) are absent, and why
# `awk` is absent despite reading: its program can call system() (it is checked
# against an allowlist in FLAG_CHECKED_READS instead), and `tree` is
# absent because -o writes its output to a file. `sed` is in FS_VERBS already,
# as the writer -i makes it.
READ_VERBS = frozenset((
    "cat", "ls", "head", "tail", "wc", "file", "stat", "basename", "dirname",
    "realpath", "du", "df", "which", "diff", "grep", "egrep", "fgrep",
    "jq", "id", "whoami", "uname", "printenv", "ps",
    # Print-only builtins and a pause. `printf` is absent: its numeric
    # conversions are not a plain print.
    "echo", "pwd", "true", "sleep",
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

FLAG_CHECKED_READS = frozenset(("find", "sort", "awk", "rg", "date"))


def _find_refusal(texts):
    hit = next((t for t in texts if t in _FIND_WRITES), None)
    retval = f"find: flag {hit}" if hit else None
    return retval


# The ripgrep options that run a named program. `--pretty` shares a prefix and
# prints.
_RG_RUNS = frozenset(("--pre", "--hostname-bin"))


def _rg_refusal(texts):
    hit = next((t for t in texts if t.split("=")[0] in _RG_RUNS), None)
    # -z / --search-zip runs decompressors found on PATH. A short cluster is
    # refused whenever it holds a z, attached values included.
    zipped = next((t for t in texts if t == "--search-zip"
                   or t.startswith("-") and not t.startswith("--") and "z" in t), None)
    retval = (f"rg: flag {hit.split('=')[0]}" if hit
              else f"rg: {zipped} searches compressed files" if zipped else None)
    return retval


# `sort` as an allowlist. Its writers and program runners differ between
# implementations, and long options can be abbreviated, so a deny list has to
# know every spelling of every one. These are the ordering and field options;
# anything else cards.
_SORT_FLAGS = frozenset("bcCdfghiMmnRrsuV")
_SORT_VALUE_FLAGS = frozenset("kt")
_SORT_LONG = frozenset((
    "--check", "--dictionary-order", "--field-separator", "--general-numeric-sort",
    "--human-numeric-sort", "--ignore-case", "--ignore-leading-blanks",
    "--ignore-nonprinting", "--key", "--merge", "--month-sort", "--numeric-sort",
    "--random-sort", "--reverse", "--stable", "--unique", "--version-sort",
))
_SORT_LONG_VALUE = frozenset(("--key", "--field-separator"))


def _sort_refusal(texts):
    """`sort` with only ordering and field options, and any files."""
    i = 0
    while i < len(texts):
        t = texts[i]
        i += 1
        if t.startswith("--"):
            if t.split("=")[0] not in _SORT_LONG:
                return f"sort: option {t.split('=')[0]}"
            if t in _SORT_LONG_VALUE:
                i += 1
        elif t.startswith("-") and len(t) > 1:
            for k, ch in enumerate(t[1:], 1):
                if ch in _SORT_VALUE_FLAGS:
                    if k == len(t) - 1:
                        i += 1  # its value is the next word
                    break
                if ch not in _SORT_FLAGS:
                    return f"sort: option -{ch}"
    return None


# awk is a language, so it is checked against an allowlist of what its program
# may contain rather than a list of the builtins that run or write things: a
# function it may call, and characters outside strings and regexes that cannot
# open a pipe (`|`), a file (`>`), an extension (`@load`, `@include`) or a
# continuation (`\`). Every builtin name of BWK awk and gawk outside that
# allowlist is refused wherever it appears, called or not: awk applies a bare
# builtin to `$0`. Options: the field separator and a variable, nothing that
# loads a program from a file.
_AWK_CALLS = frozenset((
    "length", "substr", "index", "split", "sub", "gsub", "match", "sprintf",
    "tolower", "toupper", "int", "sqrt", "exp", "log", "sin", "cos", "atan2",
    "rand", "srand", "printf", "print",
))
# The builtin and keyword names of BWK awk and gawk that are not allowed: they
# run a command, open a file or connection, or flush and close one. A closed
# set per implementation, unlike user variable names.
_AWK_REFUSED_NAMES = frozenset((
    "system", "getline", "close", "fflush", "function", "func",
    "and", "asort", "asorti", "bindtextdomain", "compl", "dcgettext",
    "dcngettext", "gensub", "isarray", "lshift", "mktime", "or", "patsplit",
    "rshift", "strftime", "strtonum", "systime", "typeof", "xor",
))
_AWK_CHARS = frozenset("{}();,$+-*/%^!=<~?:[]&|. \t\n\r_0123456789")


def _awk_program_refusal(prog):
    """Why this awk program is not one of the read-only ones, or None."""
    i, n = 0, len(prog)
    prev = ""
    while i < n:
        c = prog[i]
        if c == '"':
            j = i + 1
            while j < n and prog[j] != '"':
                j += 2 if prog[j] == "\\" else 1
            if j >= n:
                return "awk: unterminated string"
            i, prev = j + 1, "x"
            continue
        if c == "/" and prev not in ("x", ")", "]"):
            # A regex literal: here `/` cannot be division, so it opens one.
            j = i + 1
            while j < n and prog[j] != "/":
                j += 2 if prog[j] == "\\" else 1
            if j >= n:
                return "awk: unterminated regex"
            i, prev = j + 1, "x"
            continue
        if c.isalpha() or c == "_":
            j = i
            while j < n and (prog[j].isalnum() or prog[j] == "_"):
                j += 1
            word = prog[i:j]
            k = j
            while k < n and prog[k] in " \t":
                k += 1
            if word in _AWK_REFUSED_NAMES:
                return f"awk: {word}"
            if k < n and prog[k] == "(" and word not in _AWK_CALLS and word not in ("if", "while", "for"):
                return f"awk: calls {word}()"
            if word in ("print", "printf"):
                prev = "print"
            else:
                prev = "x"
            i = j
            continue
        if c in "+-" and prog[i:i + 2] in ("++", "--"):
            # Postfix after an operand keeps it an operand, so a `/` next is
            # division; prefix leaves an operator before the operand to come.
            i += 2
            prev = "x" if prev == "x" else "op"
            continue
        if c == "|":
            if prog[i:i + 2] != "||":
                return "awk: pipe"
            i += 2
            prev = "op"
            continue
        if c not in _AWK_CHARS:
            return f"awk: {c!r} outside a string or regex"
        if c not in " \t\n\r":
            prev = "x" if c.isdigit() or c in ")]$" else ("op" if c != "." else prev)
        i += 1
    return None


def _awk_refusal(texts):
    """`awk [-F sep] [-v var=val] 'program' [file | var=val ...]` whose program
    passes `_awk_program_refusal`; anything else is refused."""
    i = 0
    while i < len(texts) and texts[i].startswith("-") and texts[i] != "-":
        t = texts[i]
        if t in ("-F", "-v"):
            i += 2
        elif t.startswith("-F") and len(t) > 2:
            i += 1
        else:
            return f"awk: option {t}"
    if i >= len(texts):
        return "awk: no program"
    retval = _awk_program_refusal(texts[i])
    return retval


# `date` prints a time unless it is asked to set one, and what counts as asking
# differs by implementation. BSD getopt stops at the first non-option and BSD
# then treats a following word as the time to set, where GNU permutes; a `+`
# word is the format only in BSD's first position; and without `-j`, BSD's `-f`
# exists only to parse a time to set. So this reads the strictest common shape:
# allowlisted options first, nothing dash-shaped after them, and then either
# `-j` among those options (parse, never set) or at most one `+format`. The
# conversions an agent reaches for -- `date -u -r 1770068151`, `date -d @1770068151`,
# `date -j -f %s 1770068151 +%F` -- used to card.
_DATE_FLAGS = frozenset("uRjn")
_DATE_VALUE_FLAGS = frozenset("rdvfz")
_DATE_LONG = frozenset((
    "--utc", "--universal", "--rfc-email", "--rfc-2822", "--iso-8601",
    "--rfc-3339", "--debug", "--help", "--version", "--date", "--reference",
    "--file",
))
_DATE_LONG_VALUE = frozenset(("--date", "--reference", "--file"))


def _date_refusal(texts):
    """`date` whose words read the same to BSD and GNU, and print on both."""
    no_set = False
    parses_input = False
    i = 0
    while i < len(texts) and texts[i].startswith("-") and len(texts[i]) > 1:
        t = texts[i]
        i += 1
        if t.startswith("--"):
            if t.split("=")[0] not in _DATE_LONG:
                return f"date: option {t}"
            if t in _DATE_LONG_VALUE:
                i += 1
            continue
        for k, ch in enumerate(t[1:], 1):
            if ch == "j":
                no_set = True
            if ch in _DATE_FLAGS:
                continue
            if ch == "I":
                break  # -I[FMT]: the rest of the word is its argument
            if ch in _DATE_VALUE_FLAGS:
                parses_input = parses_input or ch == "f"
                if k == len(t) - 1:
                    i += 1  # its value is the next word
                break
            return f"date: option -{ch}"
    rest = texts[i:]
    if any(t.startswith("-") and len(t) > 1 for t in rest):
        return "date: an option after a positional reads differently on BSD and GNU"
    if no_set:
        return None
    if parses_input:
        return "date: -f without -j sets the clock"
    setting = rest[1:] if rest[:1] and rest[0].startswith("+") else rest
    if setting:
        return f"date: {setting[0]} would set the clock"
    return None


_FLAG_REFUSAL = {"find": _find_refusal, "sort": _sort_refusal, "awk": _awk_refusal,
                 "rg": _rg_refusal, "date": _date_refusal}

# An interpreter asked only for its version runs no code: `python3 --version`.
# Each interpreter's own spelling of the version flag: `node -v` is version,
# `python -v` is verbose, so the flags are per interpreter.
_VERSION_ONLY = {
    "python": ("--version", "-V"),
    "python3": ("--version", "-V"),
    "node": ("--version", "-v"),
}

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


def _fetch_names_its_file(texts):
    """True when every flag that makes this fetch write a file is `-o FILE` or
    `--output FILE`, so the command names the file itself."""
    retval = True
    for t in texts:
        head = t.split("=", 1)[0]
        if head in _FETCH_WRITE_LONG:
            retval = retval and head == "--output"
        elif t.startswith("-") and not t.startswith("--"):
            letters = set(t[1:]) & _FETCH_WRITE_LETTERS
            retval = retval and letters <= {"o"}
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
    "describe", "shortlog", "cat-file", "ls-tree",
    # Ancestry questions, all of them read-only whatever follows (#264).
    # `merge-base` has no writing form: --is-ancestor, --fork-point, --octopus,
    # --independent and -a only change what it answers. Its absence cost a card
    # for `git merge-base --is-ancestor A B`, and took every other segment of
    # the command with it. `rev-list` is the same question counted (`--count
    # A..B`); it takes revision options only, and the diff family's `--output`
    # is refused for every subcommand below anyway.
    "merge-base", "for-each-ref", "rev-list",
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

# `npm` subcommands that only read, and read only locally: `ls` walks the
# node_modules tree, no network, no scripts. `view`/`outdated` are absent on
# purpose -- they reach whatever registry a `.npmrc` in the channel tree names,
# with its auth token, and nothing here vets that host against allow_domains.
# install/ci/run/exec/publish run scripts or change the tree; `npx` is another
# verb and parks.
NPM_READS = frozenset(("ls", "list"))

# `vercel` is a per-channel grant scoped to Vercel projects (#327), modelled on
# `aws_profile`: the channel policy names what it may reach, and a command that
# reaches anything else is not granted. The policy key, set in the policy file
# only (never through set_policy, like `unattended`):
#
#     "vercel": {"team": "<slug>", "org_id": "team_...",
#                "projects": {"<name>": "prj_..."}, "writes": false}
#
# The scope is the Vercel project, not the git repo: one repo can deploy to
# several projects and a project can deploy with no repo at all.
#
# Grouped by what the command reaches. Account reads name no target. Team reads
# need the team resolved. Project commands need every piece of target evidence
# present to be in scope, and at least one present.
VERCEL_ACCOUNT_READS = frozenset((("whoami",), ("teams", "ls"), ("teams", "list")))
VERCEL_TEAM_READS = frozenset((
    ("project", "ls"), ("project", "list"), ("projects", "ls"), ("projects", "list"),
    ("domains", "ls"), ("domains", "list"), ("alias", "ls"), ("alias", "list"),
))
VERCEL_PROJECT_READS = frozenset((
    ("ls",), ("list",), ("inspect",), ("logs",), ("env", "ls"), ("env", "list"),
))
# Granted only when the policy also says `"writes": true`. Deliberately absent,
# so they park even in a granted channel: `env pull` writes the project's
# secrets into the tree, `link` rewrites .vercel/project.json -- the file this
# check reads -- and `alias set`/`rm` move a domain, which no project ID pins.
VERCEL_PROJECT_WRITES = frozenset((
    ("deploy",), ("promote",), ("rollback",),
    ("env", "add"), ("env", "rm"), ("env", "remove"),
))
# Subcommands whose first positional after the subcommand is a deployment (URL
# or name) and so a target. `ls` takes a project name there instead.
_VERCEL_DEPLOYMENT_ARG = frozenset(("inspect", "logs", "promote", "rollback"))
# The credential is skipped unread: naming it does not change the target, and
# it is usually `"$VERCEL_TOKEN"`, an expansion. Nothing else may be dynamic.
_VERCEL_TOKEN_FLAGS = frozenset(("--token", "-t"))
# These ARE the target, so their value is read and checked.
_VERCEL_TEAM_FLAGS = frozenset(("--scope", "-S", "--team", "-T"))
# Value flags that only shape output or timing.
_VERCEL_VALUE_FLAGS = frozenset(("--output", "-o", "--timeout", "--limit", "-n",
                                 "--environment", "--since", "--until"))
_VERCEL_FLAGS = frozenset(("--prod", "--yes", "-y", "--debug", "-d", "--no-color",
                           "--json", "--force", "-f", "--wait", "--follow",
                           "--version", "-v"))
# Any other flag parks: `--cwd`, `--local-config`/`-A` and `--global-config`/`-Q`
# move where the link is read from, `--name` renames the project a deploy goes
# to, and an unknown value flag would have its value read as a target.
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
_TEXT_SCOPED = frozenset(("git", "gh", "aws", "npm"))
_SYSTEM_BIN = frozenset(("", "/bin", "/usr/bin", "/sbin", "/usr/sbin",
                         "/usr/local/bin", "/opt/homebrew/bin"))

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


def _stdout_write(node):
    """True for a `>` or `>>` file redirect of standard output."""
    ops = [c.type for c in node.children]
    fds = [c for c in node.children if c.type == "file_descriptor"]
    retval = (any(op in (">", ">>") for op in ops)
              and all(c.text in (b"1",) for c in fds))
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


def _literal_word(node, src):
    """The word bash ends up with, when that takes no shell rules beyond quote
    removal to work out, else None. A check has to read what the command gets
    rather than what the source looks like, so quoted pieces are joined, and
    anything with a glob, a brace or an escape is not read at all. The escaped
    parentheses and `!` of a `find` expression are the one exception."""
    text = _text(node, src)
    retval = None
    if node.type == "raw_string":
        retval = text[1:-1]
    elif node.type in ("word", "number"):
        if text in ("\\(", "\\)", "\\!"):
            retval = text[1:]
        elif not any(ch in text for ch in "\\{*?["):
            retval = text
    elif (node.type == "string" and "\\" not in text
          and all(c.type in ('"', "string_content") for c in node.children)):
        retval = text[1:-1]
    elif node.type == "concatenation" and _contiguous(node):
        parts = [_literal_word(c, src) for c in node.children]
        retval = "".join(parts) if all(p is not None for p in parts) else None
    return retval


def _contiguous(node):
    """True when the parts of a word touch: nothing, not even a line
    continuation, sits between them."""
    kids = node.children
    retval = all(a.end_byte == b.start_byte for a, b in zip(kids, kids[1:]))
    return retval


def _glob_text(node, src):
    """A word as written, globs and all, when quote removal is the only other
    rule it needs; else None."""
    text = _text(node, src)
    retval = None
    if node.type in ("word", "number"):
        retval = text if "\\" not in text else None
    elif node.type == "concatenation" and _contiguous(node):
        parts = [_glob_text(c, src) for c in node.children]
        retval = "".join(parts) if all(p is not None for p in parts) else None
    else:
        retval = _literal_word(node, src)
    return retval


def _arg_word(node, src):
    """An argument as the command gets it, for checks that compare it with
    option names; None when that cannot be read. A glob is kept as written
    when it starts with a literal character other than a dash: every word it
    can expand to starts with that character, so none of them is an option."""
    retval = _literal_word(node, src)
    if retval is None:
        text = _glob_text(node, src)
        if text and text[0] not in "-*?[{":
            retval = text
    return retval


# The words after which an argument is never an option (#373). Both are what
# git's own parser honours, and `--` is what getopt does.
_END_OF_OPTIONS = frozenset(("--", "--end-of-options"))

# ...but for git only when nothing before it takes it as a value: in `git log
# --grep -- $(...)` the `--` is the pattern, and the substitution's words are
# options again (`--output=F` writes F). So the word just before the marker
# must be one that cannot take a separate value: a word without a dash, an
# option with its value attached (`--format=x`), or one of these git read flags
# that take none. An allowlist, so an unlisted flag before `--` parks.
_NO_VALUE_FLAGS = frozenset((
    "--oneline", "--stat", "--name-only", "--name-status", "-p", "--patch",
    "--all", "--cached", "--porcelain", "-z",
))

# Grants that are reads, by the reason this module gives them. A loop body and
# a substitution must be made of these and nothing else (#373): a read run ten
# times is still a read, and a write is not, whoever vouched for it once.
_READ_LISTINGS = frozenset(("git branch: listing", "git remote: listing",
                            "git worktree list: listing", "git config: read"))

# A loop variable is assigned in the running shell, so its name picks what it
# overwrites. `for PATH in /tmp/x; do ls; done` runs whatever `ls` is in
# /tmp/x, and `IFS` re-splits every later word. Those and the proxy and GIT_*
# variables a read follows are upper case or carry an underscore, so the names
# accepted are the short lower-case ones people write: `f`, `file`, `d`, `i`.
_LOOP_VAR = re.compile(r"[a-z][a-z0-9]*")


def _frees_marker(prev):
    """True when a `--` right after the word `prev` ends the options rather
    than being prev's value. None, a word this layer could not read, is not."""
    retval = prev is not None and (not prev.startswith("-") or "=" in prev
                                   or prev in _NO_VALUE_FLAGS)
    return retval


def _read_grant(verb, reason):
    """True when a granted segment was granted as a read. `vercel` is left out
    even for its reads: its grant reads a link file that another segment could
    rewrite, which `check` judges across the whole command (#327)."""
    retval = verb != "vercel" and (reason.endswith(": read-only") or reason in _READ_LISTINGS)
    return retval


def _bare_substitution(node):
    """The command_substitution an argument is, quoted or not, else None. Only
    this shape: a substitution glued to other text is a word this layer would
    have to assemble before it could say where it starts."""
    retval = None
    if node.type == "command_substitution":
        retval = node
    elif node.type == "string":
        inner = [c for c in node.children if c.type != '"']
        if len(inner) == 1 and inner[0].type == "command_substitution":
            retval = inner[0]
    return retval


def _is_device(target, tracked=None):
    """True for a path under /dev, however it is spelled, including relative to
    the tracked directory."""
    t = os.path.normpath(_resolve(target, tracked) or target)
    t = "/" + t.lstrip("/") if t.startswith("/") else t
    retval = t == "/dev" or t.startswith("/dev/")
    return retval


# A heredoc is granted only in the shapes where bash and tree-sitter provably
# agree on where it ends and what its text does: a plain delimiter or a wholly
# quoted one, and a closing line that is the delimiter and nothing else. In an
# unquoted body, anything the parser does not model is refused from the raw
# bytes, because a node that is not in the tree cannot be walked.
_HEREDOC_OPEN = frozenset(("<<", "<<-", "heredoc_start", "heredoc_body", "heredoc_end"))
_HEREDOC_DELIM = re.compile(r"""[A-Za-z0-9_]+|'[A-Za-z0-9_.-]+'|"[A-Za-z0-9_.-]+\"""")
_HEREDOC_UNSAFE = (b"`", b"$(", b"\\\n")


def _heredoc_refusal(c, src):
    """Why this heredoc's extent or body cannot be trusted, or None."""
    kinds = {k.type: k for k in c.children}
    start = kinds.get("heredoc_start")
    end = kinds.get("heredoc_end")
    if start is None or end is None:
        return "heredoc without an opening or closing delimiter"
    raw = _text(start, src)
    if not _HEREDOC_DELIM.fullmatch(raw):
        return "heredoc delimiter is not plain or wholly quoted"
    delim = _unquote(raw).encode()
    clean = (lambda ln: ln.lstrip(b"\t")) if "<<-" in kinds else (lambda ln: ln)
    last = src.rfind(b"\n", 0, end.start_byte) + 1
    if clean(src[last:end.end_byte]) != delim or src[end.end_byte:end.end_byte + 1] not in (b"", b"\n"):
        return "heredoc closing line is not its delimiter"
    body = src[src.find(b"\n", start.end_byte) + 1:last]
    if any(clean(ln) == delim for ln in body.split(b"\n")):
        return "heredoc delimiter appears inside its body"
    if raw == _unquote(raw) and any(tok in body for tok in _HEREDOC_UNSAFE):
        return "command substitution in a heredoc or herestring"
    return None


def _resolve(target, tracked):
    """A literal path against the tracked directory, or None."""
    retval = None
    if tracked is not None and target not in ("-",):
        t = os.path.expanduser(target)
        retval = t if os.path.isabs(t) else os.path.join(tracked, t)
    return retval


class _Walker:
    def __init__(self, src, start_dir, policy=None, channel=None, thread_ts=None):
        self.src = src
        self.tracked = start_dir
        self.start_dir = start_dir
        self.policy = policy or {}
        # File-only channel opt-in (#253), read once per walk. Not settable
        # through `set_policy`, so a channel cannot talk itself into it.
        self.unattended = bool(self.policy.get("unattended"))
        # Identity of the turn, so a commit grant can read this thread's
        # own record (#238). Absent for a direct call, which then cannot
        # satisfy a check_command -- the safe direction.
        self.channel = channel
        self.thread_ts = thread_ts
        self.probe = gitstate.GitProbe()
        self.reasons = []
        # Raised while walking the body of a redirect that writes to a real
        # file, so a read verb under it is not granted as a read (#177).
        self.writes_file = False
        # Set when a vercel segment is granted, and when any other segment is
        # granted for something other than a read (#327); `check` refuses both.
        self.vercel_seen = False
        self.other_effect = False
        # Raised while walking a single command whose stdin is a heredoc.
        self.heredoc_stdin = False
        # Raised inside a loop body, a substitution, and the command that takes
        # one (#373): only a read is granted there.
        self.reads_only = False
        # Arguments of the current segment that are `--`-guarded
        # substitutions, by byte span; `git` steps over them.
        self._opaque = frozenset()

    def read_scope(self, fn, *args):
        """fn(*args) with only read rules in force (#373).

        An unattended channel grants `git`, `rm` and the rest on their verb
        (#253), so the unattended branches are switched off here rather than
        their reasons filtered afterwards: a loop or a substitution in an
        unattended channel gets the same answer it gets in an attended one,
        from the same read rules."""
        saved = (self.reads_only, self.unattended, getattr(self, "_seg_text", ""))
        self.reads_only, self.unattended = True, False
        try:
            retval = fn(*args)
        finally:
            self.reads_only, self.unattended, self._seg_text = saved
        return retval

    def loop(self, node):
        """A plain `for x in <words>; do <reads>; done` (#373).

        Each part is allowlisted rather than the known-bad ones refused: the
        keyword is `for` (tree-sitter parses `select` into the same node), the
        list is words this layer can read without running anything, and the
        body is walked like any command with only the read rules in force.
        A C-style loop and `while` are other node types and still park."""
        kids = node.children
        if not kids or kids[0].type != "for":
            return (False, f"{kids[0].type if kids else 'loop'} loop is not grantable")
        var = node.child_by_field_name("variable")
        if var is None or not _LOOP_VAR.fullmatch(_text(var, self.src)):
            return (False, "for: only a short lower-case loop variable is grantable")
        if not any(c.type == "in" for c in kids):
            # Without `in` it iterates "$@", which this layer cannot see.
            return (False, "for: a loop without `in` is not grantable")
        body = None
        for c in kids[1:]:
            if c.type in ("variable_name", "in", ";", "\n"):
                continue
            if c.type == "do_group":
                body = c
            elif node.field_name_for_child(list(kids).index(c)) == "value":
                raw = _text(c, self.src)
                # A quoted `$(` or backtick is inert in the list, but the
                # guardrail is the text: nothing that looks like it runs.
                if (not _static(c) or _glob_text(c, self.src) is None
                        or "$(" in raw or "`" in raw):
                    return (False, "for: the list is not literals or globs")
            else:
                return (False, f"for: {c.type} is not grantable")
        if body is None:
            return (False, "for: no body")
        retval = (True, "")
        for c in body.children:
            if c.type in ("do", "done"):
                continue
            retval = self.read_scope(self.walk, c)
            if not retval[0]:
                break
        return retval

    def substitutions(self, verb, args):
        """None when every command substitution in args can be granted, else
        why not (#373).

        A substitution's output becomes argv, and a word in it that starts
        with a dash becomes an option -- for `git grep`, the one that runs a
        pager. So the rule is about where the words land, not what produced
        them: after `--` or `--end-of-options`, and only for a command that
        reads past that point as names and nothing else. READ_VERBS qualify by
        their own bar (no argument makes them write). `git` qualifies through
        its read rules, which still judge every word before the `--`. The
        flag-checked verbs do not: `find`, `awk` and `date` read their
        positionals as an expression, a program and a clock setting, so a
        `--` does not make the output inert there. The inner command is walked
        with only the read rules in force. Nothing here asks the classifier."""
        guarded = False
        opaque = []
        for a in args:
            if _no_substitution(a):
                # Whether this `--` is itself an option's value matters only
                # to git, whose handler asks it after the subcommand; for a
                # read verb an option is harmless by the bar it entered on.
                guarded = guarded or (_static(a) and _literal_word(a, self.src) in _END_OF_OPTIONS)
                continue
            if verb not in READ_VERBS and verb != "git":
                return "only a read verb or git takes one"
            if not guarded:
                return "no `--` before it, so its output could be an option"
            inner = _bare_substitution(a)
            if inner is None:
                return "not a whole argument"
            # Its output is captured into argv, so a redirect on the command
            # taking it is not where the inner command writes.
            saved = (self.writes_file, self.heredoc_stdin)
            self.writes_file = self.heredoc_stdin = False
            try:
                for c in inner.children:
                    if c.type in ("$(", ")", "`"):
                        continue
                    ok, why = self.read_scope(self.walk, c)
                    if not ok:
                        return f"inside it, {why}"
            finally:
                self.writes_file, self.heredoc_stdin = saved
            opaque.append((a.start_byte, a.end_byte))
        self._opaque = frozenset(opaque)
        return None

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
        elif node.type == "for_statement":
            retval = self.loop(node)
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
        # Words after the target belong to the command, whatever node the
        # parser hangs them on, and nothing here reads them as arguments.
        dests = c.children_by_field_name("destination")
        if len(dests) > 1 or (dests and any(k.type in _CLOSE_OPS for k in c.children)):
            return ("words after a redirect target are not grantable", None)
        # No path, nothing to judge: not a device, not in the tree, not a
        # write. Checked before the destination is read at all, because for
        # `2>&1` the "destination" is the number 1.
        if _fd_dup(c):
            return (None, False)
        dest = c.children[-1] if c.children else None
        if dest is None or not _static(dest):
            return ("redirect target is not a literal", None)
        target = _literal_word(dest, self.src)
        if target is None:
            return ("redirect target is not a plain literal", None)
        # `~+` and `~-` expand to directories `cd` chose, so only the home form
        # can be read from here.
        if target.startswith("~") and target != "~" and not target.startswith("~/"):
            return ("redirect target is not a plain literal", None)
        if self.tracked is None and not os.path.isabs(os.path.expanduser(target)):
            return ("redirect target is relative to a directory this cannot read", None)
        if _is_device(target, self.tracked) and target not in _DEV_OK:
            return (f"redirect to device {target}", None)
        # A read verb stops being a read when its output lands in a file
        # (#177). YOLT cannot tell us this -- `cat x`, `cat x > out.txt` and
        # `cat x > /usr/local/bin/foo` are one `unknown` to it, differing only
        # in a reason string nobody parses -- so the redirect is seen here or
        # not at all.
        retval = (None, not _reads_only(c) and target not in _DEV_OK)
        return retval

    def stdin_redirect(self, c):
        """One heredoc or herestring judged: (refusal, writes_a_file, trailing).

        Their text is expanded by bash exactly as an argument is, so it answers
        to the same rule as an argument. What follows a heredoc's opening word
        on its line hangs under this node: a redirect answers to
        `redirect_write`, and the rest of a pipeline or list is returned for
        the caller to walk after the command it follows, in source order."""
        trailing = []
        if not _no_substitution(c):
            return ("command substitution in a heredoc or herestring", None, trailing)
        writes = False
        if c.type == "heredoc_redirect":
            refusal = _heredoc_refusal(c, self.src)
            if refusal is not None:
                return (refusal, None, trailing)
            for part in c.children:
                if part.type == "file_redirect":
                    refusal, redirect_writes = self.redirect_write(part)
                    if refusal is not None:
                        return (refusal, None, trailing)
                    writes = writes or redirect_writes
                elif part.type in ("command", "pipeline", "list", "redirected_statement"):
                    trailing.append(part)
                elif part.type not in _HEREDOC_OPEN and part.type not in ("|", "&&", "||"):
                    return (f"{part.type} after a heredoc is not grantable", None, trailing)
        return (None, writes, trailing)

    def redirected(self, node):
        """A command, pipeline or list with redirects. The body is judged as
        usual; the redirect is an in-tree write the sandbox confines, unless
        it names a device other than the three harmless ones."""
        body = None
        writes = False
        trailing = []
        redirects = []
        for c in node.children:
            if c.type in ("command", "pipeline", "list", "for_statement"):
                body = c
            elif c.type == "file_redirect":
                refusal, redirect_writes = self.redirect_write(c)
                if refusal is not None:
                    return (False, refusal)
                writes = writes or redirect_writes
                redirects.append(c)
            elif c.type in ("heredoc_redirect", "herestring_redirect"):
                refusal, redirect_writes, more = self.stdin_redirect(c)
                if refusal is not None:
                    return (False, refusal)
                writes = writes or redirect_writes
                trailing.extend(more)
            else:
                return (False, f"{c.type} under a redirect is not grantable")
        if body is None:
            return (False, "redirect without a command")
        if writes and (self.reads_only or body.type == "for_statement"):
            # A loop or a substitution is granted as a read (#373); a file it
            # writes would make it something else. `2>/dev/null`, `2>&1` and
            # `<` write nothing and stay.
            return (False, "a redirect to a file in a loop or a substitution")
        before = len(self.reasons)
        saved = self.writes_file
        saved_heredoc = self.heredoc_stdin
        # `cat > f <<EOF` is how an agent writes a file. The heredoc was judged
        # above, so a lone `cat` reading it is the same write `tee f` is.
        # Only when the heredoc is the sole stdin and stdout is what lands in
        # the file: bash takes the last stdin redirect, so a `<` beside it
        # would make this a file copy (#177), and a stderr redirect writes
        # nothing of cat's output.
        # A redirect written after the heredoc's opening word hangs under the
        # heredoc node, so its children count too.
        kids = list(node.children) + list(body.children)
        kids += [k for c in node.children if c.type == "heredoc_redirect" for k in c.children]
        self.heredoc_stdin = (
            body.type == "command"
            and sum(c.type == "heredoc_redirect" for c in kids) == 1
            and not any(c.type == "herestring_redirect" or c.type == "file_redirect" and _reads_only(c)
                        for c in kids)
            and any(c.type == "file_redirect" and _stdout_write(c) for c in kids))
        self.writes_file = self.writes_file or writes
        if writes:
            # A redirect writes before a later segment runs, which is the same
            # hazard the result path marks for `cp`/`mv` (#328 r2):
            # `printf x > .vercel/project.json && vercel deploy` must park.
            self.other_effect = True
        retval = self.walk(body)
        self.writes_file = saved
        self.heredoc_stdin = saved_heredoc
        if retval[0]:
            # A redirect after a list opens its file once the list's `cd`s
            # have run, so the directory is judged again where it now stands.
            for c in redirects:
                refusal, _ = self.redirect_write(c)
                if refusal is not None:
                    return (False, refusal)
        if retval[0] and len(self.reasons) > before:
            self.reasons[-1] += " > redirect"
        for part in trailing:
            if not retval[0]:
                break
            retval = self.walk(part)
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
                # A path outside the system's own directories is some other
                # program that shares a name with a verb, so it keeps its path
                # and matches nothing here.
                verb = _unquote(_text(c, self.src))
                if os.path.dirname(verb) in _SYSTEM_BIN:
                    verb = os.path.basename(verb)
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
        saved = (self.writes_file, self.reads_only, self.unattended)
        try:
            retval = self._segment(node)
        finally:
            self.writes_file, self.reads_only, self.unattended = saved
        return retval

    def _segment(self, node):
        text = _text(node, self.src)
        # Kept for the handlers that have to ask about reach: an unattended
        # `git push` is granted on its subcommand and still has to name a host
        # this channel was given (#253).
        self._seg_text = text
        self._opaque = frozenset()
        for c in node.children:
            if c.type == "file_redirect":
                refusal, writes = self.redirect_write(c)
                if refusal is not None:
                    return (False, refusal)
                if writes and self.reads_only:
                    return (False, "a redirect to a file in a loop or a substitution")
                self.writes_file = self.writes_file or writes
            elif c.type in ("heredoc_redirect", "herestring_redirect"):
                refusal, writes, more = self.stdin_redirect(c)
                if refusal is not None:
                    return (False, refusal)
                if more:
                    return (False, "a statement after a heredoc here is not grantable")
                self.writes_file = self.writes_file or writes
            elif c.type == "heredoc_body" and not _no_substitution(c):
                return (False, "command substitution in a heredoc or herestring")
        # Two parser words with only line continuations between them are one
        # word to bash, and every check below would read it as two.
        for a, b in zip(node.children, node.children[1:]):
            gap = self.src[a.end_byte:b.start_byte]
            if gap and not gap.replace(b"\\\n", b""):
                return (False, "a line continuation joins two words")
        verb, args = self.argv(node)
        if verb is None:
            return (False, "command with a prefix or a non-literal name")
        # Nothing granted here may carry an argument that runs something:
        # `cp $(rm -rf x) b`, `cd $(curl ... | sh)`. The allowlisted verbs
        # and `cd` are judged on the verb alone, and YOLT only sees the
        # segments that fall through to it, so the check is unconditional --
        # except for a read run inside a read, behind `--` (#373), and then
        # the command taking it is held to the read rules as well.
        if not all(_no_substitution(a) for a in args):
            why = self.substitutions(verb, args)
            if why is not None:
                return (False, f"{verb}: command substitution in arguments: {why}")
            self.reads_only, self.unattended = True, False
        if verb == "cd" and self.reads_only:
            # A loop body runs once per word; one tracked directory cannot
            # follow that, and a substitution's `cd` moves nothing outside it.
            return (False, "cd in a loop or a substitution is not grantable")
        # Scope checks for these (`_check_github`, `_check_aws`) read
        # the command's text, so an option has to be spelled the way the
        # command receives it, or the check and the command see two commands.
        # Its value may be quoted as usual.
        if verb in _TEXT_SCOPED:
            for a in args:
                word = _literal_word(a, self.src)
                name = (word or "").split("=")[0]
                if name.startswith("-") and not _text(a, self.src).startswith(name):
                    return (False, f"{verb}: option {name} is quoted or escaped")
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
        elif verb == "cat" and self.writes_file and self.heredoc_stdin and not args:
            retval = (True, "cat: heredoc into an in-tree file")
        elif verb == "git":
            retval = self.git(args)
        elif verb == "gh":
            retval = self.gh(args)
        elif verb == "aws":
            retval = self.aws(args)
        elif verb == "npm":
            retval = self.npm(args)
        elif verb == "vercel":
            retval = self.vercel(args)
        elif verb in EGRESS_READS and not self.writes_file:
            retval = self.fetch(verb, text, args)
        elif verb in READ_VERBS and not self.writes_file:
            retval = (True, f"{verb}: read-only")
        elif (verb in _VERSION_ONLY and not self.writes_file and len(args) == 1
              and _text(args[0], self.src) in _VERSION_ONLY[verb]):
            retval = (True, f"{verb} --version: read-only")
        elif (verb == "node" and not self.writes_file and len(args) == 2
              and _text(args[0], self.src) in ("--check", "-c")
              and (_literal_word(args[1], self.src) or "-")[0] != "-"):
            # Parses the one file and exits; no other option, so nothing is
            # preloaded and nothing runs.
            retval = (True, "node --check: read-only")
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
        if retval is None:
            # The directory this segment would run in, never the agent
            # process's (#182): 2.0.x's deny predicates read it, and a
            # `cd` to a target we could not resolve falls back to the
            # channel's root rather than to wherever this process sits.
            decision, reason = yolt_gate.classify(
                text, cwd=self.tracked or self.start_dir,
            )
            # Asked for the reason a card shows. This layer vouches by its own
            # rules, so a segment none of them covers parks.
            if retval is None:
                retval = (False, shadowed or (f"no grant rule: {verb}" if decision == "safe" else reason))
        if retval[0] and self.reads_only and not _read_grant(verb, retval[1]):
            # Checked on the grant this layer gave, never on a classifier
            # verdict, which cannot reach here as a grant anyway (#373).
            retval = (False, f"{retval[1]}: not a read, so not in a loop or a substitution")
        if retval[0]:
            self.reasons.append(retval[1])
            # A vercel grant reads .vercel/project.json now; a write elsewhere
            # in the same command runs before vercel does and can rewrite it
            # in between (#327). Reads and `cd` cannot.
            if verb not in ("vercel", "cd") and not retval[1].endswith("read-only"):
                self.other_effect = True
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
        if verb == "awk" and not all(
                a.type == "raw_string"
                or a.type in ("word", "number") and "\\" not in _text(a, self.src)
                for a in args):
            # The program is code: its text must be exactly the word awk gets.
            # Inside single quotes the shell changes nothing; a double-quoted
            # or concatenated word, or a bare word with an escape, it does.
            retval = (False, "awk: an argument is not a plain word or single-quoted string")
            return retval
        # The deny lists compare words, so they have to be the words the
        # command gets, not their spelling in the source. `date` counts its
        # positionals, so a glob that could become several words is refused.
        reader = _literal_word if verb == "date" else _arg_word
        texts = [reader(a, self.src) for a in args]
        if any(t is None for t in texts):
            retval = (False, f"{verb}: an argument takes shell rules to read")
            return retval
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
            word = _literal_word(a, self.src) if _static(a) else None
            if word is not None:
                texts.append(word)
            elif _static(a):
                retval = (False, f"{verb}: an argument takes shell rules to read")
                return retval
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
        if hit and self.unattended and _fetch_names_its_file(texts):
            # An unattended channel already writes its tree without a card
            # (#253), and the sandbox confines this write the same way. Only
            # `-o FILE`: a name taken from the URL or a response header is
            # still the server choosing it.
            retval = (True, f"{verb}: fetch to a host in allow_domains, -o to a named file")
            return retval
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
            word = _literal_word(args[0], self.src)
            # `~-` and `~+` are the previous and current directory, which a
            # literal reading would take for a relative path.
            known = word is not None and not (word.startswith("~") and word != "~"
                                              and not word.startswith("~/"))
            self.tracked = _resolve(word, self.tracked) if known else None
        else:
            self.tracked = None
        retval = (True, "cd")
        return retval

    def checked(self, why):
        """Narrow a commit grant by the channel's declared check (#238).

        Reads a witness; runs nothing. A channel with no `check_command` gets
        the three blast-radius predicates it always had.

        The command string goes in the grounds on purpose. The operator defines
        what "checked" means for a channel and this layer cannot judge the
        string -- `check_command: "true"` tightens nothing. Policing the value
        would be dishonest about which of us knows the project; printing it is
        not, so the log reads `check passed since last write: true` and a human
        can see the conjunct is vacuous."""
        cmd = (self.policy or {}).get("check_command")
        if not cmd:
            retval = (True, why)
            return retval
        if not (self.channel and self.thread_ts):
            retval = (False, f"{why}, but a check_command needs a thread to read")
            return retval
        ok, detail = trajectory.check_witness(
            trajectory.thread(self.channel, self.thread_ts), cmd)
        retval = (True, f"{why}, {detail}") if ok else (False, f"{why}, but {detail}")
        return retval

    def git(self, args):
        directory = self.tracked
        self._git_globbed = False
        sub = None
        rest = []
        config_override = False
        i = 0
        # Global options come before the subcommand: `-C <dir>` retargets,
        # `-c key=val` takes a value, anything else dashed is skipped. After
        # the subcommand every word is its own (`switch -c` is a branch, not
        # a config).
        # Set once the subcommand's own options have ended (#373).
        ended = False
        while i < len(args):
            a = args[i]
            if (a.start_byte, a.end_byte) in self._opaque:
                # A substitution `substitutions` accepted (#373). It must
                # follow the subcommand's own `--`: before the subcommand, git
                # takes `--` as the end of ITS options, and the words after it
                # would reach the subcommand as options.
                if not ended:
                    return (False, "git: command substitution not after the subcommand's own `--`")
                i += 1
                continue
            t = _literal_word(a, self.src) if _static(a) else None
            if sub is not None:
                # A pathspec may glob; the word is still never an option.
                globbed = t is None and _static(a) and _arg_word(a, self.src) is not None
                ended = ended or (t in _END_OF_OPTIONS
                                  and _frees_marker(rest[-1] if rest else sub))
                rest.append(_arg_word(a, self.src) if globbed else t)
                self._git_globbed = self._git_globbed or globbed
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
                if ok:
                    # A CONJUNCT, and it cannot be traded against the three
                    # above (#238). Those measure blast radius -- is this
                    # branch work, is it yours, is it reflog-recoverable. This
                    # one asks whether the thing being committed passes a check
                    # the operator named. They are orthogonal, so passing a
                    # check must never buy a commit on the default branch, and
                    # a channel with no check_command is exactly as gated as
                    # before.
                    ok, why = self.checked(why)
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
        elif sub == "config" and not self.writes_file:
            # Read strictly: a lookup and a set differ only in how many words
            # follow, so a word that could expand into two cannot be judged.
            strict = [_literal_word(a, self.src) if _static(a) else None
                      for a in args[len(args) - len(rest):]]
            why = _git_config_refusal(strict)
            retval = (False, why) if why else (True, "git config: read")
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
            # A word this cannot read could be the output flag.
            retval = ((False, f"git {sub}: an argument is not a literal")
                      if None in rest else (True, f"git {sub}: read-only"))
        elif sub is None:                 # `git -C <dir>` alone: nothing to vouch for
            retval = (False, "git: no subcommand")
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
        if None in rest or self._git_globbed:
            return (False, f"git {sub}: an argument is not a literal")
        # Options that pick the destination themselves, or name a program to
        # run for the transport. The remote read below would be the wrong one.
        risky = next((r for r in rest if r.split("=")[0] in _GIT_NET_RISKY
                      or (sub == "clone" and r in ("-u", "-c"))), None)
        if risky:
            return (False, f"git {sub}: option {risky.split('=')[0]}")
        name = next((r for r in rest if not r.startswith("-")), "origin")
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
            t = _literal_word(a, self.src) if _static(a) else None
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

    def npm(self, args):
        """`npm <cmd>` when NPM_READS names it. None otherwise, which parks."""
        words = self._words(args)
        retval = None
        if words and not self.writes_file and words[0] in NPM_READS:
            retval = (True, f"npm {words[0]}: read-only")
        return retval

    def vercel(self, args):
        """A vercel command inside this channel's `vercel` scope (#327), or None,
        which parks. Never names the token in a reason."""
        scope = self.policy.get("vercel")
        if not isinstance(scope, dict) or self.writes_file or self.tracked is None:
            return None
        # A host variable passed through is one this check never sees, and
        # VERCEL_ORG_ID / VERCEL_PROJECT_ID / VERCEL_TOKEN all retarget vercel.
        if any(str(n).upper().startswith("VERCEL_")
               for n in (self.policy.get("env_passthrough") or [])):
            return None
        parsed = self._vercel_argv(args)
        if parsed is None:
            return None
        words, teams, version, token = parsed
        if not words and version:
            return (True, "vercel --version: read-only")
        # Without a channel token the CLI falls back to the global login in
        # HOME -- the operator's own account, which no channel was given.
        if not _vercel_token_ok(token, self.policy):
            return None
        if not words:
            # A bare `vercel` deploys the current directory.
            words = ["deploy"]
        key2, key1 = tuple(words[:2]), (words[0],)
        if key2 in VERCEL_ACCOUNT_READS:
            return (True, f"vercel {' '.join(key2)}: read-only")
        org_id = scope.get("org_id")
        team = scope.get("team")
        if any(t.lower() != str(team or "").lower() for t in teams):
            return None
        if key2 in VERCEL_TEAM_READS:
            kind, rest = "team", words[2:]
        elif key2 in VERCEL_PROJECT_READS or key1 in VERCEL_PROJECT_READS:
            kind = "project"
            rest = words[2:] if key2 in VERCEL_PROJECT_READS else words[1:]
        elif key2 in VERCEL_PROJECT_WRITES or key1 in VERCEL_PROJECT_WRITES:
            if scope.get("writes") is not True:
                return None
            kind = "write"
            rest = words[2:] if key2 in VERCEL_PROJECT_WRITES else words[1:]
        else:
            return None
        projects = scope.get("projects") or {}
        names = {str(n).lower() for n in projects}
        ids = {str(i) for i in projects.values()}
        directory = self.tracked
        if words[0] == "deploy" and rest:
            # `vercel deploy <path>` reads that directory's link.
            if len(rest) != 1:
                return None
            directory = _resolve(rest[0], self.tracked)
            rest = []
        if words[0] == "deploy" and not _within(directory, self.start_dir):
            # A deploy uploads the directory. Outside the channel tree that is
            # a way to ship any readable file to a project this channel owns.
            return None
        env = self.policy.get("env") or {}
        link = _vercel_link(directory)
        if link is False:
            return None
        orgs = [o for o in (env.get("VERCEL_ORG_ID"), link and link[0]) if o]
        if any(o != org_id for o in orgs):
            return None
        team_known = bool(teams or orgs)
        if kind == "team":
            if rest or not team_known:
                return None
            # The team path read the link too (orgs above), so a write in the
            # same command must park it like any other vercel grant (#328 r2).
            self.vercel_seen = True
            return (True, f"vercel {' '.join(key2)}: read-only, team {team}")
        evidence = [p for p in (env.get("VERCEL_PROJECT_ID"), link and link[1]) if p]
        if any(p not in ids for p in evidence):
            return None
        if words[0] == "env":
            # `env add NAME [environment]`: variable names, not targets.
            rest = []
        if len(rest) > 1:
            return None
        # A deployment URL carries its team; a bare project name does not, and
        # the same name can exist in a team the token also reaches.
        url_named = False
        if rest:
            target = rest[0]
            if words[0] in _VERCEL_DEPLOYMENT_ARG:
                if _vercel_deployment_project(target, names, team) is None:
                    return None
                url_named = True
            elif words[0] in ("ls", "list") and target.lower() in names:
                if not team_known:
                    return None
            else:
                return None
        if not evidence and not rest:
            return None
        if not team_known and not url_named:
            return None
        self.vercel_seen = True
        what = "read-only" if kind == "project" else "granted write"
        return (True, f"vercel {' '.join(words[:2] if words[0] == 'env' else words[:1])}: "
                      f"{what}, in this channel's vercel scope")

    def _vercel_argv(self, args):
        """(words, team values, saw --version, token argument text or None)
        for a vercel argv, or None when any part of it cannot be read. Only the
        token's value may be dynamic; it is returned for `_vercel_token_ok` and
        never put in a reason."""
        words, teams, version, token = [], [], False, None
        pending = None
        for a in args:
            static = _static(a)
            raw = _text(a, self.src)
            if pending == "token":
                token = raw
                pending = None
                continue
            if not static:
                name = raw.split("=", 1)[0]
                if name in _VERCEL_TOKEN_FLAGS and "=" in raw:
                    token = raw.split("=", 1)[1]
                    continue
                return None
            t = _unquote(raw)
            if pending == "team":
                teams.append(t)
                pending = None
                continue
            if pending == "value":
                pending = None
                continue
            if t.startswith("-"):
                name, eq, value = t.partition("=")
                if name in _VERCEL_TOKEN_FLAGS:
                    if eq:
                        token = value
                    else:
                        pending = "token"
                elif name in _VERCEL_TEAM_FLAGS:
                    if eq:
                        teams.append(value)
                    else:
                        pending = "team"
                elif name in _VERCEL_VALUE_FLAGS:
                    pending = None if eq else "value"
                elif name in _VERCEL_FLAGS and not eq:
                    version = version or name in ("--version", "-v")
                else:
                    return None
            else:
                words.append(t)
        if pending is not None:
            return None
        retval = (words, teams, version, token)
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


def _vercel_link(directory):
    """(orgId, projectId) from `<directory>/.vercel/project.json`, None when
    there is no link, or False when there is one this cannot read -- including
    a monorepo `repo.json`, which links several projects at once (#327).

    The file is in the channel tree, which the agent may write, so it is never
    the policy. It is evidence of where vercel will go, and that is checked
    against the policy like any other target."""
    if directory is None:
        return False
    base = os.path.join(directory, ".vercel")
    if os.path.exists(os.path.join(base, "repo.json")):
        return False
    path = os.path.join(base, "project.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
        retval = (str(data["orgId"]), str(data["projectId"]))
    except (OSError, ValueError, KeyError, TypeError):
        retval = False
    return retval


_VERCEL_HASHED = re.compile(r"^(.+)-[a-z0-9]{9}$")
_VERCEL_TOKEN_VAR = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")


def _vercel_token_ok(token, policy):
    """A token this channel was given: one variable the channel's own `env`
    sets. Absent, empty, or any other expansion parks, because the CLI would
    then use the global login (#328). A literal parks too: it would sit in the
    command text, which the trajectory records and a Vercel token's shape may
    not be one the redactor knows (#328 r2)."""
    if token is None:
        return False
    value = _unquote(token.strip())
    m = _VERCEL_TOKEN_VAR.match(value)
    retval = bool(m) and bool((policy.get("env") or {}).get(m.group(1)))
    return retval


def _within(path, root):
    """True when `path` resolves inside `root`."""
    if path is None or root is None:
        return False
    p, r = os.path.realpath(path), os.path.realpath(root)
    retval = p == r or p.startswith(r + os.sep)
    return retval


def _vercel_deployment_project(target, names, team):
    """The allowed project a deployment URL belongs to, or None.

    Only Vercel's generated `<project>-<hash>-<team>.vercel.app` is read. A
    custom domain, a `dpl_` ID or a branch URL names no project unambiguously
    in its text, so it is unresolvable and parks."""
    host = target.split("://", 1)[-1].split("/", 1)[0].lower()
    suffix = ".vercel.app"
    if not team or not host.endswith(suffix):
        return None
    label = host[:-len(suffix)]
    tail = "-" + str(team).lower()
    if not label.endswith(tail):
        return None
    label = label[:-len(tail)]
    # Exactly `<name>-<9-char hash>`. A prefix match let `site` claim
    # `site-evil-<hash>`, a different project's deployment. The
    # `<name>-git-<branch>` form is not accepted: `site-git-x` is equally a
    # project named `site-git` deploying branch `x`, and nothing in the text
    # tells them apart.
    m = _VERCEL_HASHED.match(label)
    if m and m.group(1) in names:
        return m.group(1)
    return None


def check(command, policy, channel=None, thread_ts=None):
    """(granted, reason). `reason` lists every segment's grounds when granted,
    or the first refusal when not."""
    src = command.encode("utf-8")
    tree = tree_sitter.Parser(_LANG).parse(src)
    if tree.root_node.has_error:
        return (False, "command does not parse")
    walker = _Walker(src, policy_mod.cwd_for(policy), policy, channel, thread_ts)
    ok, why = walker.walk(tree.root_node)
    if ok and not walker.reasons:
        ok, why = (False, "empty command")
    if ok and walker.vercel_seen and walker.other_effect:
        ok, why = (False, "vercel in the same command as a write: the link it was "
                          "checked against could change before it runs")
    retval = (True, "; ".join(walker.reasons)) if ok else (False, why)
    return retval
