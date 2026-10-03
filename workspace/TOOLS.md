# TOOLS.md

## Running shell without a needless card

Read-only work should just run. Whether it does is decided by the **verb, not
your intent**: the grant layer runs a command uncarded only when it can prove
every part is a read. So reach for the verbs it already knows are reads.

- **Prefer:** `cat`, `ls`, `head`, `tail`, `wc`, `file`, `stat`, `grep`/`rg`,
  `jq`, `diff`, and the read-only git subcommands (`git log`, `git show`,
  `git status`, `git diff`, `git branch --list`, `git for-each-ref`). These run
  with no card.
- **Avoid, for a read:** an interpreter (`python3 -c`, `node -e`, `sh -c`,
  `bash -c`) and process substitution (`diff <(...)`). These ALWAYS park --
  even in an unattended channel, and even when all they do is read -- because
  the gate cannot see inside them and the sandbox holds the filesystem, not the
  network. A `python3` one-liner reading JSON is a card; `jq` over the same file
  is not.
- **The sandbox runs each command under `/bin/sh -c`, not bash.** `<(...)`,
  `[[ ]]` and other bashisms fail there even after they are approved, so an
  approved card can still error. Use a temp file or a plain pipe instead:
  `git show HEAD:app/x > /tmp/old && diff /tmp/old app/x`, not
  `diff <(git show HEAD:app/x) app/x`.
- Parsing JSON is `jq`. Reading a file is `cat`. Comparing two files is
  `diff a b` (two paths). Reserve an interpreter for when running code IS the
  task -- and expect that one to park.

This is not about dodging oversight: a genuinely mutating or out-of-scope
command still parks, and should. It is about not spending a human's attention on
a read you could have phrased as a read.

## Editing files without a needless card

Same rule for writes: the grant layer vouches by verb. An in-tree edit through
a file verb -- `cat > file <<'EOF'`, `tee`, `sed -i` -- runs with no card in any
channel. Reach for those.

`apply_patch` is the exception to know: it parks in an ordinary channel (a patch
can delete a file, which the uncarded write set deliberately excludes), and runs
uncarded only in an unattended channel. So in an attended channel, make a
multi-line edit with a `cat >` heredoc or `sed`, not `apply_patch` -- and never
reach for `python3 -c`/`node -e` to write a file, which parks for a worse reason.
