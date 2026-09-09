"""Skill loading (#74): make skillz-format `SKILL.md` files usable by the agent.

A skill is a directory holding `SKILL.md` with YAML frontmatter (`name`,
`description`) and a Markdown body -- the format the
[skillz](https://github.com/voitta-ai/skillz) catalog already uses for the
`claude` and `codex` hosts. Shmobster is a third host, and reads the same files
unchanged.

Two-stage disclosure, because the standing prompt is paid on every turn by every
vendor in the waterfall: the system prompt carries one short line per skill
(name + first sentence of the description), and the model calls `load_skill` to
pull a full body only when it decides one is relevant. Full descriptions inline
would be ~25KB of standing cost for a catalog this size; names alone would never
be searched for.

Sources are explicit directories from config (`skills.paths`), scanned at boot.
Earlier paths win a name collision, so a local/private catalog can shadow the
public one. `reload()` re-scans without a restart."""
import logging
import os

import yaml

from . import config, policy as policy_mod

_SUMMARY_MAX = 150
_BODY_MAX = 20000

_INDEX = {}      # name -> {"name", "summary", "path"}
_SHADOWED = []   # (name, path) entries a higher-precedence path already claimed


def _parse(path):
    """Return (frontmatter dict, body) for a SKILL.md, or (None, None) if it has
    no parseable `---` frontmatter block."""
    try:
        with open(path, "r") as f:
            text = f.read()
    except OSError:
        retval = (None, None)
        return retval
    retval = _parse_text(text)
    return retval


def _parse_text(text):
    """(frontmatter dict, body) for SKILL.md text, or (None, None). Split from
    _parse so a draft that has not been written anywhere yet (#129) is checked
    by the same rules a file on disk is."""
    if not text.startswith("---"):
        retval = (None, None)
        return retval
    parts = text.split("---", 2)
    if len(parts) < 3:
        retval = (None, None)
        return retval
    try:
        meta = yaml.safe_load(parts[1])
    except yaml.YAMLError:
        retval = (None, None)
        return retval
    if not isinstance(meta, dict):
        retval = (None, None)
        return retval
    retval = (meta, parts[2].strip())
    return retval


def _summarize(description):
    """First sentence of the description, capped. Skill descriptions are written
    for a host that injects them whole; here they are a menu line."""
    text = " ".join(str(description or "").split())
    if not text:
        retval = ""
        return retval
    head, sep, _rest = text.partition(". ")
    if sep and len(head) + 1 <= _SUMMARY_MAX:
        retval = head + "."
        return retval
    if len(text) <= _SUMMARY_MAX:
        retval = text
        return retval
    retval = text[: _SUMMARY_MAX - 3].rstrip() + "..."
    return retval


def _scan_dir(root, index, shadowed):
    """Add every `<root>/*/SKILL.md` to index. A name already present came from
    an earlier (higher-precedence) path and is kept."""
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return
    for entry in entries:
        path = os.path.join(root, entry, "SKILL.md")
        if not os.path.isfile(path):
            continue
        meta, _body = _parse(path)
        if meta is None:
            continue
        name = str(meta.get("name") or entry).strip()
        if not name:
            continue
        if name in index:
            shadowed.append((name, path))
            continue
        index[name] = {
            "name": name,
            "summary": _summarize(meta.get("description")),
            "path": path,
        }


def reload():
    """Re-scan every configured skills path into the module index. Returns the
    number of skills indexed."""
    global _INDEX, _SHADOWED
    index, shadowed = {}, []
    for raw in config.SKILL_PATHS:
        root = os.path.expanduser(os.path.expandvars(raw))
        _scan_dir(root, index, shadowed)
    _INDEX, _SHADOWED = index, shadowed
    retval = len(_INDEX)
    return retval


def channel_paths(channel):
    """The channel policy's own `skills` directories (#130), expanded like
    allow_read: `~` and $VARS, a relative entry against the channel cwd.

    An entry that resolves under the channel's own WRITABLE roots -- the tree,
    its worktrees sibling, the temp dir, the caches, allow_write -- is refused
    with a warning, not scanned. A skill is standing instructions, and the
    grant layer (#117) runs in-tree writes without a card: a skills dir inside
    the tree would let one granted `cat > skills/x/SKILL.md` become next
    turn's prompt, skipping the PR gate that is the whole promotion story
    (#129). Learned skills live in the read-only catalog clone outside every
    channel tree; realpath first, so a symlink into the tree does not slip
    the check."""
    from . import sandbox  # deferred: sandbox imports policy, not skills
    pol = policy_mod.resolve(channel) if channel else {}
    base = policy_mod.cwd_for(pol)
    writes, _reads, _deny = sandbox.roots(pol)
    out = []
    for raw in (pol.get("skills") or []):
        path = os.path.expanduser(os.path.expandvars(str(raw)))
        if not os.path.isabs(path):
            path = os.path.join(base, path)
        path = os.path.realpath(path)
        writable = next((w for w in writes if path == w or path.startswith(w + os.sep)), None)
        if writable:
            logging.warning(
                "skills: %s ignores its skills entry %r -- it resolves under the "
                "writable root %s, where a granted write could plant instructions; "
                "point it at the catalog clone instead", channel, raw, writable)
            continue
        out.append(path)
    retval = out
    return retval


def view(channel=None):
    """The index this channel sees: the global catalogs, then its own dirs.
    Global entries win a name collision, the same order rule as skills.paths.
    The channel dirs are scanned on the call, not cached: a channel has a
    handful of skills, a merge lands between turns, and a policy edit must
    take effect without a reload -- the global index stays boot-time."""
    index = dict(_INDEX)
    shadowed = []
    for root in channel_paths(channel):
        _scan_dir(root, index, shadowed)
    retval = index
    return retval


def names(channel=None):
    retval = sorted(view(channel)) if channel else sorted(_INDEX)
    return retval


def shadowed():
    retval = list(_SHADOWED)
    return retval


def prompt_block(channel=None):
    """The standing menu for the system prompt -- empty string when no skills are
    configured, so an instance without them pays nothing."""
    index = view(channel)
    if not index:
        retval = ""
        return retval
    lines = [
        "## Skills",
        "",
        "Reusable procedures written for this kind of work. When a request "
        "matches one, call load_skill(name) and follow it instead of improvising; "
        "the line here is only a label, the body has the actual steps.",
        "",
    ]
    for name in sorted(index):
        summary = index[name]["summary"]
        lines.append(f"- {name}: {summary}" if summary else f"- {name}")
    retval = "\n".join(lines)
    return retval


def load(name, channel=None):
    """Return a skill's body text, or a message naming the near misses."""
    key = str(name or "").strip()
    index = view(channel)
    entry = index.get(key)
    if entry is None:
        near = [n for n in sorted(index) if key and key.lower() in n.lower()]
        hint = f" Closest: {', '.join(near[:5])}." if near else ""
        retval = f"no such skill: {key!r}.{hint}"
        return retval
    meta, body = _parse(entry["path"])
    if meta is None:
        retval = f"skill {key} could not be read from {entry['path']}"
        return retval
    if len(body) > _BODY_MAX:
        body = body[:_BODY_MAX] + "\n...[truncated]"
    retval = f"# skill: {key}\n(source: {entry['path']})\n\n{body}"
    return retval


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "load_skill",
            "description": (
                "Read the full text of a skill listed under '## Skills' in your "
                "system prompt. Call this before doing work the skill covers, then "
                "follow its steps. One skill per call, by exact name."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Skill name exactly as listed under '## Skills'.",
                    }
                },
                "required": ["name"],
            },
        },
    }
]

NAMES = {t["function"]["name"] for t in TOOLS}


def dispatch(name, args, channel=None):
    if name == "load_skill":
        retval = load(args.get("name", ""), channel)
    else:
        retval = f"unknown skill tool: {name}"
    return retval
