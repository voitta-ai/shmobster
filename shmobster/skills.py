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
import os

import yaml

from . import config

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


def names():
    retval = sorted(_INDEX)
    return retval


def shadowed():
    retval = list(_SHADOWED)
    return retval


def prompt_block():
    """The standing menu for the system prompt -- empty string when no skills are
    configured, so an instance without them pays nothing."""
    if not _INDEX:
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
    for name in sorted(_INDEX):
        summary = _INDEX[name]["summary"]
        lines.append(f"- {name}: {summary}" if summary else f"- {name}")
    retval = "\n".join(lines)
    return retval


def load(name):
    """Return a skill's body text, or a message naming the near misses."""
    key = str(name or "").strip()
    entry = _INDEX.get(key)
    if entry is None:
        near = [n for n in sorted(_INDEX) if key and key.lower() in n.lower()]
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


def dispatch(name, args):
    if name == "load_skill":
        retval = load(args.get("name", ""))
    else:
        retval = f"unknown skill tool: {name}"
    return retval
