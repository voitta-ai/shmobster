"""A model reply as the final text the gateway takes (#336).

The gateway renders no Markdown and splits nothing: a text part is the text
people will see, with `styles` as ranges in UTF-16 code units, and a send over
the channel's limit is refused (422). So both jobs are the consumer's, and this
is where shmobster does them -- the model writes Markdown for Slack and for
Signal alike.

Only what Signal can show is kept: bold, italic, strikethrough and monospace.
A link becomes its text with the URL after it; a heading becomes a bold line;
a bullet becomes a dot. Everything else is left as written."""
import re

# Signal's limit is 2000 UTF-8 bytes (signal-cli cuts a longer body and
# attaches the rest), and the gateway prefixes the consumer's label before
# checking it, so a chunk leaves room for one. Style offsets are UTF-16 units.
LIMIT = 1900


def units(text):
    retval = len(text.encode("utf-16-le")) // 2
    return retval


def size(text):
    retval = len(text.encode("utf-8"))
    return retval


_INLINE = re.compile(
    r"`(?P<code>[^`\n]+)`"
    r"|\*\*(?P<bold>.+?)\*\*"
    r"|~~(?P<strike>.+?)~~"
    r"|(?<![\w*])\*(?![\s*])(?P<italic>.+?)(?<![\s*])\*(?![\w*])"
    r"|(?<![\w_])_(?![\s_])(?P<italic2>[^_]+?)(?<![\s_])_(?![\w_])"
    r"|\[(?P<ltext>[^\]\n]+)\]\((?P<url>[^)\s]+)\)"
)
_STYLE = {"bold": "BOLD", "strike": "STRIKETHROUGH", "italic": "ITALIC", "italic2": "ITALIC"}
_FENCE = re.compile(r"^\s*```")
_HEADING = re.compile(r"^#{1,6}\s+(.*)$")
_BULLET = re.compile(r"^(\s*)[-*+]\s+(?=\S)")


class _Out:
    def __init__(self):
        self.parts = []
        self.at = 0
        self.styles = []

    def add(self, text):
        self.parts.append(text)
        self.at += units(text)

    def style(self, start, style):
        if self.at > start:
            self.styles.append({"start": start, "length": self.at - start, "style": style})


def _inline(line, out):
    pos = 0
    for m in _INLINE.finditer(line):
        out.add(line[pos:m.start()])
        start = out.at
        kind = m.lastgroup if m.lastgroup != "url" else "ltext"
        if m.group("code") is not None:
            out.add(m.group("code"))
            out.style(start, "MONOSPACE")
        elif m.group("ltext") is not None:
            _inline(m.group("ltext"), out)
            if m.group("ltext") != m.group("url"):
                out.add(f" ({m.group('url')})")
        else:
            for name in _STYLE:
                if m.group(name) is not None:
                    kind = name
                    break
            _inline(m.group(kind), out)
            out.style(start, _STYLE[kind])
        pos = m.end()
    out.add(line[pos:])


def render(markdown):
    """Markdown -> (text, styles), styles in UTF-16 code units."""
    out = _Out()
    fenced = False
    for i, line in enumerate((markdown or "").split("\n")):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if out.parts:
            out.add("\n")
        if fenced:
            start = out.at
            out.add(line)
            out.style(start, "MONOSPACE")
            continue
        heading = _HEADING.match(line)
        if heading:
            start = out.at
            _inline(heading.group(1), out)
            out.style(start, "BOLD")
            continue
        line = _BULLET.sub(lambda b: b.group(1) + "• ", line)
        _inline(line, out)
    retval = ("".join(out.parts), out.styles)
    return retval


def _cut(text, limit):
    """Where to end the first chunk of `text` (a str index): the last paragraph
    break, else line break, else space, that keeps it within `limit` UTF-8
    bytes; else as much as fits, never inside a character."""
    end, total = 0, 0
    for i, ch in enumerate(text):
        total += size(ch)
        if total > limit:
            break
        end = i + 1
    else:
        return len(text)
    window = text[:end]
    for sep in ("\n\n", "\n", " "):
        at = window.rfind(sep)
        if at > 0:
            return at
    return end


def split(text, styles, limit=LIMIT):
    """(text, styles) -> [(chunk, chunk_styles)], each chunk within `limit`
    UTF-8 bytes, styles (UTF-16 units) clipped to their chunk and rebased."""
    retval = []
    while text:
        end = _cut(text, limit)
        chunk = text[:end].rstrip()
        rest = text[end:]
        skipped = len(rest) - len(rest.lstrip("\n "))
        base, size = 0, units(chunk)
        clipped = []
        for st in styles:
            a, b = max(st["start"], base), min(st["start"] + st["length"], size)
            if b > a:
                clipped.append({"start": a, "length": b - a, "style": st["style"]})
        if chunk:
            retval.append((chunk, clipped))
        consumed = units(text[:end]) + units(rest[:skipped])
        styles = [{"start": st["start"] - consumed, "length": st["length"], "style": st["style"]}
                  for st in styles if st["start"] + st["length"] > consumed]
        for st in styles:
            if st["start"] < 0:
                st["length"] += st["start"]
                st["start"] = 0
        text = rest[skipped:]
    return retval


def parts(markdown, limit=LIMIT):
    """A reply as gateway messages: one list of parts per message to send."""
    text, styles = render(markdown)
    retval = [[{"type": "text", "text": chunk, **({"styles": st} if st else {})}]
              for chunk, st in split(text, styles, limit)]
    return retval
