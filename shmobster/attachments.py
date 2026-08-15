"""Slack file attachments -> model content parts (#68).

Slack never puts an attachment in the message text; it arrives as
`event["files"]`, which the loop used to drop on the floor. So a mention like
"can you read this:" with an image under it reached the model as those four
words and nothing else, and the honest answer was "there is nothing attached".

Two things about Slack file URLs are worth knowing before touching this:

- They are not public. The bot token has to ride along as a bearer header, and
  fetching one needs the `files:read` scope.
- An unauthorized fetch does NOT fail. Slack answers **200 with the HTML
  sign-in page**, so a naive reader hands the model a login form and calls it a
  PNG. The content-type check below is what turns that into an error.
"""
import base64
import logging
import urllib.error
import urllib.request

from . import config

_TIMEOUT = 20
# ponytail: one flat cap for every type; split per-mimetype only if it bites.
_MAX_BYTES = 5 * 1024 * 1024


def _fetch(url):
    """Download one Slack-hosted file as bytes, or raise."""
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {config.SLACK_BOT_TOKEN}"}
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        ctype = (resp.headers.get("content-type") or "").lower()
        blob = resp.read(_MAX_BYTES + 1)
    if ctype.startswith("text/html"):
        # Slack serves the sign-in page with a 200, so this is the only signal
        # that the token was not accepted (usually: files:read not granted).
        raise ValueError("got Slack's sign-in page instead of the file (files:read granted?)")
    if len(blob) > _MAX_BYTES:
        raise ValueError(f"larger than the {_MAX_BYTES} byte cap")
    retval = blob
    return retval


def _part(name, mime, blob):
    """One downloaded file as an OpenAI-style content part. LiteLLM translates
    `image_url` into each vendor's own image block, so a data: URI is the one
    shape that works across the waterfall."""
    if mime.startswith("image/"):
        b64 = base64.b64encode(blob).decode()
        retval = {
            "type": "image_url",
            "image_url": {"url": f"data:{mime};base64,{b64}"},
        }
    else:
        body = blob.decode("utf-8", "replace")
        retval = {"type": "text", "text": f"[attached file: {name}]\n{body}"}
    return retval


def to_parts(files):
    """Turn one message's `files` into (content_parts, notes).

    `notes` is every attachment we could not read and why -- surfaced to the
    user rather than swallowed, because silence here is exactly the bug that
    made #68 look like the model ignoring the question.
    """
    parts = []
    notes = []
    for f in files or []:
        name = f.get("name") or "file"
        mime = (f.get("mimetype") or "").lower()
        url = f.get("url_private_download") or f.get("url_private")
        if not url:
            notes.append(f"{name}: no download url in the event")
            continue
        if not (mime.startswith("image/") or mime.startswith("text/")):
            notes.append(f"{name}: unsupported type {mime or 'unknown'}")
            continue
        try:
            blob = _fetch(url)
        except (urllib.error.URLError, ValueError, OSError) as exc:
            logging.warning("could not fetch attachment %s: %s", name, exc)
            notes.append(f"{name}: {exc}")
            continue
        parts.append(_part(name, mime, blob))
    retval = (parts, notes)
    return retval
