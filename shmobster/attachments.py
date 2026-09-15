"""Slack file attachments -> model content parts (#68).

Slack never puts an attachment in the message text; it arrives as
`event["files"]`, which the loop used to drop on the floor. So a mention like
"can you read this:" with an image under it reached the model as those four
words and nothing else, and the honest answer was "there is nothing attached".

Two things about Slack file URLs are worth knowing before touching this:

- They are not public. The bot token has to ride along as a bearer header, and
  fetching one needs the `files:read` scope. That token is workspace-wide, so
  it goes only to slack.com and its subdomains, and only for as long as the
  redirect chain stays there (#153).
- An unauthorized fetch does NOT fail. Slack answers **200 with the HTML
  sign-in page**, so a naive reader hands the model a login form and calls it a
  PNG. The content-type check below is what turns that into an error.
"""
import base64
import logging
import urllib.error
import urllib.parse
import urllib.request

from . import config

_TIMEOUT = 20
# ponytail: one flat cap for every type; split per-mimetype only if it bites.
_MAX_BYTES = 5 * 1024 * 1024


def _is_slack(url):
    """True for a URL whose host is slack.com or a subdomain of it.

    The bearer is workspace-wide, so the question "may this URL have it" has to
    be asked of the URL rather than assumed from where it came: the download
    link arrives inside a Slack event, and an event is data."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    # https only: a workspace-wide bearer does not travel in the clear, and
    # Slack does not serve these over http anyway.
    retval = parts.scheme == "https" and (host == "slack.com" or host.endswith(".slack.com"))
    return retval


class _SlackOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """urlopen follows redirects by default and copies the request headers into
    the next hop -- including Authorization, to whatever host the redirect
    names (confirmed on this box's Python 3.14: a 302 to another host received
    the bearer). Slack normally controls these URLs, so the likelihood is low
    and the credential is workspace-wide, which is the wrong pair of odds to
    accept for free.

    Redirects within Slack still work, because a CDN hop is how a file download
    actually resolves; a redirect that leaves Slack fails instead of paying the
    token to whoever asked for it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_slack(newurl):
            raise urllib.error.HTTPError(
                newurl, code, "redirect off slack.com; not sending the bot token", headers, fp
            )
        retval = super().redirect_request(req, fp, code, msg, headers, newurl)
        return retval


_OPENER = urllib.request.build_opener(_SlackOnlyRedirect)


def _fetch(url):
    """Download one Slack-hosted file as bytes, or raise."""
    if not _is_slack(url):
        raise ValueError(f"not a slack.com url: {urllib.parse.urlsplit(url).hostname!r}")
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {config.SLACK_BOT_TOKEN}"}
    )
    with _OPENER.open(req, timeout=_TIMEOUT) as resp:
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
