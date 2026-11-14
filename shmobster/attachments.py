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
import hashlib
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from . import config, policy, sandbox, spine

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


# Under the channel cwd (#372). The directory ignores itself (a `*` .gitignore
# inside it), so a `git add -A` in a checkout never commits a client's file,
# and the repo's own .gitignore is never touched.
SAVE_DIR = ".attachments"
_ID_OK = re.compile(r"^[A-Za-z0-9]{1,64}$")
_NAME_BAD = re.compile(r"[^A-Za-z0-9._ -]")
_NAME_MAX = 200


def _safe_name(name):
    """The Slack filename as one plain path component. The name is data from
    the event, so `../x`, `a/b` and a leading dot all come out as an ordinary
    file inside the attachment's own directory. A long name keeps its
    extension, so `cp`ing the file somewhere still yields a `.csv`."""
    base = _NAME_BAD.sub("_", name).lstrip(". ").rstrip(". ")
    if len(base) > _NAME_MAX:
        stem, ext = os.path.splitext(base)
        ext = ext if len(ext) <= 16 else ""
        base = stem[:_NAME_MAX - len(ext)].rstrip(". ") + ext
    retval = base or "file"
    return retval


def _dir_id(f, url):
    """The per-file directory: Slack's file id, or a hash of the url when the
    event carries no usable id."""
    fid = str(f.get("id") or "")
    retval = fid if _ID_OK.match(fid) else "u" + hashlib.sha256(url.encode()).hexdigest()[:16]
    return retval


def _open_dir(name, dir_fd):
    """Open (creating if needed) one directory under dir_fd without following
    a symlink. The channel can write its own cwd, so `.attachments` could be a
    link it planted; this process is not sandboxed, and following one would
    write wherever it pointed."""
    try:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
    except FileExistsError:
        pass
    retval = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    return retval


def _save(cwd, sub, name, blob):
    """Write blob to <cwd>/.attachments/<sub>/<name>, byte-identical, and
    return the absolute path. A repeat save of the same file id rewrites the
    file atomically, so the path always holds Slack's bytes; an edit belongs
    on a copy."""
    fds = []
    try:
        fds.append(os.open(cwd, os.O_RDONLY | os.O_DIRECTORY))
        fds.append(_open_dir(SAVE_DIR, fds[-1]))
        try:
            gi = os.open(".gitignore", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=fds[-1])
            with os.fdopen(gi, "w") as fh:
                fh.write("*\n")
        except FileExistsError:
            pass
        fds.append(_open_dir(sub, fds[-1]))
        # A random suffix, retried on a clash: two turns saving the same file id
        # at once, or a temp left by a killed process, must not block a save.
        for _ in range(8):
            tmp = f".{name}.{os.urandom(6).hex()}.tmp"
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fds[-1])
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError("no free temp file name")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
            os.replace(tmp, name, src_dir_fd=fds[-1], dst_dir_fd=fds[-1])
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=fds[-1])
            except OSError:
                pass
            raise
    finally:
        for fd in fds:
            os.close(fd)
    retval = os.path.join(SAVE_DIR, sub, name)
    return retval


def save_root(channel):
    """(cwd, None) where this conversation's attachments may be saved, or
    (None, reason) when they may not.

    Only a conversation whose policy (directly, or through its `link`) sets a
    `cwd` of its own gets one: every other DM and channel shares
    default_policy's or exec.cwd's,
    so one person's file would be readable from another's turn. And never
    inside this deployment's own code, runtime files or standing prompt --
    `exec.cwd` defaults to ".", which is the live checkout -- by the same
    lists the sandbox write-denies (#147, #174, self_roots)."""
    shared = (None, "this conversation has no working directory of its own, so it may "
                    "be shared with others")
    try:
        # Its own `cwd`, not just an entry: a routing-only entry (mirror, link to
        # one), an empty one or one without `cwd` resolves to the shared default.
        resolved = policy.resolve(channel)
        cwd = policy.cwd_for(resolved)
        real = os.path.realpath(cwd)
        common = {os.path.realpath(policy.cwd_for(config.DEFAULT_POLICY)),
                  os.path.realpath(os.path.expanduser(os.path.expandvars(config.EXEC_CWD)))}
    except Exception:  # noqa: BLE001 -- fail closed: no save, said as a note
        logging.exception("attachments: could not resolve this conversation's working directory")
        return shared
    if not resolved.get("cwd") or real in common:
        return shared
    try:
        # Inside a self root (the checkout, venv, runtime files), or AT the
        # directory holding a config, policy or spine file. Only "at" for the
        # latter: a config file can sit in $HOME, and "under $HOME" would refuse
        # every channel on the host.
        inside = (any(sandbox._under(real, os.path.realpath(r)) for r in sandbox.self_roots())
                  or real in {os.path.dirname(os.path.realpath(p))
                              for p in tuple(config.SELF_FILES) + tuple(spine.files())})
    except Exception:  # noqa: BLE001 -- fail closed: no save, said as a note
        logging.exception("attachments: could not work out shmobster's own roots")
        inside = True
    if inside:
        retval = (None, "this channel's working directory is inside shmobster's own files")
        return retval
    retval = (cwd, None)
    return retval


def _unsaved(name, why):
    """The model's line for a file it can read but has no saved copy of. Its
    own wording, not the could-not-read list: the content did arrive."""
    retval = {"type": "text", "text": (
        f"[attached file {name} was NOT saved to disk: {why}. There is no copy "
        f"to work from; do not retype it.]")}
    return retval


def to_parts(files, save_under=None, no_save=None):
    """Turn one message's `files` into (content_parts, notes).

    `notes` is every attachment we could not read and why -- surfaced to the
    user rather than swallowed, because silence here is exactly the bug that
    made #68 look like the model ignoring the question.

    With `save_under` (the channel cwd), each file that passed the caps is
    also written to disk byte-identical and the model is told its path (#372):
    a model that only sees the text has no way to put the bytes in a file but
    to retype them, which silently dropped rows. Same fetch, same caps, same
    Slack-only download. A save that fails, or `no_save` (the reason this
    conversation gets none, from save_root), is said to the model per file,
    never dropped (#68).
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
        if no_save:
            parts.append(_unsaved(name, no_save))
        elif save_under:
            try:
                path = _save(save_under, _dir_id(f, url), _safe_name(name), blob)
            except OSError as exc:
                logging.warning("could not save attachment %s: %s", name, exc)
                parts.append(_unsaved(name, exc.strerror or str(exc)))
                continue
            parts.append({"type": "text", "text": (
                f"[attached file {name} is saved byte-identical at {path}, relative "
                f"to the working directory ({len(blob)} bytes, sha256 "
                f"{hashlib.sha256(blob).hexdigest()}). Work from that path; copy it "
                f"before editing.]")})
    retval = (parts, notes)
    return retval
