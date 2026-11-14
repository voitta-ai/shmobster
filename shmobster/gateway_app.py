"""voitta-gateway ingest (#336): Signal, and whatever else the gateway carries,
as a second door into the same agent, beside Slack.

The gateway owns the transport. It holds the one signal-cli process for the
shared account, decides which messages are addressed to this agent, and hands
over only those. This module polls them, runs each as a turn, and posts the
answer back as final text. The cross-cutting pieces a new ingest must wire
(CLAUDE.md, "Adding an ingest mode") are here too:
- approval cards, answered in text;
- the resume after a resolved request;
- skill proposals;
- the announcement, through slack_app's fan-out.

Signal has no threads, so one conversation is one thread to approvals.

Channel ids are `<medium>:<label>` for a group listed in the gateway's
conversations map, and `<medium>:id:<conversation_id>` for anything else (a
DM). User ids are `<medium>:<sender id>`, which is what `trusted_users` lists.
A sender id is an account identifier, so it is never put in a prompt or a
reply: identity.mention shows the name the gateway reported instead.

Approvals are text, and they are not the model's call. A trusted user's whole
message reading `approve <id>` or `deny <id>` resolves that request here, the
way a button click does on Slack. Anything else is a turn, in which the model
can still call approve_command, under the same trusted-user check."""
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import admin_tools, approvals, config, gateway_text, handler, identity, policy, proposals, redact, state
from .surface import Surface

_THREAD = "main"            # Signal has no threads: a conversation is one thread
_CURSOR = "gateway_cursor"  # the poll position, persisted on every page (state.py)
_HISTORY = 25
_CARD_TRIES = 3
# Only for command output now; cards are bounded by _card_command below.
_CARD_COMMAND_MAX = 20000
_APPROVAL = re.compile(r"^\s*(approve|deny)\s+\[?([\w-]+)\]?\s*[.!]?\s*$", re.IGNORECASE)

_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="gateway-turn")
# Approvals get their own lane, so `approve <id>` never waits behind long turns.
_approvals_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="gateway-approve")
_CONVERSATIONS = {}         # channel -> gateway conversation_id, for history on resume
_MIRRORED = identity.MIRRORED   # marks a mirrored post, so history never reads it as the agent's own
_SEEN = {}
_SEEN_LOCK = threading.Lock()
_slack_post = None          # set by start(): posts a mirrored line into a Slack channel


def _call(method, path, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        config.GATEWAY_URL.rstrip("/") + path, data=data, method=method,
        headers={"Authorization": f"Bearer {config.GATEWAY_TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        retval = json.loads(resp.read() or b"{}")
    return retval


def channel_of(data):
    medium = data.get("channel", "gateway")
    if data.get("conversation"):
        retval = f"{medium}:{data['conversation']}"
    else:
        retval = f"{medium}:id:{data['conversation_id']}"
    return retval


def _target(channel):
    rest = channel.partition(":")[2]
    if rest.startswith("id:"):
        retval = {"conversation_id": rest[3:]}
    else:
        retval = {"conversation": rest}
    return retval


_MARKER = re.compile(r"^:robot_face: \[agent[^\]]*\]\s*")
_SLACK_MENTION = re.compile(r"<[@!][A-Za-z0-9|^]+>")
_SHORTCODES = {":warning:": "\u26a0\ufe0f", ":no_entry:": "\u26d4", ":hourglass:": "\u23f3",
               ":information_source:": "\u2139\ufe0f", ":white_check_mark:": "\u2705",
               ":lock:": "\U0001F512", ":robot_face:": "\U0001F916"}


def for_signal(text):
    """Slack-isms out: the agent marker (the gateway prefixes its label), Slack
    member ids, which mean nothing here and are not Signal members' business,
    and the shortcodes Signal would show literally."""
    text = _MARKER.sub("", text or "")
    text = _SLACK_MENTION.sub("someone on Slack", text)
    for code, emoji in _SHORTCODES.items():
        text = text.replace(code, emoji)
    return text


def unsigned(text):
    """The text without a leading "<label>:" signature. The gateway signs every
    message with the agent's label, so one the model wrote too ("Cosima: Cosima:
    ...") is dropped, and the agent's own lines in history are shown unsigned so
    the model has no signature to copy."""
    label = config.AGENT_LABEL
    retval = re.sub(rf"^(?:\s*[*_]*{re.escape(label)}[*_]*\s*:[*_]*\s*)+", "", text or "",
                    flags=re.IGNORECASE) if label else (text or "")
    return retval


def send(channel, markdown, reply_to=None, key=None, raw=None, force=False):
    """Post a Markdown reply as final text, split to Signal's limit. Returns
    "ok", "retry" (may pass), "rejected" (the gateway refused it for good) or
    "withheld" (the group is not closed; see below).
    The first piece quotes `reply_to`, so a reply in a shared group stays this
    agent's: the gateway routes the answer to a quote back to whoever sent the
    quoted message. With `key`, each piece is idempotent, so posting the same
    thing again does not repeat the pieces that already went out. With `raw`,
    a (text, styles) pair is sent exactly as given: no Markdown is read.

    Nothing reaches a Signal group that is not closed (CLAUDE.md), whatever the
    path -- a reply, command output after an approval, a card, an alert -- so
    the check is here, and a withheld post returns "withheld": not a gateway
    refusal, so nothing treats it as a reason to carry a task on. Only the
    refusal itself is `force`d."""
    if not force and _group(channel) is not None and not _may_post(channel):
        return "withheld"
    retval = "ok"
    if raw:
        pieces = gateway_text.raw_parts(*raw)
    else:
        plain = unsigned(for_signal(markdown)).replace(_MARK, "")   # after the marker is gone
        text, ids = _to_mentions(channel, plain)
        pieces = gateway_text.parts(text)
        marks = sum(p.get("text", "").count(_MARK) for parts in pieces for p in parts)
        if marks != len(ids):             # rendering moved or dropped one: no mention beats a wrong one
            pieces, ids = gateway_text.parts(plain), []
        pieces = _attach_mentions(pieces, ids)
    for i, parts in enumerate(pieces):
        body = {"to": _target(channel), "parts": parts}
        if reply_to and i == 0:
            body["reply_to"] = reply_to
        if key:
            body["idempotency_key"] = f"{key}:{i}"
        try:
            _call("POST", "/v1/messages", body)
        except urllib.error.HTTPError as exc:
            logging.warning("gateway: send to %s refused: %s %s", channel, exc.code, _error_code(exc))
            if exc.code < 500 and exc.code != 429:
                return "rejected"
            retval = "retry"
        except Exception as exc:  # noqa: BLE001
            logging.warning("gateway: send to %s failed: %s", channel, type(exc).__name__)
            retval = "retry"
    return retval


_CARD_BUDGET = 1500   # bytes of command on a card: with its head and tail lines, one message


def _card_command(cmd):
    """The command as the card shows it, always within one Signal message. Split
    across messages, the cut points would hide whether a newline or a space stood
    there, and two different commands could show the same card (#386 review). Too
    long for one message: its head and tail exactly as written, and in between a
    line no command contains, saying how much is not shown."""
    if gateway_text.size(cmd) <= _CARD_BUDGET:
        return cmd
    half = _CARD_BUDGET // 2 - 100
    head, tail = _bytes_prefix(cmd, half), _bytes_suffix(cmd, half)
    hidden = gateway_text.size(cmd) - gateway_text.size(head) - gateway_text.size(tail)
    retval = (f"{head}\n\u2702\ufe0f [{hidden} bytes of this command are not shown here: read the whole "
              f"command on the host before approving]\n{tail}")
    return retval


def _bytes_prefix(text, limit):
    out, used = [], 0
    for ch in text:
        used += gateway_text.size(ch)
        if used > limit:
            break
        out.append(ch)
    return "".join(out)


def _bytes_suffix(text, limit):
    return _bytes_prefix(text[::-1], limit)[::-1]


def _verbatim(before, body, after=""):
    """Text with `body` exactly as given and styled monospace: a command on a card
    must read as it will run, so nothing in it is taken for Markdown (#386 review)."""
    head = f"{before}\n" if before else ""
    text = f"{head}{body}\n{after}" if after else f"{head}{body}"
    styles = ([{"start": gateway_text.units(head), "length": gateway_text.units(body), "style": "MONOSPACE"}]
              if body else [])
    retval = (text, styles)
    return retval


def _error_code(exc):
    try:
        retval = json.loads(exc.read() or b"{}").get("error", {}).get("code", "")
    except Exception:  # noqa: BLE001
        retval = ""
    return retval


class GatewaySurface(Surface):
    kind = "gateway"

    def __init__(self, medium):
        self.medium = medium

    def location(self, channel, thread_ts):
        retval = (
            f"You are in a {self.medium.title()} conversation ({channel}), reached through "
            "voitta-gateway. It shows bold, italic, strikethrough and monospace, and "
            "nothing else: tables and headings arrive as plain lines, so keep answers "
            "short and plainly laid out. There are no Slack tools here."
        )
        return retval

    def self_line(self):
        account = f" (its profile name is {config.GATEWAY_ACCOUNT_NAME})" if config.GATEWAY_ACCOUNT_NAME else ""
        me = config.AGENT_LABEL or "you"
        retval = (
            f"On {self.medium.title()} you share one account with other agents{account}. People "
            f"reach you by @mentioning the account (you see that as @{me}), by saying your name, "
            "or by quoting one of your messages; the gateway hands you only the messages "
            f"addressed to you, so a message you are reading is for you. Your replies there are "
            f"signed \"{me}:\" for you -- do not sign them yourself, and if someone asks who "
            f"\"{config.GATEWAY_ACCOUNT_NAME or 'the account'}\" is, it is the shared account, "
            f"and you are {me} on it. `/help` lists the agents on the account, and "
            f"`/help {me.lower()}` describes you. Other people appear as @<name> (a name "
            "the operator gave them) or @Signal user <code>; write that same @name to "
            "mention one of them, and it reaches them as a real Signal mention."
        )
        return retval

    def post(self, channel, thread_ts, text, blocks=None):
        retval = send(channel, text) == "ok"
        return retval


_MARK = "\ufffc"


# ---------------------------------------------------------------- groups
# shmobster serves only CLOSED Signal groups: no group link, and only admins add
# members. That is decided, not configurable (CLAUDE.md, "Signal groups"). The
# gateway reports who is in a group and how open it is; this side refuses.

_MEMBERS = {}             # channel -> (fetched at, members report or None)
_MEMBERS_TTL = 60
_MEMBERS_FAIL_TTL = 5     # a failed read refuses only briefly, then is tried again
_LOCK = threading.Lock()
_REFUSED = {}             # channel -> when the last refusal was posted there
_REFUSE_EVERY = 3600
_AGENT_RUN = {}           # channel -> answers to agents in a row, since a person spoke
_AGENT_RUN_MAX = 3


def _group(channel):
    """The gateway label of a Signal group channel (`signal:<label>`), or None for
    a DM or any other medium: the closed-group rule is about Signal groups."""
    medium, _, rest = str(channel or "").partition(":")
    retval = None if (medium != "signal" or not rest or rest.startswith("id:")) else rest
    return retval


def members(channel, fresh=False):
    """The gateway's report on a group: members (id, admin, self, person_id,
    agent) and whether it is open. Cached a minute (a failure a few seconds);
    None when it could not be had or is not the expected shape, which serves
    nothing (fail closed)."""
    label = _group(channel)
    if label is None:
        return None
    now = time.time()
    with _LOCK:
        hit = _MEMBERS.get(channel)
    if hit and not fresh and now - hit[0] < (_MEMBERS_TTL if hit[1] is not None else _MEMBERS_FAIL_TTL):
        return hit[1]
    try:
        info = _call("GET", f"/v1/conversations/{urllib.parse.quote(label, safe='')}/members", timeout=10)
        if not (isinstance(info, dict) and isinstance(info.get("members"), list)
                and isinstance(info.get("open"), bool) and isinstance(info.get("reasons", []), list)):
            info = None
    except urllib.error.HTTPError as exc:
        logging.warning("gateway: could not list members of %s: %s %s", channel, exc.code, _error_code(exc))
        info = None
    except Exception as exc:  # noqa: BLE001
        logging.warning("gateway: could not list members of %s (%s)", channel, type(exc).__name__)
        info = None
    with _LOCK:
        _MEMBERS[channel] = (now, info)
    return info


def _member(channel, member_id):
    info = members(channel) if _group(channel) else None
    retval = next((m for m in (info or {}).get("members") or [] if m.get("id") == member_id), None)
    return retval


def _name(channel, member_id):
    """How a person in a conversation is named to the model and in mentions:
    the operator's name for them (`persons` in gateway.yaml), else a stable
    handle -- never the profile name they chose."""
    m = _member(channel, member_id)
    medium = str(channel or "signal").partition(":")[0] or "signal"
    retval = m["person_id"] if m and m.get("person_id") else identity.handle(f"{medium}:{member_id}")
    return retval


def _closed(channel):
    """None when this conversation may be served, else the reasons it may not.
    DMs pass; a group must be closed."""
    if _group(channel) is None:
        return None
    info = members(channel)
    if info is None:
        return ["I could not check who is in it"]
    retval = (info.get("reasons") or ["it is open"]) if info.get("open") else None
    return retval


def _may_post(channel):
    """Whether a post may go to this group now. A failed read is tried once more
    before the post is withheld, so a blip does not cost a closed group its answer."""
    why = _closed(channel)
    if why and members(channel) is None:
        time.sleep(1)
        members(channel, fresh=True)
        why = _closed(channel)
    if why:
        logging.warning("gateway: withheld a post to %s: %s", channel, "; ".join(why))
    retval = not why
    return retval


def _guard(fn, data, *args):
    """Run `fn(*args)` for a message, unless its group is open (refused, said at
    most hourly) or it comes from another agent that has had its run of answers
    since a person last spoke here (dropped, logged)."""
    channel = channel_of(data)
    why = _closed(channel)
    if why is not None:
        logging.warning("gateway: not serving %s: %s", channel, "; ".join(why))
        now = time.time()
        with _LOCK:
            due = now - _REFUSED.get(channel, 0) >= _REFUSE_EVERY
            if due:
                _REFUSED[channel] = now
        if due:
            send(channel, "I only work in closed groups, and I can't serve this one: "
                          + "; ".join(why) + ". A group admin can turn the group link off and set "
                          "Add members to Only admins; then ask me again.",
                 reply_to=data.get("message_id"), force=True)
        return
    if _group(channel) is not None:
        sender_id = (data.get("sender") or {}).get("id")
        sender = _member(channel, sender_id)
        if sender is None:                # joined since the cache was filled: ask again
            info = members(channel, fresh=True)
            sender = next((m for m in (info or {}).get("members") or [] if m.get("id") == sender_id), None)
        with _LOCK:
            if sender and sender.get("agent"):
                run = _AGENT_RUN.get(channel, 0)
                if run >= _AGENT_RUN_MAX:
                    logging.warning("gateway: not answering another agent in %s: %d answers in a row "
                                    "since a person spoke", channel, run)
                    return
                _AGENT_RUN[channel] = run + 1
            else:
                _AGENT_RUN[channel] = 0
    fn(*args)


def _to_mentions(channel, text):
    """`@<name>` in a reply, for a member of this group, becomes a real Signal
    mention: the U+FFFC Signal expects, plus the member ids in order."""
    info = members(channel) if _group(channel) else None
    names = {}
    for m in (info or {}).get("members") or []:
        if m.get("id") and not m.get("self"):
            names[_name(channel, m["id"])] = m["id"]
    ids = []
    text = text.replace(_MARK, "")        # only the mentions made here may carry one
    if names:
        alt = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
        pattern = re.compile(rf"(?<![\w/.@:])@({alt})(?![\w-])")
        def one(match):
            ids.append(names[match.group(1)])
            return _MARK
        # Not inside code (``` blocks, `spans`): a name there is text, not a mention.
        chunks = re.split(r"(```.*?```|`[^`\n]*`)", text, flags=re.S)
        text = "".join(c if i % 2 else pattern.sub(one, c) for i, c in enumerate(chunks))
    return text, ids


def _attach_mentions(pieces, ids):
    """Each U+FFFC left in the rendered parts, in order, gets the next id."""
    ids = list(ids)
    for parts in pieces:
        for part in parts:
            if part.get("type") != "text" or _MARK not in part.get("text", ""):
                continue
            at, found = 0, []
            for ch in part["text"]:
                if ch == _MARK and ids:
                    found.append({"start": at, "length": 1, "id": ids.pop(0)})
                at += len(ch.encode("utf-16-le")) // 2
            if found:
                part["mentions"] = found
    return pieces


def _mentioned(text, mentions, channel=None):
    """Signal puts each @mention on one U+FFFC. A mention of this account reads as
    @<agent label> -- the account's profile name is shared by every agent on it, and
    the model knows itself by its label -- and anyone else by the name _name gives
    them in this conversation (@someone when there is no conversation to ask)."""
    units = text.encode("utf-16-le")
    valid = [m for m in mentions if isinstance(m, dict) and type(m.get("start")) is int and m["start"] >= 0]
    for m in sorted(valid, key=lambda m: m["start"], reverse=True):
        at = m["start"]
        if units[2 * at:2 * at + 2] != _MARK.encode("utf-16-le"):
            continue
        if m.get("self"):
            name = f"@{config.AGENT_LABEL or 'me'}"
        else:
            name = f"@{_name(channel, m.get('id'))}" if channel and m.get("id") else "@someone"
        units = units[:2 * at] + name.encode("utf-16-le") + units[2 * at + 2:]
    retval = units.decode("utf-16-le").replace(_MARK, "@someone")
    return retval


def _text(data, channel=None, names=True):
    """The message as text: text parts, and voice notes by their transcript.
    `channel` names other people's mentions; an event carries its own. With
    `names` off (the poll thread's parsing) nobody is looked up."""
    if channel is None and names and data.get("conversation"):
        channel = channel_of(data)
    pieces, unread = [], []
    mentions = data.get("mentions") or []
    for p in data.get("parts") or []:
        if p.get("type") == "text":
            pieces.append(_mentioned(p.get("text", ""), mentions, channel))
            mentions = []                         # offsets are into the message's one text part
        elif p.get("transcript"):
            pieces.append(f"[voice note] {p['transcript']}")
        elif p.get("type") == "file":
            unread.append(p.get("filename") or p.get("content_type") or "a file")
    retval = "\n".join(pieces).strip()
    if unread:
        retval += "\n\n[attachments I could not read: " + "; ".join(unread) + "]"
    return retval


def _history(conversation_id, current, medium="signal", channel=None):
    """The conversation so far, labelled by speaker, as slack_app does for a
    thread. Best-effort: no history is a turn without context, not a failure."""
    try:
        q = urllib.parse.urlencode({"limit": _HISTORY})
        msgs = _call("GET", f"/v1/conversations/{conversation_id}/history?{q}").get("messages", [])
    except Exception:  # noqa: BLE001
        return None
    lines = []
    for m in msgs:
        if m.get("message_id") == current:
            continue
        sender = m.get("sender") or {}
        text = _text(m, channel)
        if sender.get("kind") == "self":
            consumer = sender.get("consumer")
            mine = consumer == config.GATEWAY_CONSUMER
            if mine:
                who, text = f"{config.AGENT_LABEL or 'me'} (me)", unsigned(text)
            elif consumer:
                who = f"{consumer} (another agent)"
            else:                         # the gateway's own reply, e.g. to /help
                who = "the gateway (this account's notice, not an agent)"
            if mine and _MIRRORED in text:
                who = "mirrored from Slack, not my words"
        else:
            # By the operator's name or a handle, and trust -- never the profile
            # name the sender chose (#336 review)
            user = f"{medium}:{sender.get('id')}"
            who = (_name(channel, sender.get("id")) if channel else identity.handle(user))
            who += " (another agent)" if channel and (_member(channel, sender.get("id")) or {}).get("agent") else ""
            who += " (trusted)" if admin_tools.is_trusted(user) else ""
        if text:
            lines.append(f"[{who}] {text}")
    retval = "\n".join(lines) or None
    return retval


def _unaddressed(text):
    """The text without how it was addressed: Signal's U+FFFC for an
    @mention, or the agent's name, so "@Ada approve <id>" is an approval."""
    names = [n for n in (config.AGENT_LABEL,) if n]
    lead = r"^[\s\ufffc,:]*(?:@?(?:" + "|".join(re.escape(n) for n in names) + r")\b[\s,:]*)*" if names else r"^[\s\ufffc,:]*"
    retval = re.sub(lead, "", text, flags=re.IGNORECASE)
    return retval


def _guarded(fn, *args):
    try:
        fn(*args)
    except Exception:
        logging.exception("gateway: %s failed", getattr(fn, "__name__", "task"))


def _first_time(message_id):
    with _SEEN_LOCK:
        if message_id in _SEEN:
            return False
        _SEEN[message_id] = None
        if len(_SEEN) > 500:
            del _SEEN[next(iter(_SEEN))]
    return True


_HELP = re.compile(r"^\s*/help\s+@?(\S+)\s*$", re.IGNORECASE)


def _help(data):
    """The channel when the message is `/help <this agent>`. Any other `/help x`
    goes to the model: a gateway that is older or not shared passes those on."""
    m = _HELP.match(_unaddressed(_text(data, names=False)))      # "@Ada /help ada" too
    me = {n.lower() for n in (config.AGENT_LABEL, config.GATEWAY_CONSUMER) if n}
    retval = channel_of(data) if m and m.group(1).lower() in me else None
    return retval


def _describe(channel, mid):
    """`/help <me>`, answered without the model: what this agent is, how to reach
    it, and what it may do in this conversation (its policy here)."""
    me = config.AGENT_LABEL or "this agent"
    pol = policy.resolve(channel)
    repos = ", ".join(pol.get("github_repos") or []) or "any repository its GitHub access reaches"
    # No paths: anyone the gateway lets in can ask, trusted or not.
    asks = ("runs some git, gh and file commands here without asking" if pol.get("unattended")
            else "asks first, with an approval card, before most commands that change something")
    lines = [
        "An assistant that answers questions and runs commands for this team.",   # the gateway signs it
        f"Reach it: start a message with \"{me.lower()}\", mention this account, or quote one of its messages.",
        f"Here its GitHub repositories are: {repos}. It {asks}.",
        "A card names a request id; a trusted person replies `approve <id>` or `deny <id>`.",
        "/help lists every agent on this account.",
    ]
    send(channel, redact.scrub("\n".join(lines)), reply_to=mid, key=f"reply:{mid}")


def _approval(data):
    """(approved, request id, channel, user, surface) when the message is a trusted
    user's `approve <id>` / `deny <id>`, else None."""
    medium = data.get("channel", "gateway")
    user = f"{medium}:{(data.get('sender') or {}).get('id')}"
    m = _APPROVAL.match(_unaddressed(_text(data, names=False)))
    if not (m and admin_tools.is_trusted(user)):
        return None
    retval = (m.group(1).lower() == "approve", m.group(2), channel_of(data), user, GatewaySurface(medium))
    return retval


def _turn(data):
    channel = channel_of(data)
    medium = data.get("channel", "gateway")
    sender = data.get("sender") or {}
    user = f"{medium}:{sender.get('id')}"
    _CONVERSATIONS[channel] = data["conversation_id"]
    surface = GatewaySurface(medium)
    text = _text(data)
    try:
        _call("POST", f"/v1/messages/{data['message_id']}/reactions", {"emoji": "\U0001F440"})
    except Exception:  # noqa: BLE001
        pass
    context = _history(data["conversation_id"], data["message_id"], channel=channel)
    try:
        reply = handler.handle(text, thread_context=context, channel=channel, thread_ts=_THREAD,
                               user_id=user, surface=surface)
    except Exception as exc:  # one short line; the exception goes to the log only (#352)
        logging.exception("gateway: handler failed: channel=%s message=%s", channel, data["message_id"])
        reply = handler.failure_line(exc)
    send(channel, reply, reply_to=data["message_id"], key=f"reply:{data['message_id']}")
    _post_pending(channel, surface)
    mirror_out(channel, identity.handle(user), text, reply)


def _resolve_text(approved, req_id, channel, user, surface):
    """`approve <id>` / `deny <id>` from a trusted user: what a click is on Slack."""
    req_id = approvals.canonical(req_id)
    req = approvals.acquire(req_id, channel)
    if req is None:
        if approvals.status(req_id, channel)[0] != "held":   # held: another surface reports it
            send(channel, f"[{req_id}] is not pending here: it was already acted on, it is from "
                          "before a restart, or it belongs to another conversation.")
        return
    ctx = {"user_id": user, "channel": channel, "thread_ts": _THREAD, "surface": surface}
    try:
        run = admin_tools.run_approved if approved else admin_tools.run_denied
        result = redact.scrub(run(req_id, req, ctx))
    finally:
        approvals.release(req_id)
    send(channel, None, raw=_verbatim("", result[:_CARD_COMMAND_MAX * 2]))
    _resume(channel, req_id, req, approved, result, user, surface)


def _resume(channel, req_id, req, approved, result, user, surface):
    """Carry the turn on after a request resolved (#169); handler.resume decides
    whether this is the moment."""
    try:
        cid = _CONVERSATIONS.get(channel)
        reply = handler.resume(req_id, approved, req.get("command", ""), result,
                               thread_context=_history(cid, None, channel=channel) if cid else None,
                               channel=channel, thread_ts=_THREAD,
                               user_id=user, surface=surface, requester=req.get("requester"))
        if reply is None:
            waiting = approvals.pending_in(channel, _THREAD)
            if waiting:
                send(channel, f"[{req_id}] is resolved, and this task is waiting on {waiting} more "
                              f"request{'s' if waiting > 1 else ''} here. It continues on its own "
                              "once the last one is answered.")
            return
        send(channel, reply)
        _post_pending(channel, surface)
    except Exception:
        logging.exception("gateway: could not resume after [%s]", req_id)


def _post_pending(channel, surface):
    """Cards for what the turn parked, as text a trusted user answers in text."""
    for req_id, req in approvals.claim_unsurfaced(channel, _THREAD):
        cmd = _card_command(redact.scrub(req["command"]))
        reason = f" ({redact.scrub(req['reason'])})" if req.get("reason") else ""
        # A refusal and a question must not look alike (#172)
        head = (f"\u26d4 REFUSED by the classifier -- approve only if you are sure [{req_id}]{reason}"
                if req.get("refused") else f"\U0001F512 Needs approval [{req_id}]{reason}")
        card = _verbatim(head, cmd, f"A trusted user replies \"approve {req_id}\" or \"deny {req_id}\".")
        if gateway_text.size(card[0]) > gateway_text.LIMIT:      # a reason long enough to push it over:
            short = (f"\u26d4 REFUSED by the classifier -- approve only if you are sure [{req_id}]"
                     if req.get("refused") else f"\U0001F512 Needs approval [{req_id}]")
            card = _verbatim(short, cmd, f"Reply \"approve {req_id}\" or \"deny {req_id}\".")   # one message
        if gateway_text.size(card[0]) > gateway_text.LIMIT:      # a card is never split (#386 review)
            _card_failed(channel, req_id, surface, rejected=True)
            continue
        outcome = send(channel, None, key=f"card:{req_id}", raw=card)
        if outcome == "withheld":         # the group is not closed: drop the request, carry nothing on
            approvals.withdraw(req_id)
            logging.warning("gateway: withdrew [%s]: %s is not closed", req_id, channel)
        elif outcome != "ok":
            _card_failed(channel, req_id, surface, rejected=outcome == "rejected")
    for key, prop in proposals.claim_unsurfaced(channel):
        card = redact.scrub(f"Worth a skill? [{key}] {prop['name']} -- {prop['why']}\n"
                            f"A trusted user can ask me to open it ({key}) or decline it.")
        if send(channel, card, key=f"proposal:{key}") != "ok":
            proposals.unsurface(key)


def _card_failed(channel, req_id, surface, rejected=False):
    """A card did not post: retry on the next turn when the failure may pass,
    up to _CARD_TRIES; withdraw it when the gateway refused it or the retries
    ran out, as slack_app does (#356), so it cannot hold the thread."""
    if not rejected and approvals.unsurface(req_id) < _CARD_TRIES:
        return
    if approvals.withdraw(req_id) is None:
        return
    send(channel, f"[{req_id}] needed approval, but its card could not be posted, so it was "
                  "withdrawn and did not run. Ask again if it is still needed.")
    outcome = approvals.take_deferred(channel, _THREAD)
    if outcome is not None:
        _resume(channel, outcome["req_id"], {"command": outcome["command"], "requester": outcome["requester"]},
                outcome["approved"], outcome["result"], outcome["user_id"], surface)


_STARTED = "gateway_started"   # message ids whose turn began, kept across restarts
_STARTED_MAX = 500


_STARTED_LOCK = threading.Lock()


def _begin(mid, started):
    """Record that this message's turn is starting, before anything runs. A turn
    that began is never run again after a restart -- not even one that ended the
    process -- while one still waiting in the queue is (#386 review)."""
    with _STARTED_LOCK:                   # append and save together: no older copy saved last
        started.append(mid)
        del started[:-_STARTED_MAX]
        state.put(_STARTED, list(started))


def _run(fn, mid, started, *args):
    _begin(mid, started)
    _guarded(fn, *args)


def _loop():
    """Poll, hand each message to a worker, and ack (persist the cursor) only
    up to the oldest message whose turn has not finished, so a restart re-reads
    what was still queued. Turns that had started are skipped on that re-read
    (`_STARTED`): at most once for anything that may have acted, at least once
    for the rest."""
    acked = fetched = state.get(_CURSOR) or "now"
    started = list(state.get(_STARTED) or [])
    inflight = []                         # [(event id, future or None)], in order
    while True:
        try:
            while inflight and (inflight[0][1] is None or inflight[0][1].done()):
                acked = inflight.pop(0)[0]
            if not inflight and fetched != acked:
                acked = fetched
            if acked != state.get(_CURSOR):
                state.put(_CURSOR, acked)     # persisting the cursor is the ack (gateway README)
            q = urllib.parse.urlencode({"after": fetched, "wait": 25, "types": "message.received"})
            body = _call("GET", f"/v1/events/poll?{q}", timeout=40)
            if not isinstance(body, dict):
                raise ValueError("poll answered with something other than an object")
            for e in body.get("events") or []:
                if not isinstance(e, dict) or not isinstance(e.get("data"), dict):
                    continue
                data, fut = e["data"], None
                mid = data.get("message_id")
                if (e.get("type") == "ai.voitta.message.received.v1" and isinstance(mid, str)
                        and mid not in started and _first_time(mid)):
                    approval = _approval(data)
                    # Every lane goes through _guard: no open group is served (CLAUDE.md).
                    if approval:                  # its own lane: never behind long turns
                        fut = _approvals_pool.submit(_run, _guard, mid, started, _resolve_text, data, *approval)
                    elif (help_in := _help(data)):   # no model: the same lane, it is as quick
                        fut = _approvals_pool.submit(_run, _guard, mid, started, _describe, data, help_in, mid)
                    else:
                        fut = _pool.submit(_run, _guard, mid, started, _turn, data, data)
                if isinstance(e.get("id"), str):
                    inflight.append((e["id"], fut))
            if isinstance(body.get("next"), str):
                fetched = body["next"]
        except Exception as exc:  # noqa: BLE001 -- this thread must not die (#66: deaf but alive)
            logging.warning("gateway: poll failed (%s); retrying", type(exc).__name__)
            time.sleep(5)


def start(slack_post=None):
    """Start polling the gateway in the background, when one is configured."""
    global _slack_post
    if not config.GATEWAY_URL:
        return False
    _slack_post = slack_post
    threading.Thread(target=_loop, name="gateway-poll", daemon=True).start()
    served = conversations(timeout=5)       # boot waits on this; a hung gateway must not stall it
    if served is not None:
        logging.info("gateway: serving %d listed conversation(s)", len(served))
        def report(channels):
            for channel in channels:
                why = _closed(channel)
                if why:
                    logging.warning("gateway: %s is not served until it is closed: %s", channel, "; ".join(why))
        threading.Thread(target=report, args=(served,), name="gateway-groups", daemon=True).start()
    for key, pol in sorted(config.CHANNEL_POLICIES.items()):
        if ":" not in key or ":id:" in key:
            continue
        if served is not None and key not in served:
            logging.warning("gateway: policy %s names a conversation the gateway does not route to "
                            "consumer %r (gateway.consumer must match the token's)", key, config.GATEWAY_CONSUMER)
        ignored = sorted(set(pol) - set(policy.ROUTING_KEYS)) if pol.get("link") else []
        if ignored:
            logging.warning("gateway: policy %s is linked to %s, so its %s are ignored",
                            key, pol["link"], ", ".join(ignored))
    return True


def conversations(timeout=30):
    """This agent's listed group conversations, as channel ids (`<medium>:<label>`),
    from the gateway, which owns them; None when it could not be asked. Only
    those naming this consumer, or open to all: an admin token is shown every
    group on the account, and this agent must not announce into another's."""
    try:
        body = _call("GET", "/v1/conversations", timeout=timeout)
        retval = [f"{c['channel']}:{c['label']}" for c in body.get("conversations") or []
                  if not c.get("consumers") or config.GATEWAY_CONSUMER in c["consumers"]]
    except urllib.error.HTTPError as exc:
        # 404 here is a gateway older than GET /v1/conversations (voitta-gateway#16)
        logging.warning("gateway: could not list conversations: %s %s", exc.code, _error_code(exc))
        retval = None
    except Exception as exc:  # noqa: BLE001
        logging.warning("gateway: could not list conversations (%s)", type(exc).__name__)
        retval = None
    return retval


def announce(text):
    """Post into every listed gateway conversation; how many accepted it."""
    if not config.GATEWAY_URL:                      # no gateway: nothing to ask, nothing to log
        return 0
    me = config.AGENT_LABEL or "an agent"
    text += (f"\n\n_I'm {me}, one of the agents on this account. Start a message with "
             f"\"{me.lower()}\" or mention the account; /help lists who's here._")
    retval = sum(1 for channel in conversations() or []
                 if not _closed(channel) and send(channel, text) == "ok")   # never into an open group
    return retval


# ---------------------------------------------------------------- mirroring
# Off unless a conversation's entry sets `mirror`. Only the question and the
# final answer cross; cards stay where they were posted, so each request is
# answered in the one place it can be resolved.

def mirror_out(channel, who, question, answer):
    """A gateway turn, copied into the Slack channel its conversation links to."""
    conv = config.CHANNEL_POLICIES.get(channel) or {}
    if not (conv.get("mirror") and conv.get("link") and _slack_post):
        return
    medium = channel.partition(":")[0].title()
    try:
        # Untrusted text into Slack under the agent's own bot: escaped, so it cannot
        # @channel or disguise a link, and marked, so history never reads it as mine.
        _slack_post(conv["link"], f"{_MIRRORED} from {medium}: _{who} asked:_ {_slack_escape(redact.scrub(question))}")
        _slack_post(conv["link"], f"{_MIRRORED} from {medium}: {answer}")
    except Exception:
        logging.exception("gateway: could not mirror into %s", conv["link"])


def _slack_escape(text):
    retval = (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return retval


def mirror_in(slack_channel, question, answer):
    """A Slack turn, copied into every gateway conversation linked to it."""
    targets = [channel for channel, conv in config.CHANNEL_POLICIES.items()
               if ":" in channel and conv.get("mirror") and conv.get("link") == slack_channel]
    if not targets:
        return
    question = redact.scrub(re.sub(r"<@\w+>", "", question or "").strip())
    for channel in targets:
        if _closed(channel):              # never into an open group (CLAUDE.md)
            logging.warning("gateway: not mirroring into %s: it is not closed", channel)
            continue
        send(channel, f"{_MIRRORED} from Slack: _someone asked:_ {question}")
        send(channel, f"{_MIRRORED} from Slack: {answer}")
