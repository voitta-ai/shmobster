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


def send(channel, markdown, reply_to=None, key=None, raw=None):
    """Post a Markdown reply as final text, split to Signal's limit. Returns
    "ok", "retry" (may pass) or "rejected" (the gateway refused it for good).
    The first piece quotes `reply_to`, so a reply in a shared group stays this
    agent's: the gateway routes the answer to a quote back to whoever sent the
    quoted message. With `key`, each piece is idempotent, so posting the same
    thing again does not repeat the pieces that already went out. With `raw`,
    a (text, styles) pair is sent exactly as given: no Markdown is read."""
    retval = "ok"
    pieces = gateway_text.raw_parts(*raw) if raw else gateway_text.parts(for_signal(markdown))
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
            f"and you are {me} on it."
        )
        return retval

    def post(self, channel, thread_ts, text, blocks=None):
        retval = send(channel, text) == "ok"
        return retval


_MARK = "\ufffc"


def _mentioned(text, mentions):
    """Signal puts each @mention on one U+FFFC. A mention of this account reads as
    @<agent label> -- the account's profile name is shared by every agent on it, and
    the model knows itself by its label -- and anyone else as @someone."""
    units = text.encode("utf-16-le")
    valid = [m for m in mentions if isinstance(m, dict) and type(m.get("start")) is int and m["start"] >= 0]
    for m in sorted(valid, key=lambda m: m["start"], reverse=True):
        at = m["start"]
        if units[2 * at:2 * at + 2] != _MARK.encode("utf-16-le"):
            continue
        name = f"@{config.AGENT_LABEL or 'me'}" if m.get("self") else "@someone"
        units = units[:2 * at] + name.encode("utf-16-le") + units[2 * at + 2:]
    retval = units.decode("utf-16-le").replace(_MARK, "@someone")
    return retval


def _text(data):
    """The message as text: text parts, and voice notes by their transcript."""
    pieces, unread = [], []
    mentions = data.get("mentions") or []
    for p in data.get("parts") or []:
        if p.get("type") == "text":
            pieces.append(_mentioned(p.get("text", ""), mentions))
            mentions = []                         # offsets are into the message's one text part
        elif p.get("transcript"):
            pieces.append(f"[voice note] {p['transcript']}")
        elif p.get("type") == "file":
            unread.append(p.get("filename") or p.get("content_type") or "a file")
    retval = "\n".join(pieces).strip()
    if unread:
        retval += "\n\n[attachments I could not read: " + "; ".join(unread) + "]"
    return retval


def _history(conversation_id, current, medium="signal"):
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
        text = _text(m)
        if sender.get("kind") == "self":
            mine = sender.get("consumer") in (None, config.GATEWAY_CONSUMER)
            who = f"{config.AGENT_LABEL or 'me'} (me)" if mine else f"{sender.get('consumer')} (another agent)"
            if mine and _MIRRORED in text:
                who = "mirrored from Slack, not my words"
        else:
            # By handle and trust, never the profile name the sender chose (#336 review)
            user = f"{medium}:{sender.get('id')}"
            who = identity.handle(user) + (" (trusted)" if admin_tools.is_trusted(user) else "")
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


def _approval(data):
    """(approved, request id, channel, user, surface) when the message is a trusted
    user's `approve <id>` / `deny <id>`, else None."""
    medium = data.get("channel", "gateway")
    user = f"{medium}:{(data.get('sender') or {}).get('id')}"
    m = _APPROVAL.match(_unaddressed(_text(data)))
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
    context = _history(data["conversation_id"], data["message_id"])
    try:
        reply = handler.handle(text, thread_context=context, channel=channel, thread_ts=_THREAD,
                               user_id=user, surface=surface)
    except Exception as exc:  # one clear message, scrubbed (#72)
        logging.exception("gateway: handler failed")
        reply = redact.scrub(f"shmobster error: {exc}")
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
                               thread_context=_history(cid, None) if cid else None,
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
        if outcome != "ok":
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
                    if approval:                  # its own lane: never behind long turns
                        fut = _approvals_pool.submit(_run, _resolve_text, mid, started, *approval)
                    else:
                        fut = _pool.submit(_run, _turn, mid, started, data)
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
    retval = sum(1 for channel in conversations() or [] if send(channel, text) == "ok")
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
        send(channel, f"{_MIRRORED} from Slack: _someone asked:_ {question}")
        send(channel, f"{_MIRRORED} from Slack: {answer}")
