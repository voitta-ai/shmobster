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

from . import admin_tools, approvals, config, gateway_text, handler, identity, proposals, redact, state
from .surface import Surface

_THREAD = "main"            # Signal has no threads: a conversation is one thread
_CURSOR = "gateway_cursor"  # the poll position, persisted on every page (state.py)
_HISTORY = 25
_CARD_TRIES = 3
# Most of a long command fits on a card; the rest is cut. Signal has no
# separate place to put it, like the thread reply Slack gets.
_CARD_COMMAND_MAX = 1500
_APPROVAL = re.compile(r"^\s*(approve|deny)\s+\[?([\w-]+)\]?\s*[.!]?\s*$", re.IGNORECASE)

_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="gateway-turn")
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


def send(channel, markdown, reply_to=None):
    """Post a Markdown reply as final text, split to Signal's limit. Whether
    every piece was accepted. The first piece quotes `reply_to`, so a reply in
    a shared group stays this agent's: the gateway routes the answer to a
    quote back to whoever sent the quoted message."""
    retval = True
    for i, parts in enumerate(gateway_text.parts(markdown or "")):
        body = {"to": _target(channel), "parts": parts}
        if reply_to and i == 0:
            body["reply_to"] = reply_to
        try:
            _call("POST", "/v1/messages", body)
        except urllib.error.HTTPError as exc:
            logging.warning("gateway: send to %s refused: %s %s", channel, exc.code, _error_code(exc))
            retval = False
        except Exception as exc:  # noqa: BLE001
            logging.warning("gateway: send to %s failed: %s", channel, type(exc).__name__)
            retval = False
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
        retval = (
            f"On {self.medium.title()} you share one account with other agents; the gateway "
            "hands you only the messages addressed to you, by quote, by your name, or "
            "by the conversation's default. A message you are reading is for you."
        )
        return retval

    def post(self, channel, thread_ts, text, blocks=None):
        retval = send(channel, text)
        return retval


def _text(data):
    """The message as text: text parts, and voice notes by their transcript."""
    pieces, unread = [], []
    for p in data.get("parts") or []:
        if p.get("type") == "text":
            pieces.append(p.get("text", ""))
        elif p.get("transcript"):
            pieces.append(f"[voice note] {p['transcript']}")
        elif p.get("type") == "file":
            unread.append(p.get("filename") or p.get("content_type") or "a file")
    retval = "\n".join(pieces).strip()
    if unread:
        retval += "\n\n[attachments I could not read: " + "; ".join(unread) + "]"
    return retval


def _history(conversation_id, current):
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
        if sender.get("kind") == "self":
            mine = sender.get("consumer") in (None, config.GATEWAY_CONSUMER)
            who = f"{config.AGENT_LABEL or 'me'} (me)" if mine else f"{sender.get('consumer')} (another agent)"
        else:
            who = sender.get("name") or "user"
        text = _text(m)
        if text:
            lines.append(f"[{who}] {text}")
    retval = "\n".join(lines) or None
    return retval


def _first_time(message_id):
    with _SEEN_LOCK:
        if message_id in _SEEN:
            return False
        _SEEN[message_id] = None
        if len(_SEEN) > 500:
            del _SEEN[next(iter(_SEEN))]
    return True


def _turn(data):
    channel = channel_of(data)
    medium = data.get("channel", "gateway")
    sender = data.get("sender") or {}
    user = f"{medium}:{sender.get('id')}"
    if sender.get("name"):
        identity.NAMES[user] = sender["name"]
    surface = GatewaySurface(medium)
    text = _text(data)
    m = _APPROVAL.match(text)
    if m and admin_tools.is_trusted(user):
        _resolve_text(m.group(1).lower() == "approve", m.group(2), channel, user, surface)
        return
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
    send(channel, reply, reply_to=data["message_id"])
    _post_pending(channel, surface)
    mirror_out(channel, identity.mention(user), text, reply)


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
    send(channel, f"```\n{result[:_CARD_COMMAND_MAX * 2]}\n```")
    _resume(channel, req_id, req, approved, result, user, surface)


def _resume(channel, req_id, req, approved, result, user, surface):
    """Carry the turn on after a request resolved (#169); handler.resume decides
    whether this is the moment."""
    try:
        reply = handler.resume(req_id, approved, req.get("command", ""), result,
                               thread_context=None, channel=channel, thread_ts=_THREAD,
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
        cmd = redact.scrub(req["command"])
        if len(cmd) > _CARD_COMMAND_MAX:
            cmd = cmd[:_CARD_COMMAND_MAX] + " ... (cut)"
        reason = f"\n{req['reason']}" if req.get("reason") else ""
        card = (f"Needs approval [{req_id}]:\n```\n{cmd}\n```{reason}\n"
                f"A trusted user replies \"approve {req_id}\" or \"deny {req_id}\".")
        if not send(channel, card):
            _card_failed(channel, req_id, surface)
    for key, prop in proposals.claim_unsurfaced(channel):
        card = redact.scrub(f"Worth a skill? [{key}] {prop['name']} -- {prop['why']}\n"
                            f"A trusted user can ask me to open it ({key}) or decline it.")
        if not send(channel, card):
            proposals.unsurface(key)


def _card_failed(channel, req_id, surface):
    """A card did not post: retry on the next turn, up to _CARD_TRIES; then
    withdraw it, as slack_app does (#356), so it cannot hold the thread."""
    if approvals.unsurface(req_id) < _CARD_TRIES:
        return
    if approvals.withdraw(req_id) is None:
        return
    send(channel, f"[{req_id}] needed approval, but its card could not be posted, so it was "
                  "withdrawn and did not run. Ask again if it is still needed.")
    outcome = approvals.take_deferred(channel, _THREAD)
    if outcome is not None:
        _resume(channel, outcome["req_id"], {"command": outcome["command"], "requester": outcome["requester"]},
                outcome["approved"], outcome["result"], outcome["user_id"], surface)


def _safe_turn(data):
    try:
        _turn(data)
    except Exception:
        logging.exception("gateway: turn failed")


def _loop():
    cursor = state.get(_CURSOR) or "now"
    while True:
        try:
            q = urllib.parse.urlencode({"after": cursor, "wait": 25, "types": "message.received"})
            body = _call("GET", f"/v1/events/poll?{q}", timeout=40)
        except Exception as exc:  # noqa: BLE001
            logging.warning("gateway: poll failed (%s); retrying", type(exc).__name__)
            time.sleep(5)
            continue
        for e in body.get("events") or []:
            data = e.get("data") or {}
            if e.get("type") == "ai.voitta.message.received.v1" and _first_time(data.get("message_id")):
                _pool.submit(_safe_turn, data)
        nxt = body.get("next")
        if nxt and nxt != cursor:
            cursor = nxt
            state.put(_CURSOR, cursor)        # persisting `next` is the ack (gateway README)


def start(slack_post=None):
    """Start polling the gateway in the background, when one is configured."""
    global _slack_post
    if not config.GATEWAY_URL:
        return False
    _slack_post = slack_post
    threading.Thread(target=_loop, name="gateway-poll", daemon=True).start()
    logging.info("gateway: polling for %d listed conversation(s)", len(config.GATEWAY_CONVERSATIONS))
    return True


def announce(text):
    """Post into every listed gateway conversation; how many accepted it."""
    retval = sum(1 for label in config.GATEWAY_CONVERSATIONS if send(f"gateway:{label}", text))
    return retval


# ---------------------------------------------------------------- mirroring
# Off unless a conversation's entry sets `mirror`. Only the question and the
# final answer cross; cards stay where they were posted, so each request is
# answered in the one place it can be resolved.

def mirror_out(channel, who, question, answer):
    """A gateway turn, copied into the Slack channel its conversation links to."""
    label = channel.partition(":")[2]
    conv = config.GATEWAY_CONVERSATIONS.get(label) or {}
    if not (conv.get("mirror") and conv.get("link") and _slack_post):
        return
    try:
        _slack_post(conv["link"], f"_{who} asked on {channel.partition(':')[0].title()}:_ {question}")
        _slack_post(conv["link"], answer)
    except Exception:
        logging.exception("gateway: could not mirror into %s", conv["link"])


def mirror_in(slack_channel, question, answer):
    """A Slack turn, copied into every gateway conversation linked to it."""
    question = re.sub(r"<@\w+>", "", question or "").strip()
    for label, conv in config.GATEWAY_CONVERSATIONS.items():
        if conv.get("mirror") and conv.get("link") == slack_channel:
            send(f"gateway:{label}", f"_Asked on Slack:_ {question}")
            send(f"gateway:{label}", answer)
