"""Slack ingest (Bolt Socket Mode). Iter 0: respond to @mentions in the
configured channel(s), reply in-thread, one clear message on error (never spam).

Works with a fresh app (from deploy/slack-app-manifest.yaml) or the existing
@Shmobster bot's tokens -- same code; only .env differs."""
import logging

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from . import admin_tools, announce, approvals, attachments, build, config, gitcfg, handler, identity, learning, proposals, redact, sandbox, skills, slack_blocks, watchdog

# asctime is not in the default format (#102). Without it the disposition log
# (#97) records order but not time, and "how long did that take" / "did this run
# before or after the click" are exactly the questions it exists to answer.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s:%(name)s:%(message)s")
# Installed here, at import, before ANY statement that can log (#72). The App()
# constructor below round-trips auth.test, and every startup call can raise with
# request details attached -- so there must be no window in which an exception is
# rendered into a log unscrubbed. require() fails the boot outright if the
# redactor is unavailable, which is the safe direction.
redact.require()
redact.install_logging()
app = App(token=config.SLACK_BOT_TOKEN)


_MAX_THREAD_MSGS = 25  # ponytail: cap history; raise if threads need deeper recall


def _thread_context(client, channel, thread_ts, cur_ts):
    """Flatten prior thread messages into a labeled transcript (Iter 11 / #11).

    Flattened (not native assistant turns) so multi-user threads with consecutive
    same-role messages don't trip vendor role-alternation rules. Long-term memory
    (workspace MEMORY.md) is a separate, later concern.
    """
    if not thread_ts:
        return None
    try:
        resp = client.conversations_replies(
            channel=channel, ts=thread_ts, limit=_MAX_THREAD_MSGS
        )
    except Exception:
        return None
    lines = []
    for m in resp.get("messages", []):
        if m.get("ts") == cur_ts:
            continue  # the current mention -- handler adds it as the user turn
        who = identity.speaker(m)  # self / sibling agent / human, not blanket "agent" (#60)
        text = (m.get("text") or "").strip()
        if text:
            lines.append(f"[{who}] {text}")
    retval = "\n".join(lines) or None
    return retval


_SEEN = {}  # message ts -> None; dedup duplicate Slack deliveries / retries


def _seen(ts):
    if ts in _SEEN:
        return True
    _SEEN[ts] = None
    if len(_SEEN) > 500:
        del _SEEN[next(iter(_SEEN))]
    return False


def _post_pending(client, channel, thread_ts):
    """Render any newly parked commands as button messages in this thread."""
    for req_id, req in approvals.claim_unsurfaced(channel):
        try:
            client.chat_postMessage(
                channel=channel,
                thread_ts=thread_ts,
                # A parked command is echoed verbatim, and a credential rides
                # command lines routinely -- that is the YOLT lesson (#72).
                text=redact.scrub(f"Needs approval [{req_id}]: {req['command']}"),
                blocks=slack_blocks.approval(req_id, req),
            )
        except Exception:
            logging.exception("could not post approval buttons for %s", req_id)
    # And any skill the agent flagged this turn (#129): a card tagging the
    # trusted users, who may open the PR or decline. Same rendering path.
    for key, prop in proposals.claim_unsurfaced(channel):
        try:
            client.chat_postMessage(
                channel=channel,
                thread_ts=thread_ts,
                text=redact.scrub(f"Worth a skill? [{key}] {prop['name']} -- {prop['why']}"),
                blocks=slack_blocks.proposal(key, prop, admin_tools._trusted_tags()),
            )
        except Exception:
            logging.exception("could not post the skill proposal card for %s", key)


def _resolve(ack, body, client, action, run, queue=approvals, claimed=slack_blocks.claimed):
    """Shared button plumbing: ack inside Slack's 3s budget, act as the clicking
    user (never the model), then rewrite the message so the buttons are gone and
    the outcome is on the record."""
    ack()
    channel = body["channel"]["id"]
    message_ts = body["message"]["ts"]
    thread_ts = body["message"].get("thread_ts") or message_ts
    ctx = {
        "user_id": body["user"]["id"],
        "channel": channel,
        "thread_ts": thread_ts,
        "client": client,
    }
    # A click that resolves nothing must not touch the card (#94). chat_update
    # is destructive, and the card is the only place a parked command is ever
    # displayed -- overwriting it with a refusal both loses the command text and
    # takes the buttons away from the trusted user who could still act on it,
    # while the request itself stays in the queue, surfaced and unreachable.
    if not admin_tools.is_trusted(ctx["user_id"]):
        admin_tools.refuse_click(action["value"], ctx, action.get("action_id"))
        return
    req_id = action["value"]
    # Take the request before touching the card. Two deliveries of one press
    # land on two Bolt threads, and the loser -- whose pop finds nothing --
    # would otherwise overwrite the winner's output with "no pending request"
    # for a command that did run. Hiding the buttons does not prevent that.
    req = queue.acquire(req_id, channel)
    if req is None:
        # Two reasons acquire can fail, and they deserve different answers. If
        # another delivery of this press has it in flight, that thread will
        # update the card and saying anything here would claim it is gone while
        # it is running -- and it IS gone from the queue by then, since approve
        # pops before it executes, so the hold is the only thing that knows.
        # Only a genuinely absent request gets a message, and it goes to the
        # thread rather than rewriting the card, because a click that resolves
        # nothing must not destroy the only copy of the parked command (#94).
        if queue.status(req_id, channel)[0] == "held":
            return
        try:
            client.chat_postMessage(
                channel=channel, thread_ts=thread_ts,
                text=f":information_source: [{req_id}] is not pending here -- nothing to act on.",
            )
        except Exception:
            logging.exception("could not report a stale approval click")
        return
    try:
        # Acknowledge the click before doing the work (#101), not after. The
        # final update can be seconds away -- this one ran a network call -- and
        # until it lands the card is unchanged with its buttons still live,
        # which reads as a click that went nowhere.
        try:
            client.chat_update(
                channel=channel,
                ts=message_ts,
                text=f"Working on [{req_id}] for <@{ctx['user_id']}>",
                blocks=claimed(action.get("action_id"), req_id, ctx["user_id"], req),
            )
        except Exception:
            logging.exception("could not mark approval message as claimed")
        result = redact.scrub(run(req_id, ctx))
    finally:
        queue.release(req_id)
    try:
        client.chat_update(
            channel=channel,
            ts=message_ts,
            text=result[:2900],
            blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": f"```{result[:2900]}```"}}],
        )
    except Exception:
        logging.exception("could not update approval message")
        client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=result[:2900])


@app.action("approve_command")
def on_approve(ack, body, client, action):
    _resolve(
        ack, body, client, action,
        lambda req_id, ctx: admin_tools.dispatch(
            "approve_command", {"request_id": req_id}, ctx
        ),
    )


@app.action("deny_command")
def on_deny(ack, body, client, action):
    _resolve(ack, body, client, action, admin_tools.deny)


@app.action("open_skill_pr")
def on_open_skill_pr(ack, body, client, action):
    _resolve(
        ack, body, client, action,
        lambda key, ctx: admin_tools.dispatch("propose_skill", {"request_id": key}, ctx),
        queue=proposals, claimed=slack_blocks.proposal_claimed,
    )


@app.action("decline_skill")
def on_decline_skill(ack, body, client, action):
    _resolve(
        ack, body, client, action,
        lambda key, ctx: admin_tools.dispatch("decline_skill", {"request_id": key}, ctx),
        queue=proposals, claimed=slack_blocks.proposal_claimed,
    )


@app.event("app_mention")
def on_mention(event, say, client, logger):
    if _seen(event.get("ts")):
        return  # Slack can deliver an event more than once -- handle it once.
    channel = event.get("channel")
    # Ack immediately with a reaction so we don't look silent while churning.
    # Best-effort: needs reactions:write; if not granted, this no-ops.
    try:
        client.reactions_add(channel=channel, name="eyes", timestamp=event.get("ts"))
    except Exception:
        pass
    # Respond wherever invited (#36): no channel allowlist gate. Capability is
    # scoped by per-channel policy, not by which channels we respond in.
    thread_ts = event.get("thread_ts") or event.get("ts")
    context = _thread_context(client, channel, thread_ts, event.get("ts"))
    # Attachments ride in event["files"], not in the text (#68). Only this
    # message's -- files in thread *history* stay unread for now, since every
    # reply would re-download them.
    parts, notes = attachments.to_parts(event.get("files"))
    text = event.get("text", "")
    if notes:
        text += "\n\n[attachments I could not read: " + "; ".join(notes) + "]"
    try:
        reply = handler.handle(text, thread_context=context, channel=channel, thread_ts=thread_ts, user_id=event.get("user"), slack_client=client, attachments=parts)
    except Exception as exc:  # one clear message, no dozen "did not run" cards
        # Both paths are scrubbed: a provider exception can carry the request it
        # failed on, api_key and Authorization header included (#72). The log
        # side is covered by redact.install_logging(), which scrubs the rendered
        # traceback too.
        logger.exception("handler failed")
        reply = redact.scrub(f":warning: shmobster error: {exc}")
    say(text=reply, thread_ts=thread_ts)
    # Anything the turn parked gets Approve/Deny buttons (#50), so a trusted
    # user answers with a click instead of another round-trip through the model.
    _post_pending(client, channel, thread_ts)


@app.event("message")
def _ignore_message(event):
    # Iter 0 answers mentions only. Ack other message events so Bolt doesn't
    # log a 404 "unhandled request" for every message in the channel.
    return


def _resolve_label(client):
    """Auto-derive the agent label from the Slack app's display name when
    agent.label is unset (#8), so the marker matches whatever the app is named.
    Falls back to the bot handle, then 'shmobster'."""
    if config.AGENT_LABEL:
        return config.AGENT_LABEL
    try:
        auth = client.auth_test()
        try:
            profile = client.users_info(user=auth["user_id"])["user"]["profile"]
            name = profile.get("display_name") or profile.get("real_name")
            if name:
                return name
        except Exception:
            pass  # users:read not granted -> fall back to the bot handle
        return auth.get("user") or "shmobster"
    except Exception:
        return "shmobster"


def main():
    if not config.AGENT_LABEL:
        config.AGENT_LABEL = _resolve_label(app.client)
    try:
        config.BOT_USER_ID = app.client.auth_test().get("user_id", "")
    except Exception:
        logging.exception("could not resolve bot user id")
    logging.info("agent: %s (%s) -- shmobster %s", config.AGENT_LABEL, config.BOT_USER_ID, build())
    # Skills index (#74): names only in the log -- a skill body is content, and
    # logs are a surface we keep boring.
    if config.SKILL_PATHS:
        count = skills.reload()
        logging.info("skills: %d indexed from %d path(s)", count, len(config.SKILL_PATHS))
        for name, path in skills.shadowed():
            logging.info("skills: %s at %s shadowed by a higher-precedence path", name, path)
    # Say so in the channels when this instance came back on a new version (#77).
    # Ingest-agnostic: announce knows only how to call post(text).
    #
    # One dead channel must not silence the rest (#89). A stale or archived
    # channel id makes chat_postMessage raise, and an unguarded loop aborts
    # before the healthy channels are ever reached -- observed live, where a
    # stale DM id sorted first out of the set and the announcement reached
    # nobody, with one traceback about one channel as the only trace.
    #
    # Raising only when NOTHING got through is what keeps announce's retry
    # honest: it does not record a failed post, so a partial success that
    # reported failure would re-announce to the channels that already have it
    # on every boot -- and the watchdog (#66) makes boots frequent. Fan-out
    # semantics live here rather than in announce, which owns the version
    # comparison and the state file and knows only post(text).
    def _post(text):
        delivered = 0
        for channel in config.CHANNELS:
            try:
                app.client.chat_postMessage(channel=channel, text=text)
                delivered += 1
            except Exception:
                logging.exception(
                    "announce: could not post to %s", config.CHANNEL_NAMES.get(channel, channel))
        if not delivered:
            raise RuntimeError("no configured channel accepted the announcement")

    announce.check(_post)
    # Git runs over https with gh's token in every channel (gitcfg.py). Say
    # so now if this host cannot do that, instead of at the first push.
    for warning in gitcfg.preflight():
        logging.warning("git preflight: %s", warning)
    if sandbox.gh_file_backed():
        logging.warning(
            "gh keeps its token in %s, not the keychain; the file is denied to every "
            "channel, so gh runs unauthenticated there. Re-run `gh auth login` on a host "
            "with a working keychain.", sandbox._GH_HOSTS)
    if learning.enabled():
        logging.info("learning: proposals go to %s (%s)", config.LEARNING_REPO, config.LEARNING_PATH)
    socket_mode = SocketModeHandler(app, config.SLACK_APP_TOKEN)
    # Deaf-but-alive is the failure mode KeepAlive cannot see (#66), so we watch
    # the connection ourselves and exit when it stops hearing Slack.
    watchdog.start(socket_mode.client, config.WATCHDOG_TIMEOUT_SEC)
    socket_mode.start()


if __name__ == "__main__":
    main()
