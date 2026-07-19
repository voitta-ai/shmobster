"""Slack ingest (Bolt Socket Mode). Iter 0: respond to @mentions in the
configured channel(s), reply in-thread, one clear message on error (never spam).

Works with a fresh app (from deploy/slack-app-manifest.yaml) or the existing
@Shmobster bot's tokens -- same code; only .env differs."""
import logging

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from . import config, handler

logging.basicConfig(level=logging.INFO)
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
        who = config.AGENT_LABEL if m.get("bot_id") else "user"
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
    try:
        reply = handler.handle(event.get("text", ""), thread_context=context, channel=channel, thread_ts=thread_ts, user_id=event.get("user"), slack_client=client)
    except Exception as exc:  # one clear message, no dozen "did not run" cards
        logger.exception("handler failed")
        reply = f":warning: shmobster error: {exc}"
    say(text=reply, thread_ts=thread_ts)


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
    logging.info("agent: %s (%s)", config.AGENT_LABEL, config.BOT_USER_ID)
    SocketModeHandler(app, config.SLACK_APP_TOKEN).start()


if __name__ == "__main__":
    main()
