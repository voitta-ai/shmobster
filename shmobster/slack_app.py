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


@app.event("app_mention")
def on_mention(event, say, logger):
    channel = event.get("channel")
    if config.CHANNELS and channel not in config.CHANNELS:
        return  # Iter 0: only the configured channel(s).
    thread_ts = event.get("thread_ts") or event.get("ts")
    try:
        reply = handler.handle(event.get("text", ""))
    except Exception as exc:  # one clear message, no dozen "did not run" cards
        logger.exception("handler failed")
        reply = f":warning: shmobster error: {exc}"
    say(text=reply, thread_ts=thread_ts)


@app.event("message")
def _ignore_message(event):
    # Iter 0 answers mentions only. Ack other message events so Bolt doesn't
    # log a 404 "unhandled request" for every message in the channel.
    return


def main():
    SocketModeHandler(app, config.SLACK_APP_TOKEN).start()


if __name__ == "__main__":
    main()
