"""Slack ingest (Bolt Socket Mode). Iter 0: respond to @mentions in the
configured channel(s), reply in-thread, one clear message on error (never spam).

Works with a fresh app (from deploy/slack-app-manifest.yaml) or the existing
@Shmobster bot's tokens -- same code; only .env differs."""
import logging

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from . import admin_tools, announce, approvals, attachments, build, config, gitcfg, handler, identity, learning, logsetup, proposals, redact, sandbox, skills, slack_blocks, slack_tools, trajectory, watchdog, yolt_gate

# Installed here, at import, before ANY statement that can log (#72). The App()
# constructor below round-trips auth.test, and every startup call can raise with
# request details attached -- so there must be no window in which an exception is
# rendered into a log unscrubbed. require() fails the boot outright if the
# redactor is unavailable, which is the safe direction.
redact.require()
redact.install_logging()
app = App(token=config.SLACK_BOT_TOKEN)

# asctime is not in the default format (#102). Without it the disposition log
# (#97) records order but not time, and "how long did that take" / "did this run
# before or after the click" are exactly the questions it exists to answer.
# Where those lines land -- stderr, or the agent's own rotated 0600 file -- is
# logsetup's business, decided in main() (#155).
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
    for req_id, req in approvals.claim_unsurfaced(channel, thread_ts):
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
            approvals.unsurface(req_id)
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
            proposals.unsurface(key)


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
        # A reaction as well as the rewrite (#206). The claimed-card update
        # below already says "Working on", but a reaction is the signal people
        # are trained on: every user message gets :eyes: the moment the agent
        # picks it up, and an approval click got nothing of the kind. Between
        # the click and the result -- seconds, on a slow command -- there was no
        # way to tell "it landed and is running" from "it was lost", which is
        # exactly what the bug #169 fixed used to look like.
        slack_tools.react(client, channel, message_ts, add="eyes")
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
        # The runner gets the request we acquired (#105): it must execute
        # what it was handed, never look it up again by id -- the id path
        # would find nothing (we hold it) and report "no pending request"
        # for a command that is about to run.
        result = redact.scrub(run(req_id, req, ctx))
    finally:
        queue.release(req_id)
    if result.startswith(learning.RETRY) and queue is proposals:
        # A transient failure put the proposal back under the same id (#129
        # review): the card gets its buttons back, with the reason on it, so
        # the trusted user can try again from where they are.
        prop = proposals.peek(req_id, channel)
        blocks = slack_blocks.proposal(req_id, prop, admin_tools._trusted_tags()) if prop else []
        blocks.insert(0, {"type": "section", "text": {"type": "mrkdwn", "text": f":warning: {result[len(learning.RETRY):].strip()[:2800]}"}})
    else:
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"```{result[:2900]}```"}}]
    try:
        client.chat_update(channel=channel, ts=message_ts, text=result[:2900], blocks=blocks)
    except Exception:
        logging.exception("could not update approval message")
        client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=result[:2900])
    # The receipt becomes a verdict: :eyes: meant "heard you", and it has to
    # stop meaning that once the answer is on the card. Denial is not failure,
    # so it gets its own mark rather than the one that reads as an error.
    slack_tools.react(client, channel, message_ts, remove="eyes",
           add="white_check_mark" if action.get("action_id") == "approve_command" else "no_entry_sign")
    if queue is approvals:
        _resume_thread(client, channel, thread_ts, req_id, req,
                       approved=action.get("action_id") == "approve_command",
                       result=result, user_id=ctx["user_id"])


def _resume_thread(client, channel, thread_ts, req_id, req, approved, result, user_id):
    """Carry the turn on after a click resolved a parked command (#169).

    handler.resume decides whether this is the moment -- it returns None while
    the thread still has a parked request, so a turn that parked three commands
    resumes once, on the last click, rather than three times over.

    Best-effort by construction. The click is acked, the command has run and
    its output is on the card, so a failure in here costs the continuation and
    nothing else; it must never look like the approval failed."""
    try:
        context = _thread_context(client, channel, thread_ts, None)
        reply = handler.resume(
            req_id, approved, req.get("command", ""), result,
            thread_context=context, channel=channel, thread_ts=thread_ts,
            # The clicking trusted user, matching the text path: "approve <id>"
            # runs inside that user's own turn, so the resumed turn carries the
            # same identity a typed approval would.
            user_id=user_id, slack_client=client,
        )
        if reply is None:
            return  # something else in this thread is still waiting on a human
        client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=reply)
        # The resumed turn can park the next step, so its cards need posting
        # too -- otherwise the task stops one command later, for the same
        # reason it used to stop here.
        _post_pending(client, channel, thread_ts)
    except Exception:
        logging.exception("could not resume the thread after [%s]", req_id)


@app.action("approve_command")
def on_approve(ack, body, client, action):
    _resolve(ack, body, client, action, admin_tools.run_approved)


@app.action("deny_command")
def on_deny(ack, body, client, action):
    _resolve(ack, body, client, action, admin_tools.run_denied)


@app.action("open_skill_pr")
def on_open_skill_pr(ack, body, client, action):
    _resolve(
        ack, body, client, action,
        lambda key, prop, ctx: learning.propose_acquired(key, prop, ctx),
        queue=proposals, claimed=slack_blocks.proposal_claimed,
    )


@app.action("decline_skill")
def on_decline_skill(ack, body, client, action):
    _resolve(
        ack, body, client, action,
        lambda key, prop, ctx: learning.decline_acquired(key, prop, ctx),
        queue=proposals, claimed=slack_blocks.proposal_claimed,
    )


def _turn(event, say, client, logger):
    """One turn, from whichever Slack event carried it.

    A mention in a channel and a direct message are the same turn: the same
    handler, the same policy lookup, the same approval cards. Only the door
    differs (#23). Keeping one body means a DM cannot quietly miss something a
    mention gets -- attachments, thread context, the parked-request cards --
    which is exactly what a second copy of this would drift into."""
    channel = event.get("channel")
    # Ack immediately with a reaction so we don't look silent while churning.
    # Best-effort: needs reactions:write; if not granted, this no-ops.
    try:
        client.reactions_add(channel=channel, name="eyes", timestamp=event.get("ts"))
    except Exception:
        pass
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


@app.event("app_mention")
def on_mention(event, say, client, logger):
    if _seen(event.get("ts")):
        return  # Slack can deliver an event more than once -- handle it once.
    # Respond wherever invited (#36): no channel allowlist gate. Capability is
    # scoped by per-channel policy, not by which channels we respond in.
    _turn(event, say, client, logger)


@app.event("message")
def on_message(event, say, client, logger):
    """A direct message is a turn; a channel message still needs a mention.

    Trust does not change with the door: `trusted_users` is per user, so the
    same person has the same authority in a DM as in a channel, and the channel
    id a DM resolves to (`D...`) takes a policy like any other -- one that is
    absent falls back to `default_policy`, so a deployment wanting DMs narrower
    than its default says so there. The decision itself is `identity.dm_turn`,
    where it can be tested without a Slack connection."""
    if not identity.dm_turn(event):
        return
    if _seen(event.get("ts")):
        return  # a mention inside a DM arrives twice, once per event type
    _turn(event, say, client, logger)


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
    logsetup.setup()
    if not config.AGENT_LABEL:
        config.AGENT_LABEL = _resolve_label(app.client)
    try:
        config.BOT_USER_ID = app.client.auth_test().get("user_id", "")
    except Exception:
        logging.exception("could not resolve bot user id")
    logging.info("agent: %s (%s) -- shmobster %s", config.AGENT_LABEL, config.BOT_USER_ID, build())
    if not config.BOT_USER_ID:
        # `identity.dm_turn` refuses every DM without it, on purpose: an agent
        # that cannot recognize its own posts is one that can answer them.
        # Mentions still work, because there the mention is the address.
        logging.warning(
            "bot user id unresolved, so direct messages will not be answered (#23); "
            "mentions are unaffected. Check the bot token and auth.test"
        )
    # Skills index (#74): names only in the log -- a skill body is content, and
    # logs are a surface we keep boring.
    if config.SKILL_PATHS:
        count = skills.reload()
        logging.info("skills: %d indexed from %d path(s)", count, len(config.SKILL_PATHS))
        for name, path in skills.shadowed():
            logging.info("skills: %s at %s shadowed by a higher-precedence path", name, path)
    # Probe every configured channel once at startup (#93, follow-up to #89):
    # a stale id or a channel the bot was never invited to otherwise surfaces
    # only when a post fails, deep in a turn. conversations.history is the
    # probe because nothing here holds channels:read (see README, Slack
    # scopes): channel_not_found from it means NOT A MEMBER (or a dead id),
    # not a bad token -- fix with /invite, or correct the id in the config.
    for _ch in config.CHANNELS:
        try:
            app.client.conversations_history(channel=_ch, limit=1)
        except Exception as exc:
            _err = getattr(exc, "response", {})
            _err = _err.get("error", "") if hasattr(_err, "get") else ""
            logging.warning(
                "channel %s (%s) does not resolve at startup: %s -- "
                "channel_not_found means the bot is not a member (or the id is "
                "stale); /invite it there or fix slack.channels",
                config.CHANNEL_NAMES.get(_ch, _ch), _ch, _err or exc)
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
    # Trajectories are appended per turn and only ever read 14 days back (#155).
    dropped = trajectory.prune(config.TRAJECTORY_DAYS)
    if dropped:
        logging.info("trajectories: pruned %s file(s) older than %s days", dropped, config.TRAJECTORY_DAYS)
    for warning in gitcfg.preflight():
        logging.warning("git preflight: %s", warning)
    # What auto-runs is YOLT's rules, not the operator's terminal permissions
    # (#148). Say so at boot, and say it loudly if this host's YOLT is too old
    # to be asked.
    for warning in yolt_gate.preflight():
        logging.warning("yolt preflight: %s", warning)
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
