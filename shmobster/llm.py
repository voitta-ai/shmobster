"""Multi-vendor waterfall via LiteLLM Router, built from config.WATERFALL.

Iter 0: ordered failover (primary -> fb0 -> fb1 -> ...) with a cooldown so a
rate-limited/broken vendor is skipped for a window instead of re-hit every call.
Per-vendor observability + dead-fallback surfacing is Iter 3 (#5).

Budget parking (#80). LiteLLM decides cooldowns by HTTP status and cools only
429/401/408/404 -- see `_is_cooldown_required`. Budget exhaustion is neither:
Anthropic answers a usage cap with 400, OpenRouter answers no-credit with 402.
Fallback still works, so requests are answered, but the dead vendor is re-dialled
on every single turn for as long as the cap lasts -- weeks, in the case that
prompted this. So we park it ourselves.

Parking hangs off litellm's failure callback, NOT off an `except` around
`router.completion()`. When a fallback succeeds the Router returns that
response and the primary's exception never propagates -- verified live:
OpenRouter 402 as primary, gemini answering, no exception raised, and the
failure callback firing with the 402. An `except` here would only see the case
where the whole chain is dead, which is the case parking cannot help.

Parking rebuilds the Router without that vendor rather than reaching into
litellm's private cooldown: the group names here are positional (`primary`,
`fb0`, ...) and `complete()` asks for `primary` by name, so dropping the primary
is a *renaming*, not a deletion. Rebuilding is also public API, so a litellm
upgrade cannot break it. Expiries live in the state file, because a watchdog
restart would otherwise un-learn everything.

Cost of a rebuild: litellm's in-memory 429 cooldowns for the other deployments
reset. They cool for 60s; this is a rounding error against re-dialling a vendor
that is dead for a month.

Dead rungs (#353). A rung whose model the vendor has retired, dropped from a
free tier, or refuses for this plan will not work again until someone edits the
config. litellm cools a 404 for 60s and a 400 not at all, and when a later rung
covers the failure nothing raises -- so these sat unnoticed for days, until
every rung died at once and the agent went silent. A dead rung is parked like a
budget-exhausted one, logged at ERROR, and announced once on Slack, after the
next turn's reply (`claim_dead_notices`). The park is keyed to the rung's configured model, so
fixing the config un-parks it at once. It starts short and doubles on each
repeat (`_DEAD_PARK_FIRST` up to `_DEAD_PARK_MAX`), rather than lasting until
restart: the watchdog restarts this process routinely, which would re-learn
(and re-pay) the failure every few minutes. Short first, because a rung can be
fixed vendor-side (access enabled, credit added) with no config edit to notice;
growing, because a rung that really is gone should not be re-dialled hourly.

A short wait before falling over (#351). A 429 that says when to come back --
Gemini's RetryInfo `retryDelay`, or a Retry-After header -- is a per-minute
quota, not an outage, and litellm does not wait it out: it cools the deployment
and falls over at once. When every rung after it is dead too, a 29-second
quota ends the turn. So `complete()` asks the primary alone first, and on a
429 with a stated delay of at most `_RETRY_WAIT_CAP` waits and asks it once
more, directly, before handing the request to the rest of the chain. The
Router's fallbacks therefore start at `fb0`: the primary is never in them."""
import datetime
import logging
import math
import re
import threading
import time

import litellm
from litellm import Router
from litellm.integrations.custom_logger import CustomLogger

from . import codex_llm, config, cost, state

# Never let the rented router log raw request params -- they carry api_key.
# Belt and suspenders: disable verbose mode AND cap the LiteLLM logger at
# WARNING, so a stray LITELLM_LOG=DEBUG or a library default flip cannot dump a
# credential into the logs. (Redaction lesson from voitta-yolt#84.)
litellm.set_verbose = False
litellm.suppress_debug_info = True
# ...and do not phone home (#156). Defence in depth, not a known leak: nothing
# in this version was found calling out, but "the rented router decides what
# leaves this process" is not a property to leave at a library default when one
# assignment settles it.
litellm.telemetry = False
# Cap ALL THREE LiteLLM loggers: _turn_on_debug() flips every one to DEBUG, and
# it is "LiteLLM Router" (not "LiteLLM") that services the Router used here.
for _name in ("LiteLLM", "LiteLLM Router", "LiteLLM Proxy"):
    logging.getLogger(_name).setLevel(logging.WARNING)

_RUNG_VENDORS = {}
# The live router, its rungs `[(id, vendor, litellm_params)]` and the vendor
# names it was built from, as ONE tuple (#351): a reader takes all three in a
# single read, so a concurrent rebuild can never pair one build's router with
# another build's rungs. None until built, and after `_invalidate()`.
_LIVE = None
# Serialises the check-and-build in `_ensure()`. Never taken by `_invalidate()`,
# which runs under `_DEAD_LOCK` while `_build()` takes `_DEAD_LOCK` under this
# one -- that order would deadlock. An unlocked swap to None is atomic.
_BUILD_LOCK = threading.Lock()

_STATE_KEY = "parked_vendors"  # {vendor name: epoch seconds when it may be used again}

# Budget exhaustion, by status plus message shape. Status alone is too broad --
# a 400 is also a malformed request, and parking a vendor for an hour over a bad
# prompt would be worse than the problem.
_BUDGET_MARKERS = (
    "usage limit",
    "usage limits",
    "insufficient credit",
    "insufficient_quota",
    "credit balance",
    "exceeded your current quota",
    "billing",
    "payment required",
)

# Anthropic states when access returns: "You will regain access on 2026-09-01".
_REGAIN_DATE = re.compile(r"regain access on (\d{4})-(\d{2})-(\d{2})")

# A stated regain date further out than this is clamped to it. The date comes
# from an error body, and a far-future one (a proxy's, or a typo'd year) would
# otherwise take the rung out until someone hand-edits the state file. The same
# cap voitta-ai/agents' port of this module carries.
_MAX_PARK_SEC = 31 * 24 * 3600

# Dead rungs (#353): {vendor name: {"until", "model", "reason", "suggest",
# "told", "strikes", "back"}}. Separate from the budget parks because a record is
# only valid for the model it was recorded against -- a config edit that fixes
# the rung must un-park it. A record outlives its park by `_DEAD_PARK_MAX` so a
# rung that dies again soon after coming back gets a longer park; after that it
# is forgotten and the next failure starts over at `_DEAD_PARK_FIRST`.
_DEAD_KEY = "dead_rungs"
_DEAD_PARK_FIRST = 3600
_DEAD_PARK_MAX = 24 * 3600

# A 404 is also "this request has no route": OpenRouter answers "No endpoints
# found that support image input" for a working model handed an attachment it
# cannot read. So only a 404 that says the model or endpoint itself is gone
# counts, and the "no endpoints ... support" family never does.
_DEAD_404 = re.compile(
    r"not found for account|model_not_found|does not exist|decommissioned"
    r"|no longer available|unavailable for free|use this slug instead",
    re.IGNORECASE)
_LIVE_404 = re.compile(r"no endpoints found that support", re.IGNORECASE)

# A 400 is also "your request was malformed", and a parameter refused "for this
# model" names the model too. Only phrasing about the model itself counts, plus
# Codex's quoted-model shape: "The '<model>' model is not supported when using
# Codex with a ChatGPT account."
_DEAD_400 = re.compile(
    r"model_not_found|\bthe model\b[^.\n]{0,80}?does not exist|decommissioned"
    r"|the '[^'\n]{1,120}' model is not supported when using codex",
    re.IGNORECASE)

# OpenRouter: "use this slug instead: <slug>". Charset- and length-bound, so
# nothing but a model slug can ride out of the vendor's body into a log or a
# channel; the body itself carries account and function ids and is never echoed.
_SUGGESTED_SLUG = re.compile(r"use this slug instead:\s*([A-Za-z0-9][A-Za-z0-9._:/-]{0,119})")

# The longest stated 429 delay worth waiting out on the primary (#351). A
# per-minute quota names a delay under a minute; anything longer is an hourly or
# daily quota, where the asker is better served by the next rung now than by
# the primary much later. 60s is also what litellm cools a 429 for here
# (`cooldown_time` below), so it is the window the Router already treats as
# transient, and it stays well inside a turn nobody would call hung.
_RETRY_WAIT_CAP = 60

# Gemini's RetryInfo detail, as it appears in the error text: `"retryDelay":
# "29s"` in the JSON body, `retryDelay: 29s` once flattened. Bounded digits, so
# a malformed body cannot become a huge float.
_RETRY_DELAY = re.compile(r"retryDelay\W{0,4}(\d{1,6}(?:\.\d{1,6})?)s\b")


# Orders dead-rung work within the process (a kill's `_invalidate()` after its
# record lands). The records themselves are only ever rewritten inside
# `state.update(_DEAD_KEY, ...)`, so two turns -- or two processes during a
# restart overlap -- neither both announce a rung nor drop a fresh record
# (#358 review, #363). Lock order: _BUILD_LOCK, then this, then state's lock;
# nothing inside a state.update callback takes another lock.
_DEAD_LOCK = threading.RLock()


def _dead_records():
    """Every dead-rung record that still applies, in force or not: recorded
    against the model the rung is configured with now, and not yet past its
    history window. Pruned on read; a park running out is logged once."""
    with _DEAD_LOCK:
        now = time.time()
        _kept, changed = _prune_dead(state.get(_DEAD_KEY) or {}, now, [])
        if changed:
            notes = []
            pruned, ok = state.update(_DEAD_KEY, lambda raw: _prune_dead(raw or {}, now, notes)[0])
            # A failed write hands back the unpruned value; keep using the
            # pruned view computed above, and retry the write on the next read.
            retval = pruned if ok else _kept
            for line in (notes if ok else []):
                logging.info(line)
        else:
            retval = _kept
    return retval


def _prune_dead(raw, now, notes):
    """(kept records, whether anything changed). Pure apart from appending log
    lines to `notes`, so it can run inside a state.update callback."""
    models = {v.get("name"): v.get("model") for v in config.WATERFALL}
    kept, changed = {}, False
    for name, rec in raw.items():
        if not (isinstance(rec, dict) and isinstance(rec.get("until"), (int, float))):
            changed = True
            continue
        if rec.get("model") != models.get(name):
            changed = True
            if rec["until"] > now:
                notes.append(f"waterfall: {name}'s config changed; out of its dead-rung park")
            continue
        if rec["until"] + _DEAD_PARK_MAX <= now:
            changed = True
            continue
        if rec["until"] <= now and not rec.get("back"):
            rec = dict(rec, back=True)
            changed = True
            notes.append(f"waterfall: {name} is out of its dead-rung park; back in the chain")
        kept[name] = rec
    retval = (kept, changed)
    return retval


def _dead():
    """Dead-rung records in force: the rungs parked right now."""
    now = time.time()
    retval = {name: rec for name, rec in _dead_records().items() if rec["until"] > now}
    return retval


def _parked():
    """Every vendor out of the chain -- budget parks and dead rungs -- as
    vendor -> expiry."""
    retval = dict(_budget_parked())
    for name, rec in _dead().items():
        retval[name] = max(retval.get(name, 0), rec["until"])
    return retval


def _budget_parked():
    """Vendor -> expiry, with anything already expired dropped. Pruning on read
    is what makes a vendor come back: no timer, no background task -- the first
    turn after the window simply stops seeing it as parked."""
    now = time.time()
    dropped = []

    def _prune(raw):
        raw = raw or {}
        live = {name: until for name, until in raw.items()
                if isinstance(until, (int, float)) and until > now}
        dropped.extend(set(raw) - set(live))
        return live
    # Prune and write back in one locked step, so a park landing in between is
    # not overwritten by this thread's older copy (#363). Read-only when
    # nothing expired: the common turn should not rewrite the file.
    raw = state.get(_STATE_KEY) or {}
    if any(not (isinstance(u, (int, float)) and u > now) for u in raw.values()):
        live, _ = state.update(_STATE_KEY, _prune)
    else:
        live = dict(raw)
    for name in dropped:
        logging.info("waterfall: %s is out of its park window; back in the chain", name)
    retval = live
    return retval


def _live_waterfall():
    """The configured waterfall minus parked vendors -- but never empty. A fully
    parked chain still has to try: refusing to answer is worse than one wasted
    call, and the parks may all be stale guesses."""
    parked = _parked()
    live = [v for v in config.WATERFALL if v.get("name") not in parked]
    if not live:
        logging.warning("waterfall: every vendor is parked; trying the full chain anyway")
        live = list(config.WATERFALL)
    retval = live
    return retval


def _park_until(message):
    """When the vendor says it will be back, honour that; otherwise use the
    configured window. A date we cannot parse falls back to the window rather
    than being trusted -- a mis-parse could park a vendor for a year. A date
    past `_MAX_PARK_SEC` is clamped to it, for the same reason."""
    now = time.time()
    match = _REGAIN_DATE.search(message or "")
    if match:
        try:
            when = datetime.datetime(
                int(match.group(1)), int(match.group(2)), int(match.group(3)),
                tzinfo=datetime.timezone.utc,
            ).timestamp()
            date = match.group(0).split("on ")[1]
            if when > now + _MAX_PARK_SEC:
                days = _MAX_PARK_SEC // 86400
                retval = (now + _MAX_PARK_SEC,
                          f"for {days} days (the vendor said until {date}, past the {days}-day cap)")
                return retval
            if when > now:
                retval = (when, f"until {date}")
                return retval
        except ValueError:
            logging.warning("waterfall: unparseable regain date; using the default window")
    retval = (time.time() + config.BUDGET_PARK_SEC, f"for {config.BUDGET_PARK_SEC}s")
    return retval


def _deployment_of(kwargs):
    """The vendor's configured model string, straight from the failure callback.

    `litellm_params.metadata.deployment` is the exact string we put in the
    model_list (`openrouter/openai/gpt-4o`), so identification is a lookup rather
    than a guess. `kwargs["model"]` is NOT usable for this: litellm strips the
    provider prefix, so two vendors reached through different routers can report
    the same `openai/gpt-4o` and the wrong one gets parked."""
    params = kwargs.get("litellm_params") or {}
    metadata = params.get("metadata") or {}
    retval = metadata.get("deployment") or ""
    return retval


def _vendor_for(deployment, exc=None):
    """Which configured vendor this failure belongs to.

    Exact match on the deployment string first. Only if that is unavailable do we
    fall back to provider+suffix matching. Either way a string that matches more
    than one vendor identifies none of them -- parking the wrong vendor would
    take a working rung out of the chain, which is worse than not parking at
    all, and that holds for an exact match as much as for a suffix (#289)."""
    if deployment:
        # Same ambiguity rule as the suffix branch below (#289). Two rungs may
        # legitimately share a `model` and differ only in api_key or api_base --
        # the same model on two accounts, for rate limits that throttle
        # independently, is a normal reason to add a fallback. Returning the
        # first match then parks whichever rung happens to be listed first,
        # every time, and the one taken out of the chain is the one that works.
        matches = [v.get("name") for v in config.WATERFALL
                   if v.get("model") == deployment]
        if len(matches) == 1:
            retval = matches[0]
            return retval
        if len(matches) > 1:
            logging.warning(
                "waterfall: deployment %r matches %d configured vendors; not "
                "parking any -- give them distinct models", deployment, len(matches))
            retval = None
            return retval
    model = str(getattr(exc, "model", "") or "")
    provider = str(getattr(exc, "llm_provider", "") or "")
    if model:
        matches = [v.get("name") for v in config.WATERFALL
                   if v.get("model") == model
                   or (v.get("model", "").endswith("/" + model)
                       and (not provider or v.get("model", "").startswith(provider + "/")))]
        if len(matches) == 1:
            retval = matches[0]
            return retval
        if len(matches) > 1:
            logging.warning(
                "waterfall: %r matches %d configured vendors; not parking any", model, len(matches))
            retval = None
            return retval
    retval = None
    return retval


def _answering_vendor(resp):
    """Which configured vendor answered, from the response.

    `model` alone is not enough for the same reason `_deployment_of` exists:
    litellm strips the provider prefix, so two vendors reached through
    different routers report the same string. The deployment id the Router
    used -- `primary`, `fb0` -- is positional, and `_RUNG_VENDORS` records what
    those positions meant *when that Router was built*: parking a vendor
    rebuilds and renumbers, so resolving against the live waterfall would
    credit a response in flight to whoever now holds its id."""
    try:
        hidden = getattr(resp, "_hidden_params", None) or {}
        dep = str(hidden.get("model_id") or "")
        if dep in _RUNG_VENDORS:
            return _RUNG_VENDORS[dep]
        model = str(getattr(resp, "model", "") or "")
        matches = [v.get("name") for v in config.WATERFALL
                   if v.get("model") == model or v.get("model", "").endswith("/" + model)]
        retval = matches[0] if len(matches) == 1 else None
        return retval
    except Exception:
        return None


def is_budget_error(exc):
    """A 402, or a 400/403 that names a spend problem. A 402 needs no marker:
    it has no other reading, and OpenRouter's most common one -- "This request
    requires more credits, or fewer max_tokens ... can only afford N" -- names
    none, so it was re-dialled every turn. A 400 still needs one, because it is
    also 'your request was malformed'."""
    status = getattr(exc, "status_code", None)
    if status == 402:
        retval = True
        return retval
    if status not in (400, 403):
        retval = False
        return retval
    text = str(getattr(exc, "message", "") or str(exc)).lower()
    retval = any(marker in text for marker in _BUDGET_MARKERS)
    return retval


def park(exc, deployment=""):
    """Park the vendor that raised `exc`. Returns its name, or None when the
    vendor could not be identified -- in which case parking nothing is the safe
    choice, since parking the wrong one removes a working rung."""
    if not config.BUDGET_PARK_SEC:
        retval = None
        return retval
    name = _vendor_for(deployment, exc)
    if name is None:
        logging.warning("waterfall: budget error from an unidentified vendor; not parking")
        retval = None
        return retval
    if name in _parked():
        retval = name  # already parked; the callback fires per attempt
        return retval
    text = str(getattr(exc, "message", "") or str(exc))
    until, human = _park_until(text)
    _budget_parked()  # prune first, so the write below carries no expired entry

    def _park(parked):
        parked = dict(parked or {})
        parked[name] = until
        return parked
    _, ok = state.update(_STATE_KEY, _park)  # one locked step: a concurrent park is not lost (#363)
    if not ok:
        # Nothing persisted, so a rebuilt router would still call it; say so
        # rather than log a park that did not happen.
        logging.error("waterfall: %s is out of budget but the park could not be recorded", name)
        retval = None
        return retval
    # The message can carry the failed request; never log it (#72 covers the
    # handlers, this keeps the vendor's prose out of the record entirely).
    logging.warning("waterfall: %s is out of budget; parked %s", name, human)
    _invalidate()
    retval = name
    return retval


def dead_reason(exc):
    """(reason, suggested slug or "") when `exc` says this rung cannot work as
    configured; None otherwise. The reason is a fixed label, never the vendor's
    text, which carries account and function ids. Both statuses need the text to
    say the model or endpoint itself is gone (`_DEAD_404`, `_DEAD_400`): either
    can also mean "this one request cannot be served"."""
    status = getattr(exc, "status_code", None)
    text = str(getattr(exc, "message", "") or str(exc))
    if status == 404 and _DEAD_404.search(text) and not _LIVE_404.search(text):
        reason = "the vendor says this model or endpoint does not exist for this account (404)"
    elif status == 400 and _DEAD_400.search(text):
        reason = "the vendor refuses this model for this account or plan (400)"
    else:
        retval = None
        return retval
    match = _SUGGESTED_SLUG.search(text)
    retval = (reason, match.group(1).rstrip(".") if match else "")
    return retval


def retry_delay(exc):
    """Seconds a 429 asks the caller to wait before asking again, or None when
    it is not a 429 or names no delay. RetryInfo's `retryDelay` in the error
    text first (Gemini), then a `retry-after-ms` / `retry-after` header in
    seconds; an HTTP-date Retry-After is not parsed. Never below 1s."""
    if getattr(exc, "status_code", None) != 429:
        retval = None
        return retval
    seconds = None
    match = _RETRY_DELAY.search(str(getattr(exc, "message", "") or str(exc)))
    if match:
        seconds = float(match.group(1))
    else:
        headers = getattr(exc, "litellm_response_headers", None)
        if headers is None:
            headers = getattr(getattr(exc, "response", None), "headers", None)
        try:
            ms = headers.get("retry-after-ms") if headers is not None else None
            sec = headers.get("retry-after") if headers is not None else None
            if ms is not None:
                seconds = float(ms) / 1000
            elif sec is not None:
                seconds = float(sec)
        except (AttributeError, TypeError, ValueError):
            seconds = None
    if seconds is None or not math.isfinite(seconds) or seconds < 0:
        retval = None
        return retval
    retval = max(1, math.ceil(seconds))
    return retval


def _hours(sec):
    """A park length for people, rounded up: "45m", "2h"."""
    retval = f"{math.ceil(sec / 60)}m" if sec < 3600 else f"{math.ceil(sec / 3600)}h"
    return retval


def kill(exc, deployment=""):
    """Park the rung that raised `exc` as dead and say so at ERROR. Returns its
    name, or None when `exc` is not a dead-rung error or the rung cannot be
    identified (parking a guess would take a working rung out).

    The park doubles per repeat within the record's history window, from
    `_DEAD_PARK_FIRST` to `_DEAD_PARK_MAX`. With parking off
    (`budget_park_sec: 0`) nothing is parked, but the rung is still logged and
    announced -- once per history window, since an unparked rung fails every
    turn."""
    found = dead_reason(exc)
    if found is None:
        retval = None
        return retval
    reason, suggest = found
    hint = f"; the vendor suggests model {suggest!r}" if suggest else ""
    name = _vendor_for(deployment, exc)
    if name is None:
        logging.error("waterfall: DEAD RUNG %s: %s%s -- could not tell which configured "
                      "rung it is, so not parking it", deployment or "unknown rung", reason, hint)
        retval = None
        return retval
    with _DEAD_LOCK:
        retval = _kill_locked(name, reason, suggest, hint)
    return retval


def _kill_locked(name, reason, suggest, hint):
    now = time.time()
    parking = bool(config.BUDGET_PARK_SEC)
    model = next((v.get("model") for v in config.WATERFALL if v.get("name") == name), "")
    notes, outcome = [], {}

    def _kill(raw):
        records, _ = _prune_dead(raw or {}, now, notes)
        prior = records.get(name)
        if prior and (prior["until"] > now or not parking):
            # Dialled while parked (every rung parked, so the full chain is
            # tried; or a call already in flight), or parking is off. Already
            # announced.
            outcome["again"] = True
            return records
        strikes = (prior.get("strikes") or 1) + 1 if prior else 1
        window = min(_DEAD_PARK_FIRST * 2 ** (strikes - 1), _DEAD_PARK_MAX) if parking else 0
        records[name] = {"until": now + window, "model": model, "reason": reason,
                         "suggest": suggest, "told": False, "strikes": strikes,
                         "back": not parking}  # nothing parked, so nothing to come back from
        outcome["window"] = window
        return records
    # The whole read, decision and write in one state transaction (#363).
    _, ok = state.update(_DEAD_KEY, _kill)
    for line in notes:
        logging.info(line)
    if outcome.get("again"):
        logging.warning("waterfall: %s failed again and is still dead: %s", name, reason)
        retval = name
        return retval
    if not ok:
        action = "could not record it in the state file, so not parking it"
    elif parking:
        action = f"skipping it for {_hours(outcome['window'])}"
    else:
        action = "not parking it (budget_park_sec is 0)"
    logging.error("waterfall: DEAD RUNG %s (%s): %s%s; %s -- fix or remove it in the "
                  "waterfall config", name, model, reason, hint, action)
    if parking and ok:
        _invalidate()
    retval = name
    return retval


def claim_dead_notices():
    """Markdown lines for dead rungs not yet announced, marked announced.

    The Slack ingest posts them in the thread of the turn that just ended, so
    the notice reaches an operator without a new transport -- Slack only: a
    Signal group on a shared account is no place for an operator notice. Once
    per park: the flag lives in the state file, so a restart neither repeats
    nor loses one. The line names the rung, never its model string, which for
    some providers carries a cloud account id; the model is in the ERROR log
    line."""
    with _DEAD_LOCK:
        retval = _claim_locked()
    return retval


def _claim_locked():
    now = time.time()
    notes, lines = [], []

    def _claim(raw):
        records, _ = _prune_dead(raw or {}, now, notes)
        del lines[:]
        for name, rec in records.items():
            if rec.get("told"):
                continue
            records[name] = dict(rec, told=True)
            if not config.BUDGET_PARK_SEC:
                action = "Parking is off, so it is still being tried"
            elif rec["until"] > now:
                action = f"Skipping it for {_hours(rec['until'] - now)}"
            else:
                action = "Its park has run out, so it is being tried again"
            line = (f"\U0001F6A8 LLM rung **{name}** is dead: {rec.get('reason')}. "
                    f"{action}; fix or remove it in the waterfall config.")
            if rec.get("suggest"):
                line += f" The vendor suggests `{rec['suggest']}`."
            lines.append(line)
        return records
    # Mark and claim in one state transaction: of two processes claiming at
    # once, the second sees told=True and gets nothing (#363). Nothing to
    # announce unless the mark landed, or a later claim would repeat it. Skip
    # the write entirely when there is nothing unannounced.
    pending = any(isinstance(r, dict) and not r.get("told")
                  for r in (state.get(_DEAD_KEY) or {}).values())
    retval = []
    if pending:
        _, ok = state.update(_DEAD_KEY, _claim)
        for line in notes:
            logging.info(line)
        retval = list(lines) if ok else []
    return retval


class _BudgetWatch(CustomLogger):
    """Park on litellm's per-deployment failure callback.

    This is the only hook that sees a failure the fallbacks went on to cover --
    and that is the whole case: the turn still gets answered, so nothing raises,
    yet the exhausted vendor must not be dialled again next turn."""

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        _on_failure(kwargs)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        _on_failure(kwargs)


def _on_failure(kwargs):
    exc = kwargs.get("exception")
    if exc is None:
        return
    if isinstance(exc, litellm.Timeout):
        # Named in the log the way parking is (#125): a rung that keeps timing
        # out should be visible as a pattern, not as stack traces.
        logging.warning("waterfall: %s timed out; failing over", _deployment_of(kwargs) or "unknown rung")
        return
    if is_budget_error(exc):
        park(exc, _deployment_of(kwargs))
        return
    if dead_reason(exc) is not None:
        kill(exc, _deployment_of(kwargs))  # logs itself: ERROR when new, WARNING when again
        return
    if getattr(exc, "status_code", None) == 404:
        # A 404 the dead-rung rules do not recognise (#351): litellm cools it
        # for 60s and the chain moves on, so it costs nothing visible -- which
        # is how a retired slug sat in the chain unnoticed. No network check at
        # startup can tell a dead slug from a live one, so say it here, where
        # the vendor has just said it.
        logging.warning("waterfall: %s answered 404 (%s); failing over. If this repeats, "
                        "check its model slug in the waterfall config",
                        _deployment_of(kwargs) or "unknown rung", type(exc).__name__)
        return
    # Named too. When a fallback covers the failure nothing raises and
    # litellm logs nothing at WARNING, so a rung that was rate-limited,
    # erroring or holding a bad key left no trace at all. Type and status
    # only: the message can carry the failed request (#72).
    logging.warning("waterfall: %s failed (%s %s)", _deployment_of(kwargs) or "unknown rung",
                    type(exc).__name__, getattr(exc, "status_code", None) or "no status")


_WATCH = _BudgetWatch()


def _watch():
    """Register the failure callback once. litellm.callbacks is global, and a
    duplicate registration would park (idempotently) twice per failure."""
    if not any(isinstance(cb, _BudgetWatch) for cb in litellm.callbacks):
        litellm.callbacks = list(litellm.callbacks) + [_WATCH]


def _invalidate():
    global _LIVE
    _LIVE = None


def _deployment(model_name, vendor):
    # A subscription rung (codex, #35) has no api_key at all: it authenticates
    # from the CLI's own token file. Sending `api_key: None` is not the same as
    # omitting it -- litellm treats the key as present-but-empty.
    params = {"model": vendor["model"]}
    # Every rung gets a per-request ceiling (#125): a rung that hangs must
    # become a Timeout the Router can fail over, not a held turn.
    params["timeout"] = vendor.get("timeout_sec") or config.WATERFALL_TIMEOUT
    if vendor.get("api_key"):
        params["api_key"] = vendor["api_key"]
    if vendor.get("api_base"):
        params["api_base"] = vendor["api_base"]
    retval = {"model_name": model_name, "litellm_params": params}
    return retval


def _build():
    """The Router alone; see `_build_with_rungs`."""
    retval = _build_with_rungs()[0]
    return retval


def _build_with_rungs():
    """(Router, its rungs as `[(id, vendor, litellm_params)]`), from one read of
    the live waterfall, so the two always describe the same chain (#351)."""
    _watch()
    # Registered before the Router is built, not at import: a `codex/` row is
    # optional, and litellm must know the prefix by the time it resolves one.
    codex_llm.register()
    wf = _live_waterfall()
    if not wf:
        raise SystemExit("config waterfall is empty -- add at least one vendor")
    model_list = [_deployment("primary", wf[0])]
    rest = wf[1:]
    for i, vendor in enumerate(rest):
        model_list.append(_deployment(f"fb{i}", vendor))
    # Which rung is which, fixed at build time (#190). Reading it back from the
    # live waterfall at attribution time is a race: parking a vendor rebuilds
    # the Router and renumbers the rungs, so a response already in flight would
    # be credited to whichever vendor now holds its id. The ids are positional,
    # and this is the only place that knows what they meant.
    global _RUNG_VENDORS
    _RUNG_VENDORS = {m["model_name"]: (wf[0] if m["model_name"] == "primary"
                                       else rest[int(m["model_name"][2:])]).get("name")
                     for m in model_list}
    # The chain starts at fb0, not at the primary (#351): `complete()` asks the
    # primary alone, so it can wait out a short 429 before anything falls over,
    # and then hands the request to fb0 with the rest behind it.
    rungs = [(m["model_name"], (wf[0] if m["model_name"] == "primary"
                                else rest[int(m["model_name"][2:])]).get("name"),
              dict(m["litellm_params"]))
             for m in model_list]
    fallbacks = [{"fb0": [f"fb{i}" for i in range(1, len(rest))]}] if len(rest) > 1 else []
    router = Router(
        model_list=model_list,
        fallbacks=fallbacks,
        num_retries=1,
        cooldown_time=60,
        # Cool a rate-limited deployment on the FIRST 429 rather than after the
        # default fail threshold (#51). A Slack agent's traffic is bursty and
        # low-volume: by the time a threshold is reached the burst is over, and
        # every fail in it was a wasted round-trip.
        allowed_fails=0,
    )
    retval = (router, rungs)
    return retval


def _ensure():
    """Build the router, or rebuild it when the set of usable vendors changed --
    a park added one, or a park expired and gave one back. Returns the router
    and its rungs as built, `[(id, vendor, litellm_params), ...]`, together:
    a rebuild renumbers the rungs, so they are only meaningful for that router."""
    global _LIVE
    with _BUILD_LOCK:
        live = _LIVE
        vendors = tuple(v.get("name") for v in _live_waterfall())
        if live is None or vendors != live[2]:
            if live is not None:
                logging.info("waterfall: rebuilding, chain is now %s", " -> ".join(vendors))
            router, rungs = _build_with_rungs()
            # The vendors key is what was actually built, not the read above:
            # a park landing in between would otherwise mislabel this router.
            live = (router, rungs, tuple(vendor for _id, vendor, _params in rungs))
            _LIVE = live
    retval = (live[0], live[1])
    return retval


def _retry_primary(exc, rung, kwargs):
    """Wait out a short 429 on the primary and ask it once more (#351). Returns
    the response, or None when there is nothing to wait for or the retry failed
    too -- either way the caller falls over to the rest of the chain.

    The retry goes to litellm directly, not through the Router: the Router has
    already cooled the deployment for `cooldown_time`, longer than the delay
    being honoured, and would refuse it without dialling. The failure callback
    still sees a failed retry -- `metadata.deployment` is what it identifies the
    rung by -- so a budget or dead-rung error here parks as it would anywhere."""
    delay = retry_delay(exc)
    _rung_id, vendor, params = rung
    if delay is None:
        retval = None
        return retval
    if delay > _RETRY_WAIT_CAP:
        logging.warning("waterfall: %s is rate-limited for %ss, past the %ss wait cap; "
                        "failing over", vendor, delay, _RETRY_WAIT_CAP)
        retval = None
        return retval
    logging.warning("waterfall: %s is rate-limited; retrying it in %ss before failing over",
                    vendor, delay)
    time.sleep(delay)
    try:
        resp = litellm.completion(**params, **kwargs, metadata={"deployment": params.get("model")})
    except Exception as again:  # noqa: BLE001 -- the chain is still there to try
        logging.warning("waterfall: %s failed again after the wait (%s %s); failing over",
                        vendor, type(again).__name__,
                        getattr(again, "status_code", None) or "no status")
        retval = None
        return retval
    logging.info("waterfall: %s answered after the wait", vendor)
    # The Router still has the primary cooled for the rest of `cooldown_time`,
    # so every later step of this turn would skip a rung that just answered.
    # A rebuild drops that cooldown (and the other rungs' 60s ones -- see the
    # module docstring for why that is a rounding error).
    _invalidate()
    retval = resp
    return retval


def complete(messages, tools=None):
    """Return the raw assistant message (has .content and .tool_calls).

    The primary is asked alone first, so a short 429 can be waited out on it
    before anything falls over (#351); then fb0, with the rest of the chain as
    its fallbacks. Everything else is the Router's, as before.

    No try/except for budget errors here on purpose: when a fallback covers the
    failure nothing is raised, so parking lives in the failure callback instead.
    An exception reaching this caller means the whole chain failed, which parking
    cannot rescue -- the vendors are already parked by the callback, and the next
    turn rebuilds without them."""
    kwargs = {"messages": messages}
    if tools:
        kwargs["tools"] = tools
    router, rungs = _ensure()
    try:
        # num_retries=0: with no fallbacks behind it the Router would re-dial a
        # 429'd primary at once, which is neither the wait nor the failover.
        resp = router.completion(model=rungs[0][0], num_retries=0, **kwargs)
        vendor = None
    except Exception as exc:
        resp = _retry_primary(exc, rungs[0], kwargs)
        if resp is None and len(rungs) < 2:
            raise
        vendor = rungs[0][1] if resp is not None else None
        if resp is None:
            resp = router.completion(model=rungs[1][0], **kwargs)
    # What it cost, on the rung that actually answered (#190). The Router may
    # have failed over, so the vendor is read back off the response rather than
    # assumed to be the primary. A direct retry carries no Router id, so it is
    # credited to the rung it was sent to.
    cost.note(resp, vendor or _answering_vendor(resp))
    retval = resp.choices[0].message
    return retval


def reply(messages):
    retval = complete(messages).content
    return retval
