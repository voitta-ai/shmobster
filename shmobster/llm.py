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
budget-exhausted one, logged at ERROR, and announced once in the next reply
(`claim_dead_notices`). The park is keyed to the rung's configured model, so
fixing the config un-parks it at once. It starts short and doubles on each
repeat (`_DEAD_PARK_FIRST` up to `_DEAD_PARK_MAX`), rather than lasting until
restart: the watchdog restarts this process routinely, which would re-learn
(and re-pay) the failure every few minutes. Short first, because a rung can be
fixed vendor-side (access enabled, credit added) with no config edit to notice;
growing, because a rung that really is gone should not be re-dialled hourly."""
import datetime
import logging
import re
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

_ROUTER = None
_RUNG_VENDORS = {}
_ROUTER_VENDORS = None  # the vendor names the live router was built from

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
    r"model_not_found|does not exist|decommissioned"
    r"|the '[^'\n]{1,120}' model is not supported when using codex",
    re.IGNORECASE)

# OpenRouter: "use this slug instead: <slug>". Charset- and length-bound, so
# nothing but a model slug can ride out of the vendor's body into a log or a
# channel; the body itself carries account and function ids and is never echoed.
_SUGGESTED_SLUG = re.compile(r"use this slug instead:\s*([A-Za-z0-9][A-Za-z0-9._:/-]{0,119})")


def _dead_records():
    """Every dead-rung record that still applies, in force or not: recorded
    against the model the rung is configured with now, and not yet past its
    history window. Pruned on read; a park running out is logged once."""
    raw = state.get(_DEAD_KEY) or {}
    now = time.time()
    models = {v.get("name"): v.get("model") for v in config.WATERFALL}
    kept, changed = {}, False
    for name, rec in raw.items():
        if not (isinstance(rec, dict) and isinstance(rec.get("until"), (int, float))):
            changed = True
            continue
        if rec.get("model") != models.get(name):
            changed = True
            if rec["until"] > now:
                logging.info("waterfall: %s's config changed; out of its dead-rung park", name)
            continue
        if rec["until"] + _DEAD_PARK_MAX <= now:
            changed = True
            continue
        if rec["until"] <= now and not rec.get("back"):
            rec = dict(rec, back=True)
            changed = True
            logging.info("waterfall: %s is out of its dead-rung park; back in the chain", name)
        kept[name] = rec
    if changed:
        state.put(_DEAD_KEY, kept)
    retval = kept
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
    raw = state.get(_STATE_KEY) or {}
    now = time.time()
    live = {name: until for name, until in raw.items()
            if isinstance(until, (int, float)) and until > now}
    if len(live) != len(raw):
        state.put(_STATE_KEY, live)
        for name in set(raw) - set(live):
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
    parked = dict(_budget_parked())
    parked[name] = until
    state.put(_STATE_KEY, parked)
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


def _hours(sec):
    retval = f"{sec // 3600}h"
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
    records = dict(_dead_records())
    prior = records.get(name)
    now = time.time()
    parking = bool(config.BUDGET_PARK_SEC)
    if prior and (prior["until"] > now or not parking):
        # Dialled while parked (every rung parked, so the full chain is tried;
        # or a call already in flight), or parking is off. Already announced.
        logging.warning("waterfall: %s failed again and is still dead: %s", name, reason)
        retval = name
        return retval
    model = next((v.get("model") for v in config.WATERFALL if v.get("name") == name), "")
    strikes = (prior.get("strikes") or 1) + 1 if prior else 1
    window = min(_DEAD_PARK_FIRST * 2 ** (strikes - 1), _DEAD_PARK_MAX) if parking else 0
    records[name] = {"until": now + window, "model": model, "reason": reason,
                     "suggest": suggest, "told": False, "strikes": strikes,
                     "back": not parking}  # nothing parked, so nothing to come back from
    state.put(_DEAD_KEY, records)
    action = (f"skipping it for {_hours(window)}" if parking
              else "not parking it (budget_park_sec is 0)")
    logging.error("waterfall: DEAD RUNG %s (%s): %s%s; %s -- fix or remove it in the "
                  "waterfall config", name, model, reason, hint, action)
    if parking:
        _invalidate()
    retval = name
    return retval


def claim_dead_notices():
    """Channel lines for dead rungs not yet announced, marked announced.

    The handler appends them to the next reply, and the Slack ingest to its
    error reply when every rung failed, so the notice reaches whoever is in the
    channel without a new transport. Once per park: the flag lives in the state
    file, so a restart neither repeats nor loses one. The line names the rung,
    never its model string, which for some providers carries a cloud account
    id; the model is in the ERROR log line."""
    records = dict(_dead_records())
    now = time.time()
    lines = []
    for name, rec in records.items():
        if rec.get("told"):
            continue
        records[name] = dict(rec, told=True)
        if rec["until"] > now:
            action = f"Skipping it for {_hours(int(rec['until'] - now + 59))}"
        else:
            action = "Parking is off, so it is still being tried"
        line = (f":rotating_light: LLM rung *{name}* is dead: {rec.get('reason')}. "
                f"{action}; fix or remove it in the waterfall config.")
        if rec.get("suggest"):
            line += f" The vendor suggests `{rec['suggest']}`."
        lines.append(line)
    if lines:
        state.put(_DEAD_KEY, records)
    retval = lines
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
    global _ROUTER, _ROUTER_VENDORS
    _ROUTER, _ROUTER_VENDORS = None, None


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
    fallbacks = [{"primary": [f"fb{i}" for i in range(len(rest))]}] if rest else []
    retval = Router(
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
    return retval


def _ensure():
    """Build the router, or rebuild it when the set of usable vendors changed --
    a park added one, or a park expired and gave one back."""
    global _ROUTER, _ROUTER_VENDORS
    vendors = tuple(v.get("name") for v in _live_waterfall())
    if _ROUTER is None or vendors != _ROUTER_VENDORS:
        if _ROUTER_VENDORS is not None:
            logging.info("waterfall: rebuilding, chain is now %s", " -> ".join(vendors))
        _ROUTER = _build()
        _ROUTER_VENDORS = vendors
    return _ROUTER


def complete(messages, tools=None):
    """Return the raw assistant message (has .content and .tool_calls).

    No try/except for budget errors here on purpose: when a fallback covers the
    failure nothing is raised, so parking lives in the failure callback instead.
    An exception reaching this caller means the whole chain failed, which parking
    cannot rescue -- the vendors are already parked by the callback, and the next
    turn rebuilds without them."""
    kwargs = {"model": "primary", "messages": messages}
    if tools:
        kwargs["tools"] = tools
    resp = _ensure().completion(**kwargs)
    # What it cost, on the rung that actually answered (#190). The Router may
    # have failed over, so the vendor is read back off the response rather than
    # assumed to be the primary.
    cost.note(resp, _answering_vendor(resp))
    retval = resp.choices[0].message
    return retval


def reply(messages):
    retval = complete(messages).content
    return retval
