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

Parking rebuilds the Router without that vendor rather than reaching into
litellm's private cooldown: the group names here are positional (`primary`,
`fb0`, ...) and `complete()` asks for `primary` by name, so dropping the primary
is a *renaming*, not a deletion. Rebuilding is also public API, so a litellm
upgrade cannot break it. Expiries live in the state file, because a watchdog
restart would otherwise un-learn everything.

Cost of a rebuild: litellm's in-memory 429 cooldowns for the other deployments
reset. They cool for 60s; this is a rounding error against re-dialling a vendor
that is dead for a month."""
import datetime
import logging
import re
import time

import litellm
from litellm import Router

from . import config, state

# Never let the rented router log raw request params -- they carry api_key.
# Belt and suspenders: disable verbose mode AND cap the LiteLLM logger at
# WARNING, so a stray LITELLM_LOG=DEBUG or a library default flip cannot dump a
# credential into the logs. (Redaction lesson from voitta-yolt#84.)
litellm.set_verbose = False
litellm.suppress_debug_info = True
# Cap ALL THREE LiteLLM loggers: _turn_on_debug() flips every one to DEBUG, and
# it is "LiteLLM Router" (not "LiteLLM") that services the Router used here.
for _name in ("LiteLLM", "LiteLLM Router", "LiteLLM Proxy"):
    logging.getLogger(_name).setLevel(logging.WARNING)

_ROUTER = None
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


def _parked():
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
    than being trusted -- a mis-parse could park a vendor for a year."""
    match = _REGAIN_DATE.search(message or "")
    if match:
        try:
            when = datetime.datetime(
                int(match.group(1)), int(match.group(2)), int(match.group(3)),
                tzinfo=datetime.timezone.utc,
            ).timestamp()
            if when > time.time():
                retval = (when, f"until {match.group(0).split('on ')[1]}")
                return retval
        except ValueError:
            logging.warning("waterfall: unparseable regain date; using the default window")
    retval = (time.time() + config.BUDGET_PARK_SEC, f"for {config.BUDGET_PARK_SEC}s")
    return retval


def _vendor_for(exc):
    """Which configured vendor raised this. litellm strips the provider prefix
    from `model` (config `openrouter/openai/gpt-4o` arrives as `openai/gpt-4o`),
    so match on suffix, with llm_provider as the cross-check."""
    model = str(getattr(exc, "model", "") or "")
    provider = str(getattr(exc, "llm_provider", "") or "")
    for vendor in config.WATERFALL:
        configured = vendor.get("model", "")
        if model and (configured == model or configured.endswith("/" + model)):
            retval = vendor.get("name")
            return retval
    for vendor in config.WATERFALL:
        if provider and vendor.get("model", "").startswith(provider + "/"):
            retval = vendor.get("name")
            return retval
    retval = None
    return retval


def is_budget_error(exc):
    """A 4xx that names a spend problem. Status alone is not enough: 400 is also
    'your request was malformed', and 402 is unambiguous but rare."""
    status = getattr(exc, "status_code", None)
    if status not in (400, 402, 403):
        retval = False
        return retval
    text = str(getattr(exc, "message", "") or str(exc)).lower()
    retval = any(marker in text for marker in _BUDGET_MARKERS)
    return retval


def park(exc):
    """Park the vendor that raised `exc`. Returns its name, or None if the vendor
    could not be identified (in which case parking nothing is the safe choice --
    parking the wrong vendor would take a working rung out of the chain)."""
    if not config.BUDGET_PARK_SEC:
        retval = None
        return retval
    name = _vendor_for(exc)
    if name is None:
        logging.warning("waterfall: budget error from an unidentified vendor; not parking")
        retval = None
        return retval
    text = str(getattr(exc, "message", "") or str(exc))
    until, human = _park_until(text)
    parked = dict(_parked())
    parked[name] = until
    state.put(_STATE_KEY, parked)
    # The message can carry the failed request; never log it (#72 covers the
    # handlers, this keeps the vendor's prose out of the record entirely).
    logging.warning("waterfall: %s is out of budget; parked %s", name, human)
    _invalidate()
    retval = name
    return retval


def _invalidate():
    global _ROUTER, _ROUTER_VENDORS
    _ROUTER, _ROUTER_VENDORS = None, None


def _deployment(model_name, vendor):
    params = {"model": vendor["model"], "api_key": vendor.get("api_key")}
    if vendor.get("api_base"):
        params["api_base"] = vendor["api_base"]
    retval = {"model_name": model_name, "litellm_params": params}
    return retval


def _build():
    wf = _live_waterfall()
    if not wf:
        raise SystemExit("config waterfall is empty -- add at least one vendor")
    model_list = [_deployment("primary", wf[0])]
    rest = wf[1:]
    for i, vendor in enumerate(rest):
        model_list.append(_deployment(f"fb{i}", vendor))
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

    A budget failure parks the vendor and retries once on the shortened chain, so
    the turn that discovers the exhaustion still gets answered rather than
    surfacing the error to the user."""
    kwargs = {"model": "primary", "messages": messages}
    if tools:
        kwargs["tools"] = tools
    try:
        resp = _ensure().completion(**kwargs)
    except Exception as exc:
        if not is_budget_error(exc) or park(exc) is None:
            raise
        resp = _ensure().completion(**kwargs)
    retval = resp.choices[0].message
    return retval


def reply(messages):
    retval = complete(messages).content
    return retval
