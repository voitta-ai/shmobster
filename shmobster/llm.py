"""Multi-vendor waterfall via LiteLLM Router, built from config.WATERFALL.

Iter 0: ordered failover (primary -> fb0 -> fb1 -> ...) with a cooldown so a
rate-limited/broken vendor is skipped for a window instead of re-hit every call.
Per-vendor observability + dead-fallback surfacing is Iter 3 (#5)."""
import logging

import litellm
from litellm import Router

from . import config

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


def _deployment(model_name, vendor):
    params = {"model": vendor["model"], "api_key": vendor.get("api_key")}
    if vendor.get("api_base"):
        params["api_base"] = vendor["api_base"]
    retval = {"model_name": model_name, "litellm_params": params}
    return retval


def _build():
    wf = config.WATERFALL
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
    )
    return retval


def _ensure():
    global _ROUTER
    if _ROUTER is None:
        _ROUTER = _build()
    return _ROUTER


def complete(messages, tools=None):
    """Return the raw assistant message (has .content and .tool_calls)."""
    router = _ensure()
    kwargs = {"model": "primary", "messages": messages}
    if tools:
        kwargs["tools"] = tools
    resp = router.completion(**kwargs)
    retval = resp.choices[0].message
    return retval


def reply(messages):
    retval = complete(messages).content
    return retval
