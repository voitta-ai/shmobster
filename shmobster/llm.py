"""Multi-vendor waterfall via LiteLLM Router, built from config.WATERFALL.

Iter 0: ordered failover (primary -> fb0 -> fb1 -> ...) with a cooldown so a
rate-limited/broken vendor is skipped for a window instead of re-hit every call.
Per-vendor observability + dead-fallback surfacing is Iter 3 (#5)."""
from litellm import Router

from . import config

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


def reply(messages):
    global _ROUTER
    if _ROUTER is None:
        _ROUTER = _build()
    resp = _ROUTER.completion(model="primary", messages=messages)
    retval = resp.choices[0].message.content
    return retval
