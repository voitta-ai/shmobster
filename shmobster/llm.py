"""Multi-vendor waterfall via LiteLLM Router.

Iter 0 keeps it minimal: ordered fallback (primary -> fb0 -> fb1 -> ...) with a
cooldown so a rate-limited/broken vendor is skipped for a window instead of being
re-hit every call. Observability + dead-fallback surfacing is Iter 3 (#5)."""
from litellm import Router

from . import config

_ROUTER = None


def _build():
    models = config.MODELS
    model_list = [{"model_name": "primary", "litellm_params": {"model": models[0]}}]
    rest = models[1:]
    for i, m in enumerate(rest):
        model_list.append({"model_name": f"fb{i}", "litellm_params": {"model": m}})
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
