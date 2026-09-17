"""What each model call cost, captured per turn (#190).

The waterfall already knows when a vendor's budget is exhausted and parks it
(#80). It did not know what anything *cost*, so there was no answer to "what
did this channel spend today" and no way to see that a prompt or skill change
made every turn more expensive.

LiteLLM computes the per-response cost already, so this is capture and rollup
rather than pricing.

**Unknown cost is None, never 0.** A subscription rung (the codex one) and a
model missing from LiteLLM's cost map both produce no number. Recording that as
zero would make a rollup quietly wrong in the one direction nobody checks --
spending that reports as free. Tokens are still recorded, so an unpriced rung
is visible as usage even where it has no price.

Accumulation is thread-local because that is what a turn is: Bolt handles each
Slack event on its own thread, so a per-turn collector is exactly a per-thread
one, and two channels talking at once cannot pour into each other's total.
"""
import logging
import threading

_local = threading.local()


def _calls():
    if not hasattr(_local, "calls"):
        _local.calls = []
    return _local.calls


def start():
    """Begin a turn. Clears whatever the thread was carrying -- a turn that
    raised before draining must not bill the next one."""
    _local.calls = []


def _tokens(usage):
    """(prompt, completion, cached) from a litellm usage object, each None when
    it is not reported rather than 0."""
    if usage is None:
        return (None, None, None)
    get = usage.get if isinstance(usage, dict) else lambda k, d=None: getattr(usage, k, d)
    prompt = get("prompt_tokens")
    completion = get("completion_tokens")
    details = get("prompt_tokens_details") or None
    cached = None
    if details is not None:
        dget = details.get if isinstance(details, dict) else lambda k, d=None: getattr(details, k, d)
        cached = dget("cached_tokens")
    return (prompt, completion, cached)


def note(resp, vendor=None):
    """Record one completed call. Never raises: a turn that answered is not one
    to fail over bookkeeping."""
    try:
        hidden = getattr(resp, "_hidden_params", None) or {}
        cost = hidden.get("response_cost")
        prompt, completion, cached = _tokens(getattr(resp, "usage", None))
        entry = {
            "vendor": vendor,
            "model": str(getattr(resp, "model", "") or "") or None,
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "cached_tokens": cached,
            # None, not 0: see the module docstring.
            "cost": float(cost) if isinstance(cost, (int, float)) else None,
        }
        _calls().append(entry)
    except Exception:
        logging.exception("cost: could not record a call")


def peek():
    """This turn's calls so far, without clearing -- what a mid-turn question
    about cost has to read, since the turn has not been recorded yet."""
    retval = list(_calls())
    return retval


def drain():
    """This turn's calls, clearing them."""
    retval = list(_calls())
    _local.calls = []
    return retval


def total(calls):
    """(cost, priced, unpriced) over a list of call records.

    `unpriced` is the count of calls that reported no cost, and it is returned
    rather than folded in so a caller can say "$0.04 over 3 calls, 1 unpriced"
    instead of implying the total is complete."""
    cost = 0.0
    priced = 0
    unpriced = 0
    for c in calls or []:
        v = c.get("cost")
        if isinstance(v, (int, float)):
            cost += float(v)
            priced += 1
        else:
            unpriced += 1
    retval = (round(cost, 6), priced, unpriced)
    return retval


def summarize(calls):
    """A one-line human summary of a list of call records."""
    cost, priced, unpriced = total(calls)
    if not priced and not unpriced:
        retval = "no model calls recorded"
        return retval
    parts = [f"${cost:.4f} over {priced + unpriced} call(s)"]
    if unpriced:
        parts.append(
            f"{unpriced} of them unpriced (a subscription rung or a model with no "
            f"cost entry) -- the real total is higher than this"
        )
    retval = "; ".join(parts)
    return retval
