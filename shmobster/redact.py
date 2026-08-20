"""Redact credentials before output leaves this process (#72).

Same bug class that bit voitta-yolt (#84, #91): anything that returns command
output verbatim hoards every credential that rides through it. shmobster hands
`run_shell` output straight to a Slack channel, and `cat`, `env` and `printenv`
are read-only -- they clear the YOLT gate and run with no approval.

**One source of truth.** The shape detection is voitta-yolt's `secret_redact`
(v1.0.0+), imported from the same tree as the classifier this instance already
uses, rather than a second pattern list that drifts from it. Its markers name
the shape (`[REDACTED:github-token]`), so a redacted record stays diagnosable.

On top of that, one thing YOLT cannot know: **the secrets this process holds**.
Every Slack token, waterfall api_key and per-channel policy `env` value is
redacted by exact match, so a credential in a format nobody anticipated is still
caught when it is one of ours.

**Fails loudly, never open.** If `secret_redact` cannot be imported, `scrub()`
raises rather than returning text unredacted -- an unredacted channel post is
worse than a failed tool call. `require()` surfaces that at boot instead of on
the first credential.

Redaction happens at collection (the tool result), not only at render, so every
downstream copy -- model context, vendor-side logs, the Slack message -- inherits
it."""
import importlib.util
import os

from . import config

_MARK = "[REDACTED:shmobster-config]"
_MIN_VALUE_LEN = 8

_REDACTOR = None


def _load():
    """Import voitta-yolt's secret_redact from the configured classifier's dir.

    shmobster already points at that tree for the exec gate (exec.yolt_classifier),
    so this needs no second config knob and cannot drift to a different checkout."""
    global _REDACTOR
    if _REDACTOR is not None:
        return _REDACTOR
    classifier = config.YOLT_CLASSIFIER
    if not classifier:
        raise RuntimeError(
            "redaction unavailable: exec.yolt_classifier is not configured, so "
            "voitta-yolt's secret_redact cannot be located"
        )
    path = os.path.join(os.path.dirname(classifier), "secret_redact.py")
    if not os.path.exists(path):
        raise RuntimeError(
            f"redaction unavailable: {path} not found -- voitta-yolt must be "
            "v1.0.0 or newer (secret_redact landed in #84)"
        )
    spec = importlib.util.spec_from_file_location("yolt_secret_redact", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "redact"):
        raise RuntimeError(f"redaction unavailable: {path} has no redact()")
    _REDACTOR = module
    return _REDACTOR


def require():
    """Fail at boot, not at the first credential, if redaction is unavailable."""
    retval = _load() is not None
    return retval


def known_values():
    """Secrets this process holds, longest first -- so a value containing a
    shorter one is masked whole instead of leaving a tail behind."""
    values = [config.SLACK_BOT_TOKEN, config.SLACK_APP_TOKEN]
    for vendor in config.WATERFALL:
        values.append(vendor.get("api_key") or "")
    for policy in list(config.CHANNEL_POLICIES.values()) + [config.DEFAULT_POLICY]:
        for value in (policy.get("env") or {}).values():
            values.append(value)
    retval = sorted(
        {v for v in values if isinstance(v, str) and len(v) >= _MIN_VALUE_LEN},
        key=len,
        reverse=True,
    )
    return retval


def scrub(text):
    """Return `text` with credentials replaced. Non-strings pass through, so a
    caller can wrap a tool result without type-checking it first."""
    if not isinstance(text, str) or not text:
        retval = text
        return retval
    out = text
    for value in known_values():
        if value in out:
            out = out.replace(value, _MARK)
    retval = _load().redact(out)
    return retval
