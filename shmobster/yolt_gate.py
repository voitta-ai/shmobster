"""Gate a shell command through voitta-yolt's grammar classifier.

Subprocesses YOLT's `grammar_classifier.py '<command>'`, which prints
{"decision": "safe"|"unsafe", "reason": ...}. "safe" == read-only (auto-run);
anything else (unsafe, error, unconfigured) is treated as mutating -> needs
approval. Fail-closed: if YOLT can't run, we do NOT auto-run."""
import json
import subprocess
import sys

from . import config


def classify(command):
    path = config.YOLT_CLASSIFIER
    if not path:
        retval = ("unsafe", "yolt not configured (exec.yolt_classifier)")
        return retval
    try:
        proc = subprocess.run(
            [sys.executable, path, command],
            capture_output=True,
            text=True,
            timeout=15,
        )
        data = json.loads(proc.stdout)
        retval = (data.get("decision", "unsafe"), data.get("reason", ""))
    except Exception as exc:  # fail closed -> mutating
        retval = ("unsafe", f"yolt error: {exc}")
    return retval


def is_read_only(command):
    decision, _ = classify(command)
    retval = decision == "safe"
    return retval
