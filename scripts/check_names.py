"""Name pass of check-sensitive-terms.sh: find wordlist terms in files.

Usage: python3 -I scripts/check_names.py <terms-file> <path> [<path> ...]
Prints grep-style `path:line:text` for each hit; exits 1 on any, else 0.

grep cannot do this rule: the term is found case-INsensitively, but whether it
stands on a word boundary is decided case-SENSITIVELY on the original text,
where a camelCase hump counts as a boundary. `grep -iw` (#335) treats a whole
identifier as one word, so a listed `acmecorp` in `AcmeCorpThing` or
`ACMECORP_PROD` went uncaught -- the shape a client name takes in code. Plain
substring matching catches those but also fires on a short term inside an
ordinary word (`rubzebra`) or a lowercase run (`labelZebra`), which is what
#335 removed. Same rule as skillz#392.

Each term is an extended regex, as before; a multi-word term (`seeds of fog`)
also matches as one identifier: `SeedsOfFog`, `seeds_of_fog`, `seeds-of-fog`.
"""
import os
import re
import sys


def boundary_ok(text, start, end):
    """Start: beginning of text, a non-alphanumeric before it, or the match
    starts uppercase right after a lowercase letter or digit (myAcmeCorp).
    End: end of text, a non-alphanumeric after it, or the next character is
    uppercase while the match ended lowercase or on a digit (AcmeCorpThing)."""
    if end <= start:
        return False
    before = text[start - 1] if start > 0 else ""
    first = text[start]
    after = text[end] if end < len(text) else ""
    last = text[end - 1]
    start_ok = (not before or not before.isalnum()
                or (first.isupper() and (before.islower() or before.isdigit())))
    end_ok = (not after or not after.isalnum()
              or (after.isupper() and (last.islower() or last.isdigit())))
    retval = start_ok and end_ok
    return retval


def compile_terms(path):
    retval = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            term = line.strip()
            if not term or term.startswith("#"):
                continue
            variants = {term}
            # Identifier variants only for a plain multi-word term: splitting a
            # regex on its spaces would cut through its syntax.
            if not re.search(r"[][\\^$.|?*+(){}]", term):
                words = re.split(r"[\s_-]+", term)
                if len(words) > 1:
                    variants |= {sep.join(words) for sep in ("", "_", "-", " ")}
            for variant in variants:
                try:
                    retval.append(re.compile(variant, re.IGNORECASE))
                except re.error:
                    # grep -E and Python regex differ at the edges; a term
                    # Python cannot compile still counts, as a literal.
                    retval.append(re.compile(re.escape(variant), re.IGNORECASE))
    return retval


def files(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = [d for d in dirs if d != ".git"]
                for name in sorted(names):
                    yield os.path.join(root, name)
        elif os.path.isfile(path):
            yield path


def main(argv):
    patterns = compile_terms(argv[1])
    retval = 0
    for path in files(argv[2:]):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if b"\0" in data:
            continue  # binary, like grep -I
        for number, text in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            if any(boundary_ok(text, m.start(), m.end())
                   for p in patterns for m in p.finditer(text)):
                print(f"{path}:{number}:{text}")
                retval = 1
    return retval


if __name__ == "__main__":
    sys.exit(main(sys.argv))
