"""shmobster -- a standalone Slack agent.

The version anchor (#76). One string, bumped in its own release commit; CI on
master turns a version with no tag into a tag plus a GitHub release.

Instances run as long-lived services on separate machines, pulling from git, so
"which build is this?" has to be answerable from the outside. `build()` answers
it: the release version plus the checkout's short sha, because between tags the
sha is the only thing that distinguishes two running instances."""
__version__ = "0.5.2"


_BUILD = None


def build():
    """`<version>+<short-sha>` when running from a git checkout, else the bare
    version. Never raises -- an unidentifiable build still has to boot. Cached:
    it goes into every turn's system prompt, and the sha cannot change under a
    running process without a restart."""
    global _BUILD
    if _BUILD is not None:
        return _BUILD

    import os
    import subprocess

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        sha = proc.stdout.strip() if proc.returncode == 0 else ""
    except Exception:
        sha = ""
    if sha:
        retval = f"{__version__}+{sha}"
    else:
        retval = __version__
    _BUILD = retval
    return retval
