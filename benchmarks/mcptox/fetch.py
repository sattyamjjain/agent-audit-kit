#!/usr/bin/env python3
"""The one network step: download the pinned MCPTox file into the cache, verified.

Fetches every file in `corpus.FILES` from the pinned commit of
`corpus.REPOSITORY` (raw.githubusercontent.com, read-only, no token), checks its
size, SHA-256 and git blob id against the pin, and only then moves it into
`corpus.CACHE_DIR`. A file already cached with the right hash is not downloaded
again. Exit 1 on any mismatch or failed download; a mismatching download is
never written to the cache.

The dataset has no license, so the cache is the only place its text may live:
a user cache directory outside the repository (`$XDG_CACHE_HOME/agent-audit-kit/
mcptox`, or `AAK_MCPTOX_CACHE`).

    python benchmarks/mcptox/fetch.py            # fetch and verify
    python benchmarks/mcptox/fetch.py --verify   # offline: check what is cached
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.mcptox import corpus  # noqa: E402

_USER_AGENT = "agent-audit-kit-mcptox-benchmark (+https://github.com/sattyamjjain/agent-audit-kit)"
_TIMEOUT = 120


def _download(url: str, attempts: int = 3) -> bytes:
    last: Exception | None = None
    for _ in range(attempts):
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                body: bytes = resp.read()
                return body
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = exc
    raise RuntimeError(f"GET {url} failed: {last!r}")


def pin_problems(name: str, blob: bytes) -> list[str]:
    """How `blob` differs from the pin for `name`; empty when it matches all three."""
    pin = corpus.FILES[name]
    problems: list[str] = []
    if len(blob) != pin["bytes"]:
        problems.append(f"{name}: {len(blob)} bytes, pinned {pin['bytes']}")
    if corpus.sha256_bytes(blob) != pin["sha256"]:
        problems.append(f"{name}: SHA-256 {corpus.sha256_bytes(blob)} != pinned {pin['sha256']}")
    if corpus.git_blob_sha1(blob) != pin["git_blob_sha1"]:
        problems.append(f"{name}: git blob {corpus.git_blob_sha1(blob)} != pinned {pin['git_blob_sha1']}")
    return problems


def fetch(cache_dir: Path | None = None) -> int:
    failures: list[str] = []
    for name in corpus.FILES:
        target = corpus.cached_file(name, cache_dir)
        if target.is_file() and not pin_problems(name, target.read_bytes()):
            print(f"{name}: already cached and verified at {target}")
            continue
        try:
            blob = _download(corpus.raw_url(name))
        except RuntimeError as exc:
            failures.append(str(exc))
            continue
        problems = pin_problems(name, blob)
        if problems:
            failures.extend(problems)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        # Write beside the target and rename, so a reader never sees half a file.
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".partial-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.replace(tmp, target)
        print(f"{name}: fetched {len(blob)} bytes from {corpus.REPOSITORY}@{corpus.COMMIT[:12]}, "
              f"verified, cached at {target}")
    for msg in failures:
        print(f"  FAILED {msg}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verify", action="store_true", help="Offline: check the cached files against the pins.")
    args = ap.parse_args()
    if args.verify:
        problems = corpus.cache_problems()
        for msg in problems:
            print(f"  {msg}")
        print("cache verified" if not problems else "cache is not filled or does not match the pins")
        return 1 if problems else 0
    return fetch()


if __name__ == "__main__":
    raise SystemExit(main())
