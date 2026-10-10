#!/usr/bin/env python3
"""Network steps for the instruction-file slice: pin the corpus, fill the cache.

Two subcommands, both read-only against public GitHub:

  pin    Download the SENTINEL manifests at the pinned commit, resolve every
         listed repository's metadata and the head commit of its recorded branch
         with one batched GraphQL query per 50 repositories (`gh api graphql`),
         fetch each instruction file at that commit, and write manifest.json with
         the SHA-256 and size of every file. A re-pin is a corpus refresh: it
         moves the slice, so it is never part of `make fp-instruction`.
  fetch  Fill the cache from manifest.json, verifying every SHA-256. A file
         already cached with the right hash is not downloaded again. Exit 1 on
         any mismatch or failed download.

File contents only ever land in `corpus.CACHE_DIR`, a user cache directory
outside the repository (`$XDG_CACHE_HOME/agent-audit-kit/fp-instruction-files`,
or `AAK_FP_INSTRUCTION_CACHE`). manifest.json carries commits, paths and hashes;
the raw URL of every file is `RAW_URL_TEMPLATE` filled in from them.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.false_positive.instruction_files import corpus  # noqa: E402

_USER_AGENT = "agent-audit-kit-fp-benchmark (+https://github.com/sattyamjjain/agent-audit-kit)"
_TIMEOUT = 30
_BATCH = 50
_WORKERS = 8


def _http_get(url: str, attempts: int = 3) -> tuple[int, bytes]:
    """``(status, body)``; a 404 is returned, other failures are retried, then raised."""
    last: Exception | None = None
    for _ in range(attempts):
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return 404, b""
            last = exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = exc
    raise RuntimeError(f"GET {url} failed: {last!r}")


def _sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _cache_path(name_with_owner: str, rel: str) -> Path:
    return corpus.CACHE_DIR / name_with_owner / rel


def _sentinel_manifests() -> dict[str, tuple[str, dict[str, Any]]]:
    out: dict[str, tuple[str, dict[str, Any]]] = {}
    for split, rel in corpus.SENTINEL_FILES.items():
        url = f"https://raw.githubusercontent.com/{corpus.SENTINEL_REPOSITORY}/{corpus.SENTINEL_COMMIT}/{rel}"
        status, body = _http_get(url)
        if status != 200:
            raise RuntimeError(f"SENTINEL manifest {rel} returned HTTP {status}")
        out[split] = (_sha256(body), json.loads(body))
    return out


def _graphql(query: str) -> dict[str, Any]:
    proc = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={query}"],
        capture_output=True, text=True, check=False,
    )
    # A repository that no longer exists comes back as an error next to the data
    # for the rest, and gh exits non-zero for it; the data is still usable.
    try:
        payload: dict[str, Any] = json.loads(proc.stdout or "{}")
    except ValueError as exc:
        raise RuntimeError(f"gh api graphql returned no JSON: {proc.stderr[:500]}") from exc
    if not payload.get("data"):
        raise RuntimeError(f"gh api graphql failed: {proc.stderr[:500] or payload}")
    return payload["data"]


def _repo_metadata(entries: list[tuple[str, str]]) -> dict[str, dict[str, Any] | None]:
    """``{repo: github-metadata | None}`` for ``(repo, branch)`` pairs."""
    out: dict[str, dict[str, Any] | None] = {}
    for start in range(0, len(entries), _BATCH):
        batch = entries[start:start + _BATCH]
        parts = []
        for i, (repo, branch) in enumerate(batch):
            owner, name = repo.split("/", 1)
            parts.append(
                f"r{i}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) "
                "{ nameWithOwner isPrivate isArchived isFork stargazerCount "
                f"ref(qualifiedName: {json.dumps('refs/heads/' + branch)}) {{ target {{ oid }} }} }}"
            )
        data = _graphql("query { " + " ".join(parts) + " }")
        for i, (repo, _branch) in enumerate(batch):
            node = data.get(f"r{i}")
            if not node:
                out[repo] = None
                continue
            ref = node.get("ref") or {}
            out[repo] = {
                "name_with_owner": node["nameWithOwner"],
                "private": bool(node["isPrivate"]),
                "archived": bool(node["isArchived"]),
                "fork": bool(node["isFork"]),
                "stars": int(node["stargazerCount"]),
                "commit": (ref.get("target") or {}).get("oid"),
            }
    return out


def _fetch_file(name_with_owner: str, commit: str, rel: str) -> dict[str, Any]:
    url = corpus.RAW_URL_TEMPLATE.format(name_with_owner=name_with_owner, commit=commit, path=rel)
    try:
        status, body = _http_get(url)
    except RuntimeError as exc:
        return {"path": rel, "error": str(exc)}
    if status != 200:
        return {"path": rel, "error": f"HTTP {status} at the pinned commit"}
    target = _cache_path(name_with_owner, rel)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    return {"path": rel, "sha256": _sha256(body), "bytes": len(body)}


def pin() -> int:
    paths = corpus.instruction_paths()
    sentinel = _sentinel_manifests()
    listed: list[dict[str, Any]] = []
    for split, (_sha, data) in sentinel.items():
        for repo, rec in data["repos"].items():
            listed.append({
                "repo": repo,
                "split": split,
                "branch": rec["branch"],
                "stars_source": int(rec["stars"]),
                "listed_files": sorted(f for f in rec["files"] if f in paths),
            })
    listed.sort(key=lambda r: r["repo"])
    meta = _repo_metadata([(r["repo"], r["branch"]) for r in listed])

    jobs: list[tuple[int, str, str, str]] = []
    for i, rec in enumerate(listed):
        gh = meta.get(rec["repo"])
        if gh and gh.get("commit"):
            for rel in rec["listed_files"]:
                jobs.append((i, gh["name_with_owner"], gh["commit"], rel))
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        fetched = list(pool.map(lambda j: (j[0], _fetch_file(j[1], j[2], j[3])), jobs))

    repos: list[dict[str, Any]] = []
    by_index: dict[int, list[dict[str, Any]]] = {}
    for i, result in fetched:
        by_index.setdefault(i, []).append(result)
    for i, rec in enumerate(listed):
        gh = meta.get(rec["repo"])
        results = sorted(by_index.get(i, []), key=lambda f: f["path"])
        entry: dict[str, Any] = {
            "repo": rec["repo"],
            "split": rec["split"],
            "branch": rec["branch"],
            "stars_source": rec["stars_source"],
            "github": gh,
            "files": [f for f in results if "sha256" in f],
            "unavailable": [{"path": f["path"], "reason": f["error"]} for f in results if "error" in f],
        }
        if gh is None:
            entry["note"] = "repository not found on GitHub at pin time"
        elif not gh.get("commit"):
            entry["note"] = f"branch {rec['branch']!r} not found at pin time"
        repos.append(entry)

    manifest = {
        "schema": 1,
        "source": {
            "name": "SENTINEL bench manifests, published with the #771 report",
            "repository": corpus.SENTINEL_REPOSITORY,
            "commit": corpus.SENTINEL_COMMIT,
            "license": "Apache-2.0",
            "files": {
                split: {
                    "path": corpus.SENTINEL_FILES[split],
                    "sha256": sha,
                    "fetched": data.get("fetched"),
                    "repos": len(data["repos"]),
                }
                for split, (sha, data) in sentinel.items()
            },
        },
        "pinned_at": dt.datetime.now(dt.timezone.utc).date().isoformat(),
        "instruction_paths": list(paths),
        "raw_url_template": corpus.RAW_URL_TEMPLATE,
        "repos": repos,
    }
    problems = corpus.validate_manifest(manifest, paths)
    if problems:
        print("refusing to write an invalid manifest:\n  " + "\n  ".join(problems[:20]))
        return 1
    corpus.MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    pinned = sum(len(r["files"]) for r in repos)
    missing = sum(len(r["unavailable"]) for r in repos)
    print(f"wrote {corpus.MANIFEST.relative_to(REPO_ROOT)}: {len(repos)} repos, "
          f"{pinned} files pinned, {missing} unavailable")
    return 0


def fetch() -> int:
    data = corpus.load_manifest()
    jobs: list[tuple[str, str, str, str]] = []
    skipped = 0
    for rec in data.get("repos") or []:
        gh = rec.get("github") or {}
        for f in rec.get("files") or []:
            target = _cache_path(gh["name_with_owner"], f["path"])
            if target.is_file() and _sha256(target.read_bytes()) == f["sha256"]:
                skipped += 1
                continue
            jobs.append((gh["name_with_owner"], gh["commit"], f["path"], f["sha256"]))

    def _one(job: tuple[str, str, str, str]) -> str | None:
        nwo, commit, rel, want = job
        got = _fetch_file(nwo, commit, rel)
        if "error" in got:
            return f"{nwo}/{rel}: {got['error']}"
        if got["sha256"] != want:
            _cache_path(nwo, rel).unlink(missing_ok=True)
            return f"{nwo}/{rel}: SHA-256 {got['sha256']} != pinned {want}"
        return None

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        failures = [msg for msg in pool.map(_one, jobs) if msg]
    print(f"cache: {skipped} already verified, {len(jobs) - len(failures)} fetched, "
          f"{len(failures)} failed")
    for msg in failures:
        print(f"  {msg}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["pin", "fetch"])
    args = ap.parse_args()
    return pin() if args.command == "pin" else fetch()


if __name__ == "__main__":
    raise SystemExit(main())
