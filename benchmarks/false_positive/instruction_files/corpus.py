#!/usr/bin/env python3
"""Benign-slice derivation for the instruction-file false-positive benchmark.

The MCP benchmark one directory up measures the rules that fire on MCP server
configs. It says so in its own Limitations: instruction files (`CLAUDE.md`,
`AGENTS.md` and the like) are not in it, so the rules that read them have no
measured false-positive rate. This is the slice that measures them, built the
same way: a committed, pinned corpus, a pre-registered NON-CIRCULAR predicate,
the shipped engine, and a human adjudication that no script writes.

Corpus: the bench manifests the #771 reporter published with their report,
`GarvitAgrawal04/SENTINEL` `bench/results/manifest_main.json` (590 repositories)
and `manifest_heldout.json` (340), pinned at SENTINEL commit `SENTINEL_COMMIT`.
They list popular public repositories that ship instruction files, "presumed
benign, not audited one by one", which is the reporter's own description and the
reason they are a fair benign proxy: nobody selected them for what AAK says
about them. `manifest.json` pins every instruction file AAK reads by repository,
commit SHA, path and SHA-256. File contents are never committed; `fetch.py`
fills a cache outside the repository (`CACHE_DIR`) and verifies every hash.

Pre-registered predicate. A repository is in the benign slice iff ALL hold:

  1. It is listed in the SENTINEL bench manifests (main or held-out) at the
     pinned commit.
  2. At pin time GitHub reports it **public, not archived and not a fork**: the
     canonical, maintained project rather than a copy or a tombstone.
  3. Its **SENTINEL-recorded star count is at least 1,000** (`STAR_FLOOR`). The
     floor is the source's own popularity premise written down; it is read from
     the frozen manifest, not from the live API, so the slice does not move when
     stars do.
  4. It is **not in any CVE / advisory feed AAK ships** (`data/vuln_db.json`
     package names plus the CVE version-pin package names), matched by
     repository name, the same exclusion set the MCP slice uses.
  5. At least one **instruction file** (a path an instruction-file rule reads,
     `instruction_paths()`) was fetched at the pinned commit.

"Benign" is a property of how the repositories were selected and of their own
GitHub metadata. It is deliberately NOT "AAK found nothing", which would make the
measurement circular.

The held-out split is kept, but it is not an unseen test set: both manifests
were scanned during the #771 and #869 matcher rework (2026-10-02 and 2026-10-04),
so this is a tuned measurement, and RESULTS.md says so. The split is reported
because its star band (1,242 to 2,999) differs from main's (6,929 and up).

This module is pure: it reads committed files, hits no network, writes nothing
unless asked to (`--write`).
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[2]
if str(REPO_ROOT) not in sys.path:
    # `python benchmarks/...` puts this directory on sys.path, not the repo, so
    # without this an editable install pointing at another checkout would be
    # the `agent_audit_kit` imported here.
    sys.path.insert(0, str(REPO_ROOT))

MANIFEST = _HERE / "manifest.json"
SLICE_JSON = _HERE / "slice.json"


def _default_cache_dir() -> Path:
    """Where fetched instruction files live: outside the repository, on purpose.

    The first draft kept them under this directory, gitignored, and the next full
    test run failed: `test_scanner_is_silent_on_this_repository` scans the repo
    root, so 1,445 third-party CLAUDE.md / AGENTS.md files read as AAK's own
    surface. A self-scan would have reported them too. A user cache directory is
    outside every scan of the repo, and outside every `git add`.
    """
    override = os.environ.get("AAK_FP_INSTRUCTION_CACHE")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "agent-audit-kit" / "fp-instruction-files"


CACHE_DIR = _default_cache_dir()

SENTINEL_REPOSITORY = "GarvitAgrawal04/SENTINEL"
SENTINEL_COMMIT = "2b70c363512dc7ba76f86d7e16bdedb82740cd66"
SENTINEL_FILES: dict[str, str] = {
    "main": "bench/results/manifest_main.json",
    "heldout": "bench/results/manifest_heldout.json",
}
STAR_FLOOR = 1000
RAW_URL_TEMPLATE = "https://raw.githubusercontent.com/{name_with_owner}/{commit}/{path}"

PREDICATE = (
    "listed in the SENTINEL bench manifests (main or held-out) at commit "
    f"{SENTINEL_COMMIT[:12]} AND public, not archived, not a fork at pin time AND "
    f"SENTINEL-recorded stars >= {STAR_FLOOR} AND not in AAK's shipped CVE/advisory "
    "feed (vuln_db.json + CVE-pin package names) AND at least one instruction file "
    "fetched at the pinned commit"
)

# The order the conjuncts are tested in, which is also the order an excluded
# repository's reason is reported in: the first conjunct it fails.
EXCLUSION_REASONS = (
    "not found on GitHub at pin time",
    "private",
    "archived",
    "fork",
    "below the star floor",
    "in a shipped CVE/advisory feed",
    "no instruction file fetched",
)

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SPLITS = frozenset(SENTINEL_FILES)


def instruction_paths() -> tuple[str, ...]:
    """Every instruction-file path a shipped rule reads, sorted.

    Taken from the scanners rather than written down again, so a path added to
    `agent_config._AGENT_CONFIG_FILES` makes `--check` fail until the corpus is
    re-pinned with it, instead of the slice quietly not measuring the new file.
    """
    from agent_audit_kit.scanners.agent_config import _AGENT_CONFIG_FILES
    from agent_audit_kit.scanners.agent_trust_surface import _GEMINI_INSTRUCTION_NAMES

    return tuple(sorted(set(_AGENT_CONFIG_FILES) | set(_GEMINI_INSTRUCTION_NAMES)))


def cve_feed_identifiers() -> frozenset[str]:
    """The MCP slice's exclusion set, reused so both slices exclude the same names."""
    from benchmarks.false_positive.corpus import cve_feed_identifiers as _mcp_ids

    return _mcp_ids()


def _repo_identifiers(record: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    names = [str(record.get("repo") or "")]
    gh = record.get("github") or {}
    names.append(str(gh.get("name_with_owner") or ""))
    for name in names:
        name = name.lower()
        if name:
            out.add(name)
            out.add(name.split("/")[-1])
    return {n for n in out if n}


def exclusion_reason(record: dict[str, Any], cve_ids: frozenset[str]) -> str | None:
    """The first predicate conjunct `record` fails, or None when it is benign."""
    gh = record.get("github")
    if not isinstance(gh, dict) or not gh.get("commit"):
        return EXCLUSION_REASONS[0]
    if gh.get("private") is not False:
        return EXCLUSION_REASONS[1]
    if gh.get("archived") is not False:
        return EXCLUSION_REASONS[2]
    if gh.get("fork") is not False:
        return EXCLUSION_REASONS[3]
    if int(record.get("stars_source") or 0) < STAR_FLOOR:
        return EXCLUSION_REASONS[4]
    if _repo_identifiers(record) & cve_ids:
        return EXCLUSION_REASONS[5]
    if not record.get("files"):
        return EXCLUSION_REASONS[6]
    return None


def is_benign(record: dict[str, Any], cve_ids: frozenset[str]) -> bool:
    """The pre-registered benign predicate. A pure function of its inputs."""
    return exclusion_reason(record, cve_ids) is None


def load_manifest(manifest_path: Path | None = None) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((manifest_path or MANIFEST).read_text(encoding="utf-8"))
    return data


def validate_manifest(data: dict[str, Any], paths: tuple[str, ...] | None = None) -> list[str]:
    """Problems with a manifest, as human-readable strings; empty when it is valid.

    Checks the shape a reader relies on: the source is the pinned SENTINEL
    commit, every repository has a split and a source star count, every fetched
    file names an instruction path, a 40-hex commit and a 64-hex SHA-256, and no
    path appears twice for one repository. `paths` defaults to the scanners'
    current instruction paths, so a manifest pinned before a path was added is
    reported as needing a re-pin.
    """
    problems: list[str] = []
    expected_paths = tuple(paths) if paths is not None else instruction_paths()
    if data.get("schema") != 1:
        problems.append("schema must be 1")
    source = data.get("source") or {}
    if source.get("repository") != SENTINEL_REPOSITORY:
        problems.append(f"source.repository must be {SENTINEL_REPOSITORY}")
    if source.get("commit") != SENTINEL_COMMIT:
        problems.append(f"source.commit must be the pinned {SENTINEL_COMMIT}")
    for split, rel in SENTINEL_FILES.items():
        entry = (source.get("files") or {}).get(split) or {}
        if entry.get("path") != rel:
            problems.append(f"source.files.{split}.path must be {rel}")
        if not _HEX64.match(str(entry.get("sha256") or "")):
            problems.append(f"source.files.{split}.sha256 is not a 64-hex digest")
    if list(data.get("instruction_paths") or []) != list(expected_paths):
        problems.append(
            "instruction_paths differs from the scanners' current paths "
            f"{list(expected_paths)}; re-pin with `make fp-instruction-pin`"
        )
    seen: set[str] = set()
    for i, rec in enumerate(data.get("repos") or []):
        where = f"repos[{i}]"
        repo = str(rec.get("repo") or "")
        if not _REPO_RE.match(repo):
            problems.append(f"{where}: repo {repo!r} is not owner/name")
        if repo in seen:
            problems.append(f"{where}: duplicate repo {repo}")
        seen.add(repo)
        if rec.get("split") not in _SPLITS:
            problems.append(f"{where} {repo}: split must be one of {sorted(_SPLITS)}")
        if not isinstance(rec.get("stars_source"), int) or rec["stars_source"] < 0:
            problems.append(f"{where} {repo}: stars_source must be a non-negative int")
        gh = rec.get("github")
        files = rec.get("files") or []
        if gh is not None:
            if not isinstance(gh, dict):
                problems.append(f"{where} {repo}: github must be an object or null")
                continue
            for key in ("name_with_owner", "private", "archived", "fork", "stars", "commit"):
                if key not in gh:
                    problems.append(f"{where} {repo}: github.{key} is missing")
            if gh.get("commit") is not None and not _HEX40.match(str(gh.get("commit"))):
                problems.append(f"{where} {repo}: github.commit is not a 40-hex SHA")
        elif files:
            problems.append(f"{where} {repo}: files are pinned but github is null")
        if files and not (isinstance(gh, dict) and gh.get("commit")):
            problems.append(f"{where} {repo}: files are pinned without a commit")
        file_paths: set[str] = set()
        for f in files:
            fp = str(f.get("path") or "")
            if fp not in expected_paths:
                problems.append(f"{where} {repo}: {fp!r} is not an instruction path")
            if fp in file_paths:
                problems.append(f"{where} {repo}: duplicate file {fp}")
            file_paths.add(fp)
            if not _HEX64.match(str(f.get("sha256") or "")):
                problems.append(f"{where} {repo} {fp}: sha256 is not a 64-hex digest")
            if not isinstance(f.get("bytes"), int) or f["bytes"] < 0:
                problems.append(f"{where} {repo} {fp}: bytes must be a non-negative int")
        for u in rec.get("unavailable") or []:
            if str(u.get("path") or "") not in expected_paths:
                problems.append(f"{where} {repo}: unavailable {u.get('path')!r} is not an instruction path")
            if not u.get("reason"):
                problems.append(f"{where} {repo}: unavailable {u.get('path')} has no reason")
    repos = [str(r.get("repo") or "") for r in data.get("repos") or []]
    if repos != sorted(repos):
        problems.append("repos must be sorted by repo (deterministic order)")
    return problems


def benign_slice(manifest_path: Path | None = None) -> list[dict[str, Any]]:
    """The benign-slice repository records, sorted by repo (deterministic)."""
    data = load_manifest(manifest_path)
    cve_ids = cve_feed_identifiers()
    return sorted(
        (r for r in data.get("repos") or [] if is_benign(r, cve_ids)),
        key=lambda r: str(r.get("repo")),
    )


def slice_manifest(manifest_path: Path | None = None) -> dict[str, Any]:
    """The benign slice as a citable artifact: which repositories, files and commits.

    Mirrors `benign-slice.json`: the predicate makes the slice re-derivable, this
    makes it inspectable without running anything. Exclusions are counted by the
    first conjunct each repository fails, so `upstream_repos` minus the
    exclusions is `n`.
    """
    data = load_manifest(manifest_path)
    cve_ids = cve_feed_identifiers()
    repos = data.get("repos") or []
    excluded = Counter(
        reason for r in repos if (reason := exclusion_reason(r, cve_ids)) is not None
    )
    benign = [r for r in repos if exclusion_reason(r, cve_ids) is None]
    return {
        "predicate": PREDICATE,
        "source": data.get("source"),
        "pinned_at": data.get("pinned_at"),
        "instruction_paths": data.get("instruction_paths"),
        "upstream_repos": len(repos),
        "excluded": {reason: excluded.get(reason, 0) for reason in EXCLUSION_REASONS},
        "n": len(benign),
        "n_by_split": dict(sorted(Counter(r["split"] for r in benign).items())),
        "files": sum(len(r.get("files") or []) for r in benign),
        "files_by_path": dict(
            sorted(Counter(f["path"] for r in benign for f in r.get("files") or []).items())
        ),
        "repos": [
            {
                "repo": r["repo"],
                "split": r["split"],
                "commit": r["github"]["commit"],
                "stars_source": r["stars_source"],
                "files": sorted(f["path"] for f in r.get("files") or []),
            }
            for r in sorted(benign, key=lambda r: str(r["repo"]))
        ],
    }


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Derive and inspect the instruction-file benign slice.")
    ap.add_argument("--write", action="store_true", help="(Re)write slice.json.")
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if manifest.json is invalid or slice.json is stale vs a fresh derivation.",
    )
    args = ap.parse_args()

    if not MANIFEST.is_file():
        print(f"{MANIFEST.relative_to(REPO_ROOT)} is missing; run `make fp-instruction-pin`")
        return 1
    problems = validate_manifest(load_manifest())
    if problems:
        print("manifest.json is invalid:\n  " + "\n  ".join(problems))
        return 1

    data = slice_manifest()
    blob = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.check:
        current = SLICE_JSON.read_text(encoding="utf-8") if SLICE_JSON.is_file() else ""
        if current != blob:
            print("instruction slice.json is stale vs manifest.json - run 'make fp-instruction' and commit")
            return 1
        print(f"instruction slice.json is up to date (n = {data['n']} repos, {data['files']} files)")
        return 0
    if args.write:
        SLICE_JSON.write_text(blob, encoding="utf-8")
        print(f"wrote {SLICE_JSON.relative_to(REPO_ROOT)} (n = {data['n']})")
    print(f"instruction slice: n = {data['n']} repos, {data['files']} files")
    print("predicate:", PREDICATE)
    print("excluded:", data["excluded"])
    print("by split:", data["n_by_split"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
