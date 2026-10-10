#!/usr/bin/env python3
"""Instruction-file false-positive benchmark: scan the benign slice, list every HIGH/CRITICAL.

Runs the **real engine** (`agent_audit_kit.engine.run_scan`, what `aak scan`
drives) once per benign repository, over a temporary tree holding only that
repository's pinned instruction files at their original paths. Every scanner
runs, not just the instruction-file ones, because the question this answers is
the one a build asks: what fires on these files.

Unlike the MCP harness, which surfaces a top-30 for review, this lists **every**
HIGH/CRITICAL finding: the denominator is the whole set, and a sample once
missed a real true positive on this corpus.

Nothing here labels a finding true or false. `adjudication.json` is a human
judgement; `--init-adjudication` writes the empty template for it and refuses to
touch a file that already holds a verdict.

Committed output carries no third-party text: each finding is keyed by
repository, path, line and rule, with a SHA-256 of its evidence. `--sheet`
writes a human-readable list with the matched text, from the local cache, to a
path you choose; it is for adjudicating, not for committing.

Offline once the cache is filled (`make fp-instruction-fetch`; it lives outside
the repository, see `corpus.CACHE_DIR`). Deterministic: sorted output, an
order-independent finding-set digest, no wall-clock.

    python benchmarks/false_positive/instruction_files/run.py            # summary
    python benchmarks/false_positive/instruction_files/run.py --write    # results.json
    python benchmarks/false_positive/instruction_files/run.py --check    # drift guard
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent_audit_kit.engine import run_scan  # noqa: E402

from benchmarks.false_positive.instruction_files import corpus  # noqa: E402

RESULTS_JSON = _HERE / "results.json"
ADJUDICATION_JSON = _HERE / "adjudication.json"

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_HIGH_CRIT = frozenset({"critical", "high"})
VERDICTS = frozenset({"true_positive", "false_positive", "ambiguous"})
_KEY_FIELDS = ("repo", "path", "line", "rule_id")


class CacheIncomplete(RuntimeError):
    """A pinned file is missing from the cache or does not match its SHA-256."""


def _sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _cached(record: dict[str, Any], rel: str) -> Path:
    return corpus.CACHE_DIR / record["github"]["name_with_owner"] / rel


def cache_problems(records: list[dict[str, Any]]) -> list[str]:
    """Every pinned file that is missing or wrong in the cache."""
    problems: list[str] = []
    for rec in records:
        for f in rec.get("files") or []:
            target = _cached(rec, f["path"])
            if not target.is_file():
                problems.append(f"{rec['repo']}/{f['path']}: not cached")
            elif _sha256(target.read_bytes()) != f["sha256"]:
                problems.append(f"{rec['repo']}/{f['path']}: SHA-256 does not match the pin")
    return problems


def _scan_repo(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan one repository's instruction files in isolation; return its findings."""
    tmp = Path(tempfile.mkdtemp(prefix="aak-fp-instr-"))
    try:
        for f in record.get("files") or []:
            source = _cached(record, f["path"])
            blob = source.read_bytes() if source.is_file() else b""
            if _sha256(blob) != f["sha256"]:
                raise CacheIncomplete(f"{record['repo']}/{f['path']}")
            target = tmp / f["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
        result = run_scan(tmp)
        return [
            {
                "repo": record["repo"],
                "split": record["split"],
                "path": f.file_path,
                "line": int(f.line_number or 0),
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "evidence_sha256": _sha256((f.evidence or "").strip().encode("utf-8")),
            }
            for f in result.findings
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _sort_key(f: dict[str, Any]) -> tuple[Any, ...]:
    return (_SEV_RANK[f["severity"]], f["rule_id"], f["repo"], f["path"], f["line"], f["evidence_sha256"])


def _ranked(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def run_benchmark(records: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    slice_records = corpus.benign_slice() if records is None else records
    n = len(slice_records)
    findings: list[dict[str, Any]] = []
    for rec in slice_records:
        findings.extend(_scan_repo(rec))
    findings.sort(key=_sort_key)

    hc = [f for f in findings if f["severity"] in _HIGH_CRIT]
    repos_hc = {f["repo"] for f in hc}
    digest = _sha256(
        json.dumps(
            sorted([f["rule_id"], f["repo"], f["path"], f["line"], f["severity"], f["evidence_sha256"]] for f in findings),
            ensure_ascii=False,
        ).encode("utf-8")
    )
    return {
        "tool": "agent-audit-kit",
        "benign_slice_predicate": corpus.PREDICATE,
        "slice_n": n,
        "slice_n_by_split": dict(sorted(Counter(r["split"] for r in slice_records).items())),
        "files_scanned": sum(len(r.get("files") or []) for r in slice_records),
        "total_findings": len(findings),
        "severity_buckets": {k: sum(1 for f in findings if f["severity"] == k) for k in _SEV_RANK},
        "findings_by_rule": _ranked(Counter(f["rule_id"] for f in findings)),
        "high_critical_findings": len(hc),
        "repos_with_high_critical": len(repos_hc),
        "high_critical_repo_rate": round(len(repos_hc) / n, 4) if n else 0.0,
        "high_critical_by_rule": _ranked(Counter(f["rule_id"] for f in hc)),
        "high_critical_by_split": dict(sorted(Counter(f["split"] for f in hc).items())),
        "scanner_failures": sum(1 for f in findings if f["rule_id"] == "AAK-INTERNAL-SCANNER-FAIL"),
        "finding_set_digest": digest,
        "high_critical": hc,
    }


def finding_key(f: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(f[k] for k in _KEY_FIELDS)


def adjudication_template(results: dict[str, Any]) -> dict[str, Any]:
    """The empty adjudication: one entry per HIGH/CRITICAL finding, verdict null."""
    return {
        "_comment": (
            "Human adjudication of EVERY HIGH/CRITICAL finding on the instruction-file "
            "benign slice. No script writes a verdict. Set each `verdict` to "
            "true_positive, false_positive or ambiguous (ambiguous counts in the "
            "denominator only, as in the MCP slice), fill in rater and run_date, then "
            "update RESULTS.md and run `make fp-instruction-check`. While any verdict "
            "is null the slice is pending and no rate may be stated."
        ),
        "rater": None,
        "run_date": None,
        "tuned": True,
        "tuned_note": (
            "Both SENTINEL manifests were scanned while the AAK-AGENT-* matchers were "
            "reworked for #771 (2026-10-02) and #869 (2026-10-04), so this slice is not "
            "unseen data for those rules: the rate it yields is a tuned measurement."
        ),
        "verdicts": [
            {**{k: f[k] for k in (*_KEY_FIELDS, "severity", "evidence_sha256")}, "verdict": None, "note": ""}
            for f in results["high_critical"]
        ],
    }


def write_sheet(results: dict[str, Any], out: Path, records: list[dict[str, Any]] | None = None) -> None:
    """A Markdown list of every HIGH/CRITICAL finding with its matched text and context."""
    by_repo = {r["repo"]: r for r in (corpus.benign_slice() if records is None else records)}
    lines = [
        "# Instruction-file slice: findings to adjudicate",
        "",
        f"{results['high_critical_findings']} HIGH/CRITICAL findings on "
        f"{results['slice_n']} benign repositories. Local working copy with "
        "third-party text: do not commit it.",
        "",
    ]
    for i, f in enumerate(results["high_critical"], 1):
        rec = by_repo[f["repo"]]
        source = _cached(rec, f["path"]) if f["path"] in {x["path"] for x in rec["files"]} else None
        text = source.read_text(encoding="utf-8", errors="replace").splitlines() if source else []
        ln = f["line"]
        context = text[max(0, ln - 3):ln + 2] if ln else []
        lines += [
            f"## {i}. {f['rule_id']} [{f['severity'].upper()}] {f['repo']} `{f['path']}`:{ln}",
            "",
            f"https://github.com/{rec['github']['name_with_owner']}/blob/{rec['github']['commit']}/{f['path']}#L{ln}",
            "",
            "```text",
            *[f"{n:>5} {'>' if n == ln else ' '} {t}" for n, t in enumerate(context, start=max(1, ln - 2))],
            "```",
            "",
            "Verdict: ____  Note: ____",
            "",
        ]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="(Re)write results.json.")
    ap.add_argument("--out", default=None, help="Write the result here instead of results.json.")
    ap.add_argument("--check", action="store_true", help="Exit 1 if results.json is stale vs a fresh run.")
    ap.add_argument(
        "--init-adjudication", action="store_true",
        help="Write the empty adjudication.json for the committed results; refuses if any verdict is set.",
    )
    ap.add_argument("--sheet", default=None, help="Write the adjudication sheet (with third-party text) here.")
    args = ap.parse_args()

    if args.init_adjudication:
        results = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
        if ADJUDICATION_JSON.is_file():
            existing = json.loads(ADJUDICATION_JSON.read_text(encoding="utf-8"))
            if any(v.get("verdict") is not None for v in existing.get("verdicts") or []):
                print("adjudication.json already holds verdicts; refusing to overwrite a human judgement")
                return 1
        blob = json.dumps(adjudication_template(results), indent=2, sort_keys=True) + "\n"
        ADJUDICATION_JSON.write_text(blob, encoding="utf-8")
        print(f"wrote {ADJUDICATION_JSON.relative_to(REPO_ROOT)} ({len(results['high_critical'])} pending)")
        return 0

    records = corpus.benign_slice()
    problems = cache_problems(records)
    if problems:
        if args.check:
            print(
                f"instruction results: NOT CHECKED, {len(problems)} pinned file(s) missing from the cache "
                "(run `make fp-instruction-fetch`). This is a skip, not a pass."
            )
            return 0
        print("cache is incomplete (run `make fp-instruction-fetch`):\n  " + "\n  ".join(problems[:20]))
        return 1

    data = run_benchmark(records)
    blob = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.check:
        current = RESULTS_JSON.read_text(encoding="utf-8") if RESULTS_JSON.is_file() else ""
        if current != blob:
            print("instruction results.json is stale - run 'make fp-instruction', re-adjudicate by hand, and commit")
            return 1
        print("instruction results are up to date")
        return 0
    if args.out:
        Path(args.out).write_text(blob, encoding="utf-8")
    elif args.write:
        RESULTS_JSON.write_text(blob, encoding="utf-8")
        print(f"wrote {RESULTS_JSON.relative_to(REPO_ROOT)}")
    if args.sheet:
        write_sheet(data, Path(args.sheet), records)
        print(f"wrote {args.sheet}")

    print(
        f"instruction slice n = {data['slice_n']} repos, {data['files_scanned']} files | "
        f"findings = {data['total_findings']} | severity = {data['severity_buckets']}\n"
        f"HIGH+CRITICAL = {data['high_critical_findings']} across {data['repos_with_high_critical']} repos "
        f"({data['high_critical_repo_rate'] * 100:.1f}%) by rule {data['high_critical_by_rule']}\n"
        f"scanner failures = {data['scanner_failures']} | digest = {data['finding_set_digest'][:16]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
