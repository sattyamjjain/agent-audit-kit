"""`python -m benchmarks.cve_prescreen <command>`, from the repository root.

  context CVE-…|#N     the compact context, retrieval only (no model)
  screen  CVE-…|#N     noise filter + classification on the subscription
  ground-truth         rebuild ground_truth.json from the ledger + closed issues
  retrieve             warm the retrieval cache for every ground-truth record
  backtest             screen every ground-truth record into a run directory
  report               score a run into results.json and RESULTS.md (--check: drift guard)

Network: `context`, `screen` and `retrieve` read NVD, GitHub (REST) and OSV
unless the cache already holds the answer (`--offline` refuses the network).
`ground-truth` reads the tracker through `gh api` REST unless `--issues-json`
is given. `screen` and `backtest` call `claude -p`. `report` is offline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from benchmarks.cve_prescreen import backtest, ground_truth, prompts  # noqa: E402
from benchmarks.cve_prescreen.retrieval import (  # noqa: E402
    DEFAULT_REPO,
    DiskCache,
    Retriever,
    cache_dir,
    cve_for_issue,
)
from benchmarks.cve_prescreen.runner import auth_status, cli_version  # noqa: E402
from benchmarks.cve_prescreen.screen import (  # noqa: E402
    DEFAULT_CLASSIFY_MODEL,
    DEFAULT_NOISE_MODEL,
    screen,
)

LEDGER = _REPO / "CHANGELOG.cves.md"


def _retriever(args: argparse.Namespace) -> Retriever:
    return Retriever(
        DiskCache(cache_dir()),
        refresh=getattr(args, "refresh", False),
        offline=getattr(args, "offline", False),
    )


def _target_cve(target: str, repo: str) -> str:
    raw = target.strip()
    if raw.startswith("#") or raw.isdigit():
        return cve_for_issue(int(raw.lstrip("#")), repo)
    return raw.upper()


def _require_subscription() -> dict[str, Any]:
    auth = auth_status()
    if auth.get("authMethod") != "claude.ai":
        raise SystemExit(
            f"refusing to call the model: auth method is {auth.get('authMethod')!r}, not the "
            "claude.ai subscription login (`claude auth login`)"
        )
    return auth


def cmd_context(args: argparse.Namespace) -> int:
    cve = _target_cve(args.target, args.repo)
    print(json.dumps(_retriever(args).bundle(cve).context(), indent=1, sort_keys=True, ensure_ascii=False))
    return 0


def cmd_screen(args: argparse.Namespace) -> int:
    cve = _target_cve(args.target, args.repo)
    _require_subscription()
    context = _retriever(args).bundle(cve).context()
    result = screen(context, noise_model=args.noise_model, classify_model=args.classify_model)
    out = {
        "cve": cve,
        "candidate": result["candidate"],
        "classification": (result.get("classification") or {}).get("structured"),
        "extraction": {k: v for k, v in (result.get("extraction") or {}).items() if k != "checks"},
        "models_used": {
            "noise": (result.get("noise") or {}).get("models_used"),
            "classification": (result.get("classification") or {}).get("models_used"),
        },
        "note": "Candidate only. The maintainer decides the disposition.",
    }
    print(json.dumps(out, indent=1, ensure_ascii=False))
    return 0


def cmd_ground_truth(args: argparse.Namespace) -> int:
    if args.issues_json:
        issues = json.loads(Path(args.issues_json).read_text(encoding="utf-8"))
    else:
        issues = ground_truth.fetch_issue_snapshot(args.repo, args.since)
        if args.save_issues:
            Path(args.save_issues).write_text(json.dumps(issues, indent=1), encoding="utf-8")
    records, report = ground_truth.build(LEDGER.read_text(encoding="utf-8"), issues, args.since)
    out = Path(args.out)
    ground_truth.write(out, records, report)
    print(json.dumps(ground_truth.summary(records), indent=1))
    if report["unlabelled"]:
        print(f"unlabelled (add to OVERRIDES): {report['unlabelled']}", file=sys.stderr)
    return 0


def cmd_retrieve(args: argparse.Namespace) -> int:
    truths = ground_truth.load(Path(args.ground_truth))
    retriever = _retriever(args)
    for i, truth in enumerate(truths, 1):
        bundle = retriever.bundle(truth.cve)
        print(f"[{i}/{len(truths)}] {truth.cve} {bundle.status}", flush=True)
    print(f"network calls: {retriever.network_calls}")
    return 0


def _run_dir(args: argparse.Namespace) -> Path:
    if args.run_dir:
        return Path(args.run_dir)
    return cache_dir() / "runs" / prompts.PROMPT_VERSION


def cmd_backtest(args: argparse.Namespace) -> int:
    truths = ground_truth.load(Path(args.ground_truth))
    if args.only:
        wanted = {c.upper() for c in args.only}
        truths = [t for t in truths if t.cve in wanted]
    if args.limit:
        truths = truths[: args.limit]
    auth = _require_subscription()
    run_dir = _run_dir(args)
    run_dir.mkdir(parents=True, exist_ok=True)
    meta_path = run_dir / "run.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    meta.update({
        "prompt_version": prompts.PROMPT_VERSION,
        "prompt_fingerprint": backtest.prompt_fingerprint(),
        "cli_version": cli_version(),
        "auth_method": auth.get("authMethod"),
        "subscription_type": auth.get("subscriptionType"),
        "noise_model": args.noise_model,
        "classify_model": args.classify_model,
        "concurrency": min(args.concurrency, backtest.MAX_CONCURRENCY),
    })
    if meta.get("prompt_fingerprint_at_start", meta["prompt_fingerprint"]) != meta["prompt_fingerprint"]:
        raise SystemExit("the prompts changed since this run directory was started; use a new --run-dir")
    meta.setdefault("prompt_fingerprint_at_start", meta["prompt_fingerprint"])
    meta_path.write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")
    retriever = Retriever(DiskCache(cache_dir()), offline=not args.fetch)
    counts = backtest.run_backtest(
        truths, retriever, run_dir, concurrency=args.concurrency,
        noise_model=args.noise_model, classify_model=args.classify_model, force=args.force,
        log=lambda line: print(line, flush=True),
    )
    print(json.dumps(counts))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    if args.check:
        committed = backtest.RESULTS_MD.read_text(encoding="utf-8") if backtest.RESULTS_MD.is_file() else ""
        rendered = backtest.render_markdown(backtest.load_results())
        if committed != rendered:
            print("RESULTS.md is stale: run `python -m benchmarks.cve_prescreen report --write`", file=sys.stderr)
            return 1
        print("RESULTS.md matches results.json")
        return 0
    run_dir = _run_dir(args)
    truths = ground_truth.load(Path(args.ground_truth))
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    records = sorted((run_dir / "records").glob("CVE-*.json"))
    stamps = []
    for path in records:
        stamp = json.loads(path.read_text(encoding="utf-8")).get("screened_at")
        if stamp:
            stamps.append(stamp)
    meta = {
        k: meta.get(k) for k in (
            "prompt_version", "prompt_fingerprint", "cli_version", "auth_method",
            "subscription_type", "noise_model", "classify_model", "concurrency",
        )
    }
    meta["run_started"] = min(stamps) if stamps else None
    meta["run_finished"] = max(stamps) if stamps else None
    meta["limitations"] = backtest.LIMITATIONS
    offline = Retriever(DiskCache(cache_dir()), offline=True)
    results = backtest.build_results(
        truths, run_dir, meta, Path(args.ground_truth),
        context_for=lambda cve: offline.bundle(cve).context(),
    )
    if args.write:
        backtest.write_results(results)
        print(f"wrote {backtest.RESULTS_JSON.relative_to(_REPO)} and {backtest.RESULTS_MD.relative_to(_REPO)}")
    else:
        print(json.dumps(results["summary"], indent=1))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmarks.cve_prescreen", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=DEFAULT_REPO, help="owner/name of the tracker (REST)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("context", help="print the compact context (no model)")
    p.add_argument("target", help="CVE id, or #N for a cve-response issue")
    p.add_argument("--offline", action="store_true", help="cache only, no network")
    p.add_argument("--refresh", action="store_true", help="ignore the cache")
    p.set_defaults(func=cmd_context)

    p = sub.add_parser("screen", help="candidate disposition for one CVE or issue")
    p.add_argument("target")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--refresh", action="store_true")
    p.add_argument("--noise-model", default=DEFAULT_NOISE_MODEL)
    p.add_argument("--classify-model", default=DEFAULT_CLASSIFY_MODEL)
    p.set_defaults(func=cmd_screen)

    p = sub.add_parser("ground-truth", help="rebuild ground_truth.json")
    p.add_argument("--issues-json", help="issue snapshot instead of a live REST read")
    p.add_argument("--save-issues", help="also save the live snapshot here")
    p.add_argument("--since", default=ground_truth.SINCE)
    p.add_argument("--out", default=str(backtest.GROUND_TRUTH))
    p.set_defaults(func=cmd_ground_truth)

    p = sub.add_parser("retrieve", help="warm the cache for every ground-truth record")
    p.add_argument("--ground-truth", default=str(backtest.GROUND_TRUTH))
    p.add_argument("--refresh", action="store_true")
    p.set_defaults(func=cmd_retrieve)

    p = sub.add_parser("backtest", help="screen every ground-truth record")
    p.add_argument("--ground-truth", default=str(backtest.GROUND_TRUTH))
    p.add_argument("--run-dir", help="default: <cache>/runs/<prompt version>")
    p.add_argument("--concurrency", type=int, default=backtest.MAX_CONCURRENCY,
                   help=f"capped at {backtest.MAX_CONCURRENCY}")
    p.add_argument("--only", nargs="*", help="these CVE ids only")
    p.add_argument("--limit", type=int)
    p.add_argument("--force", action="store_true", help="re-screen records already in the run dir")
    p.add_argument("--fetch", action="store_true", help="allow retrieval for records not cached")
    p.add_argument("--noise-model", default=DEFAULT_NOISE_MODEL)
    p.add_argument("--classify-model", default=DEFAULT_CLASSIFY_MODEL)
    p.set_defaults(func=cmd_backtest)

    p = sub.add_parser("report", help="score a run; --check is the offline drift guard")
    p.add_argument("--ground-truth", default=str(backtest.GROUND_TRUTH))
    p.add_argument("--run-dir")
    p.add_argument("--write", action="store_true", help="write results.json and RESULTS.md")
    p.add_argument("--check", action="store_true", help="fail if RESULTS.md differs from results.json")
    p.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
