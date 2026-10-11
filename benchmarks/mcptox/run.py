#!/usr/bin/env python3
"""MCPTox rules-only recall: scan every case with the shipped engine, count what fires.

Runs the **real engine** (`agent_audit_kit.engine.run_scan`, what `aak scan`
drives) once per case, over the minimal project `build.py` writes for it: one
`.mcp.json`, one server, the case's tool in its `tools` array. Every scanner
runs and every rule is active, the defaults of a plain `aak scan`. Nothing in
the rule set is adjusted for this benchmark; that is the measurement.

Attribution. The same server with an empty `tools` array is scanned once as a
control, and a case's findings are its scan minus the control's, matched on
(rule, evidence). With the minimal server entry the control raises nothing, so
every finding counted is one the tool caused; `control_findings` records that.

Three detection definitions are reported, on the malicious cases (recall) and
on the clean tools of the same servers (false-positive rate):

  any_rule        at least one finding attributed to the tool, from any rule
  tool_poisoning  at least one such finding from a rule in Category.TOOL_POISONING
  per rule        the cases each rule fired on

plus the same counts at a severity floor, which is what `--fail-on` gates on.

Untuned, and kept that way. `results.json` records the package it measured
(`aak.package_digest`, a hash of every file under `agent_audit_kit/` that can
change a scan) and declares `untuned: true`. `--write` refuses to replace that
measurement with one of a different package unless told, with `--supersede`,
whether the rule changes since were informed by MCPTox. `--check` re-runs and
compares only when the package is the measured one; otherwise it reports NOT
COMPARED, because a fresh run of a changed rule set is a different measurement,
not a refresh of this one.

Committed output carries no dataset text: cases appear by id, the tools by a
digest of all of them. Offline once the cache is filled (`make mcptox-fetch`).
Deterministic: sorted output, digests over sorted rows, no wall-clock.

    python benchmarks/mcptox/run.py            # summary
    python benchmarks/mcptox/run.py --write    # (re)write results.json
    python benchmarks/mcptox/run.py --check    # drift guard
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent_audit_kit import SCANNER_COUNT, __version__  # noqa: E402
from agent_audit_kit.engine import run_scan  # noqa: E402
from agent_audit_kit.models import SCANNER_FAIL_RULE_ID, Category  # noqa: E402
from agent_audit_kit.rules.builtin import RULES  # noqa: E402

from benchmarks.false_positive.stats import wilson_interval  # noqa: E402
from benchmarks.mcptox import build, corpus  # noqa: E402

RESULTS_JSON = _HERE / "results.json"

# Environment switches that change what a scan reports. Both are off in a plain
# `aak scan`, and the run holds them off whatever the caller's environment says:
# AAK_TOXIC_FLOW enables the opt-in AAK-TOXICFLOW-001, and
# AAK_FETCH_SERVER_CARD_URL makes mcp_server_card fetch over the network.
ENV_GATES: tuple[str, ...] = ("AAK_TOXIC_FLOW", "AAK_FETCH_SERVER_CARD_URL")

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
FLOORS: tuple[str, ...] = ("critical", "high", "medium", "low")
_TOOL_POISONING = Category.TOOL_POISONING.value

DEFINITIONS: dict[str, str] = {
    "any_rule": "at least one finding attributed to the case's tool, from any rule",
    "tool_poisoning": "at least one attributed finding from a rule in Category.TOOL_POISONING",
    "at_or_above": "at least one attributed finding at or above the given severity (what --fail-on gates on)",
    "by_rule": "the cases each rule fired on, attributed",
}

Row = tuple[str, str, str, str]  # (rule_id, category, severity, evidence)


@contextmanager
def default_environment() -> Iterator[None]:
    """Hold the `ENV_GATES` switches off for the duration, then restore them."""
    saved = {k: os.environ.pop(k) for k in ENV_GATES if k in os.environ}
    try:
        yield
    finally:
        os.environ.update(saved)


def scan_config(config: dict[str, Any]) -> list[Row]:
    """Scan one config as a fresh temporary project; its findings as sorted rows."""
    tmp = Path(tempfile.mkdtemp(prefix="aak-mcptox-"))
    try:
        build.write_project(config, tmp)
        result = run_scan(tmp)
        return sorted(
            (f.rule_id, f.category.value, f.severity.value, (f.evidence or "").strip())
            for f in result.findings
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def attributed(rows: list[Row], control: list[Row]) -> list[Row]:
    """`rows` minus the control's findings, as a multiset on (rule, evidence)."""
    remaining = Counter((r[0], r[3]) for r in control)
    out: list[Row] = []
    for r in rows:
        key = (r[0], r[3])
        if remaining[key] > 0:
            remaining[key] -= 1
            continue
        out.append(r)
    return out


def verdict(rows: list[Row]) -> dict[str, Any]:
    """What one case's attributed findings amount to under each definition."""
    hits = [r for r in rows if r[0] != SCANNER_FAIL_RULE_ID]
    severities = sorted({r[2] for r in hits}, key=SEVERITY_ORDER.index)
    return {
        "rules": sorted({r[0] for r in hits}),
        "tool_poisoning": any(r[1] == _TOOL_POISONING for r in hits),
        "max_severity": severities[0] if severities else None,
        "scanner_failures": sum(1 for r in rows if r[0] == SCANNER_FAIL_RULE_ID),
    }


def rate(k: int, n: int) -> dict[str, Any]:
    """`k` of `n` with its point estimate and Wilson 95% interval."""
    low, high = wilson_interval(k, n)
    return {
        "k": k,
        "n": n,
        "rate": round(k / n, 6) if n else 0.0,
        "wilson95": [round(low, 6), round(high, 6)],
    }


def _count(verdicts: list[dict[str, Any]], pred: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
    return rate(sum(1 for v in verdicts if pred(v)), len(verdicts))


def _at_or_above(floor: str) -> Callable[[dict[str, Any]], bool]:
    limit = SEVERITY_ORDER.index(floor)

    def pred(v: dict[str, Any]) -> bool:
        sev = v["max_severity"]
        return sev is not None and SEVERITY_ORDER.index(sev) <= limit

    return pred


def summarize(verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "any_rule": _count(verdicts, lambda v: bool(v["rules"])),
        "tool_poisoning": _count(verdicts, lambda v: bool(v["tool_poisoning"])),
        "at_or_above": {floor: _count(verdicts, _at_or_above(floor)) for floor in FLOORS},
    }


def _grouped(cases: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]], field: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for c in cases:
        groups.setdefault(str(c[field]), []).append(verdicts[c["case_id"]])
    out: dict[str, Any] = {}
    for name in sorted(groups):
        s = summarize(groups[name])
        out[name] = {"any_rule": s["any_rule"], "tool_poisoning": s["tool_poisoning"]}
    return out


def package_digest(root: Path | None = None) -> str:
    """SHA-256 over every file under `agent_audit_kit/` that can change a scan.

    Rule metadata is in `rules.json`, but detection is code: the regexes live in
    the scanner modules, so a rules.json hash alone would call two different
    rule sets the same. Prose (`*.md`), bytecode and dotfiles are left out, so a
    contributor note or a `.DS_Store` does not read as a rule change.
    """
    pkg = (root or REPO_ROOT) / "agent_audit_kit"
    rows: list[list[str]] = []
    for path in pkg.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(pkg)
        if any(part == "__pycache__" or part.startswith(".") for part in rel.parts):
            continue
        if path.suffix in (".pyc", ".pyo", ".md"):
            continue
        rows.append([rel.as_posix(), corpus.sha256_bytes(path.read_bytes())])
    rows.sort()
    return corpus.sha256_text(json.dumps(rows))


def _git(*args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *args], capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return proc.stdout.strip()


def provenance() -> dict[str, Any]:
    """Where the measured package came from. Not compared by `--check`: two
    commits with the same package digest measure the same rule set."""
    status = _git("status", "--porcelain", "--", "agent_audit_kit")
    return {
        "aak_commit": _git("rev-parse", "HEAD"),
        "aak_package_unmodified_at_commit": status == "" if status is not None else None,
    }


def aak_block() -> dict[str, Any]:
    rules_json = REPO_ROOT / "rules.json"
    return {
        "version": __version__,
        "package_digest": package_digest(),
        "rules_json_sha256": corpus.sha256_bytes(rules_json.read_bytes()) if rules_json.is_file() else None,
        "rule_count": len(RULES),
        "tool_poisoning_rule_count": sum(1 for r in RULES.values() if r.category is Category.TOOL_POISONING),
        "scanner_count": SCANNER_COUNT,
        "scan": {
            "entrypoint": "agent_audit_kit.engine.run_scan(project_root)",
            "rules": "all (no --rules / --exclude-rules filter)",
            "include_user_config": False,
            "environment_gates_held_off": list(ENV_GATES),
            "project": "one .mcp.json: mcpServers.<dataset server name>.tools = [the case's tool]",
            "attribution": "case findings minus the same server's empty-tools control, on (rule_id, evidence)",
        },
    }


def _per_rule(
    mal: list[dict[str, Any]], ben: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """`by_rule` (registry metadata plus both rates) and `fired_on` (the case ids)."""
    by_rule: dict[str, Any] = {}
    fired_on: dict[str, Any] = {}
    for rid in sorted({r for v in verdicts.values() for r in v["rules"]}):
        rule = RULES.get(rid)
        on_mal = [c["case_id"] for c in mal if rid in verdicts[c["case_id"]]["rules"]]
        on_ben = [c["case_id"] for c in ben if rid in verdicts[c["case_id"]]["rules"]]
        by_rule[rid] = {
            "title": rule.title if rule else rid,
            "severity": rule.severity.value if rule else None,
            "category": rule.category.value if rule else None,
            "malicious": rate(len(on_mal), len(mal)),
            "benign": rate(len(on_ben), len(ben)),
        }
        fired_on[rid] = {"malicious": on_mal, "benign": on_ben}
    return by_rule, fired_on


def run_benchmark(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Scan every case and every server's control; the `measurement` block."""
    controls: dict[str, list[Row]] = {}
    verdicts: dict[str, dict[str, Any]] = {}
    with default_environment():
        for server in sorted({c["server"] for c in cases}):
            controls[server] = scan_config(build.control_config(server))
        for c in cases:
            rows = attributed(scan_config(build.project_config(c)), controls[c["server"]])
            verdicts[c["case_id"]] = verdict(rows)

    mal = [c for c in cases if c["label"] == "malicious"]
    ben = [c for c in cases if c["label"] == "benign"]

    def vs(subset: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [verdicts[c["case_id"]] for c in subset]

    by_rule, fired_on = _per_rule(mal, ben, verdicts)
    digest_rows = sorted(
        [cid, v["rules"], v["tool_poisoning"], v["max_severity"]] for cid, v in verdicts.items()
    )
    return {
        "definitions": DEFINITIONS,
        "malicious": summarize(vs(mal)),
        "malicious_wrong_data_0": summarize(vs([c for c in mal if c["wrong_data"] == 0])),
        "malicious_deduplicated": summarize(vs([c for c in mal if c["duplicate_of"] is None])),
        "benign": summarize(vs(ben)),
        "by_paradigm": _grouped(mal, verdicts, "paradigm"),
        "by_security_risk": _grouped(mal, verdicts, "security risk"),
        "by_rule": by_rule,
        "fired_on": fired_on,
        "rules_fired": len(by_rule),
        "control_findings": sum(len(rows) for rows in controls.values()),
        "scanner_failures": sum(v["scanner_failures"] for v in verdicts.values()),
        "verdict_digest": corpus.sha256_text(json.dumps(digest_rows, ensure_ascii=False)),
    }


def build_results(cases: list[dict[str, Any]], data: dict[str, Any], untuned: bool) -> dict[str, Any]:
    return {
        "benchmark": "MCPTox rules-only recall (AgentAuditKit, untuned)",
        "untuned": untuned,
        "provenance": provenance(),
        "aak": aak_block(),
        "dataset": {
            "paper": corpus.PAPER,
            "paper_url": corpus.PAPER_URL,
            "repository": corpus.REPOSITORY,
            "commit": corpus.COMMIT,
            "files": corpus.FILES,
            "license": corpus.LICENSE_NOTE,
            "counts": corpus.dataset_counts(data, cases),
            "cases_digest": corpus.cases_digest(cases),
        },
        "measurement": run_benchmark(cases),
    }


def _comparable(results: dict[str, Any]) -> dict[str, Any]:
    """Everything `--check` compares: all but the provenance block."""
    return {k: v for k, v in results.items() if k != "provenance"}


def _dump(results: dict[str, Any]) -> str:
    return json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _shown(path: Path) -> str:
    """`path` relative to the repository when it is inside it, for messages."""
    return str(path.relative_to(REPO_ROOT)) if path.is_relative_to(REPO_ROOT) else str(path)


def _load_committed() -> dict[str, Any] | None:
    if not RESULTS_JSON.is_file():
        return None
    data: dict[str, Any] = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
    return data


def _print_summary(results: dict[str, Any]) -> None:
    m = results["measurement"]

    def fmt(r: dict[str, Any]) -> str:
        low, high = r["wilson95"]
        return f"{r['k']}/{r['n']} = {100 * r['rate']:.1f}% [{100 * low:.1f}%, {100 * high:.1f}%]"

    print(f"MCPTox @ {corpus.COMMIT[:12]} | AAK {results['aak']['version']} "
          f"package {results['aak']['package_digest'][:12]}")
    for group in ("malicious", "malicious_wrong_data_0", "malicious_deduplicated", "benign"):
        s = m[group]
        print(f"  {group:24} any_rule {fmt(s['any_rule'])} | tool_poisoning {fmt(s['tool_poisoning'])}")
    print(f"  rules fired: {m['rules_fired']} | control findings: {m['control_findings']} | "
          f"scanner failures: {m['scanner_failures']} | verdicts {m['verdict_digest'][:16]}")


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="(Re)write results.json.")
    ap.add_argument("--out", default=None, help="Write the result here instead of results.json.")
    ap.add_argument("--check", action="store_true", help="Exit 1 if a fresh run of the measured package differs.")
    ap.add_argument(
        "--supersede", choices=("untuned", "tuned"), default=None,
        help="With --write, replace a measurement of a different package, declaring whether the "
             "rule changes since were made without (untuned) or with (tuned) sight of MCPTox.",
    )
    return ap


def _gate(args: argparse.Namespace, committed: dict[str, Any] | None, current: str) -> int | None:
    """The exit code when the run must stop before scanning, else None.

    The two package-digest guards: `--check` compares only a measurement of the
    package on disk, and `--write` will not replace the untuned measurement with
    a run of a different package unless `--supersede` says what that run is.
    """
    if args.check:
        if committed is None:
            print(f"{_shown(RESULTS_JSON)} is missing")
            return 1
        if committed["aak"]["package_digest"] != current:
            print("mcptox results: NOT COMPARED. agent_audit_kit/ differs from the package measured at "
                  f"{(committed['provenance'].get('aak_commit') or '?')[:12]}; the published recall is that "
                  "rule set's, and a fresh run here would be a new measurement, not a refresh.")
            return 0
        return None
    stale = committed is not None and committed["aak"]["package_digest"] != current
    if args.write and stale and args.supersede is None:
        assert committed is not None
        print("refusing: results.json is the measurement of a different package "
              f"({committed['aak']['package_digest'][:12]}, here {current[:12]}). Write elsewhere with "
              "--out, or pass --supersede untuned|tuned to replace it and say whether the rule changes "
              "since were made with sight of MCPTox.")
        return 1
    return None


def _emit(args: argparse.Namespace, committed: dict[str, Any] | None, results: dict[str, Any]) -> int:
    """Compare (`--check`) or write the fresh results; print the summary."""
    if args.check:
        assert committed is not None
        if _dump(_comparable(committed)) != _dump(_comparable(results)):
            print("mcptox results.json is stale or the run is not deterministic: a fresh run of the "
                  "measured package differs from it")
            return 1
        print("mcptox results are up to date (fresh run of the measured package matches)")
        return 0
    if args.out:
        Path(args.out).write_text(_dump(results), encoding="utf-8")
        print(f"wrote {args.out}")
    elif args.write:
        RESULTS_JSON.write_text(_dump(results), encoding="utf-8")
        print(f"wrote {_shown(RESULTS_JSON)}")
    _print_summary(results)
    return 0


def main() -> int:
    args = _parser().parse_args()
    problems = corpus.cache_problems()
    if problems:
        if args.check:
            print("mcptox results: NOT CHECKED, the pinned release file is not cached "
                  "(run `make mcptox-fetch`). This is a skip, not a pass.")
            return 0
        print("cache is not filled (run `make mcptox-fetch`):\n  " + "\n  ".join(problems))
        return 1

    committed = _load_committed()
    stop = _gate(args, committed, package_digest())
    if stop is not None:
        return stop
    untuned = bool(committed.get("untuned", True)) if committed else True
    if args.supersede is not None:
        untuned = args.supersede == "untuned"
    data = corpus.load_dataset()
    cases = corpus.all_cases(data)
    return _emit(args, committed, build_results(cases, data, untuned))


if __name__ == "__main__":
    raise SystemExit(main())
