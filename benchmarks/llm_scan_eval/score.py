#!/usr/bin/env python3
"""Score `--llm-scan` eval runs from their archived receipts, offline.

Everything here is recomputed from ``runs/*/results-*.jsonl`` and the cases
file, so a reader can check every published number without an API key.
Verdicts are parsed by ``llm_scan.parse_anthropic_message``, the CLI's own
parser, and each reply lands in one of the CLI's states:

- ``flagged`` / ``clean``: the model gave a verdict;
- ``declined`` (``stop_reason: "refusal"``), ``cut_off`` (``max_tokens``),
  ``unparsed`` or ``errored``: not analyzed, which ``--llm-scan`` reports as
  AAK-LLM-002 and never as clean.

Recall is flagged malicious cases over ALL malicious cases: a refusal on a
poisoned description is not a catch, because the CLI does not report it as
one. Refusal rates are reported beside it, since a refusal does surface the
tool to a human as "not analyzed". Intervals are Wilson 95%.

    python score.py --cases cases.jsonl runs/haiku runs/sonnet --json results.json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from agent_audit_kit import llm_scan  # noqa: E402

GAP_STATES = ("declined", "cut_off", "unparsed", "errored")


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _state(row: dict[str, Any]) -> tuple[str, str | None]:
    if "state" in row:  # a redacted receipt (run_eval.py redact) carries its parsed state
        return (row["state"], row.get("refusal_category"))
    if row["type"] != "succeeded":
        return ("errored", None)
    verdict = llm_scan.parse_anthropic_message(row["message"])
    return (verdict.status, verdict.refusal_category)


def load_run(run_dir: Path) -> dict[str, Any]:
    batches = sorted(run_dir.glob("batch-*.json"))
    if not batches:
        raise SystemExit(f"{run_dir}: no batch-*.json")
    states: dict[int, dict[int, str]] = defaultdict(dict)
    refusal_categories: Counter[str] = Counter()
    served: Counter[str] = Counter()
    meta: dict[str, Any] = {}
    cost: dict[str, float] = defaultdict(float)
    for b in batches:
        submitted = json.loads(b.read_text())
        meta = submitted["meta"]
        batch_id = submitted["batch_id"]
        results = run_dir / f"results-{batch_id}.jsonl"
        if not results.is_file():
            raise SystemExit(f"{results} missing: run `run_eval.py collect` first")
        for line in results.read_text().splitlines():
            row = json.loads(line)
            case_part, run_part = row["custom_id"].split("-r")
            state, category = _state(row)
            states[int(case_part[1:])][int(run_part)] = state
            if state == "declined":
                refusal_categories[category or "none given"] += 1
            if row.get("message"):
                served[row["message"].get("model") or "unknown"] += 1
            elif row.get("model"):
                served[row["model"]] += 1
        cost_file = run_dir / f"cost-{batch_id}.json"
        if cost_file.is_file():
            for k, v in json.loads(cost_file.read_text()).items():
                cost[k] += v
    return {"meta": meta, "states": states, "refusals": refusal_categories, "served": served,
            "cost": dict(cost)}


def score(cases: list[dict[str, Any]], run: dict[str, Any], group_field: str | None) -> dict[str, Any]:
    states = run["states"]
    runs = sorted({r for per in states.values() for r in per})
    out: dict[str, Any] = {
        "model": run["meta"]["model"], "effort": run["meta"]["effort"], "runs": len(runs),
        "cases": len(states), "prompt_sha256": run["meta"]["prompt_sha256"],
        "served_models": dict(run["served"]), "refusal_categories": dict(run["refusals"]),
        "cost": run["cost"],
    }
    per_run = []
    for r in runs:
        tally: Counter[tuple[str, str]] = Counter()
        for i, per in states.items():
            tally[(cases[i]["label"], per.get(r, "errored"))] += 1
        mal = sum(v for (lab, _), v in tally.items() if lab == "malicious")
        ben = sum(v for (lab, _), v in tally.items() if lab == "benign")
        caught = tally[("malicious", "flagged")]
        false = tally[("benign", "flagged")]
        gaps = sum(v for (_, s), v in tally.items() if s in GAP_STATES)
        per_run.append({
            "run": r,
            "recall": caught / mal if mal else None, "recall_ci": wilson(caught, mal),
            "fpr": false / ben if ben else None, "fpr_ci": wilson(false, ben),
            "malicious": mal, "caught": caught, "benign": ben, "false_positives": false,
            "not_analyzed": gaps,
            "declined_malicious": tally[("malicious", "declined")],
            "declined_benign": tally[("benign", "declined")],
            "states": {f"{lab}/{s}": v for (lab, s), v in sorted(tally.items())},
        })
    out["per_run"] = per_run
    # Stability: a case whose verdict differs between runs of the same model.
    multi = [per for per in states.values() if len(per) > 1]
    flips = sum(1 for per in multi if len(set(per.values())) > 1)
    out["flip_rate"] = flips / len(multi) if multi else None
    out["flips"] = flips
    if group_field:
        groups: dict[str, Counter[str]] = defaultdict(Counter)
        for i, per in states.items():
            if cases[i]["label"] != "malicious":
                continue
            key = str(cases[i].get(group_field))
            for s in per.values():
                groups[key]["n"] += 1
                groups[key][s] += 1
        out["by_" + group_field] = {
            k: {"n": v["n"], "caught": v["flagged"], "recall": v["flagged"] / v["n"],
                "declined": v["declined"]}
            for k, v in sorted(groups.items())
        }
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--cases", type=Path, required=True)
    ap.add_argument("--group", default=None, help="Case field to break recall down by.")
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("runs", type=Path, nargs="+")
    args = ap.parse_args(argv)
    cases = [json.loads(line) for line in args.cases.read_text().splitlines() if line.strip()]
    results = [score(cases, load_run(d), args.group) for d in args.runs]
    for res in results:
        for pr in res["per_run"]:
            rec = pr["recall"]
            fpr = pr["fpr"]
            print(f"{res['model']:<18} run {pr['run']}: recall {rec:.1%} "
                  f"[{pr['recall_ci'][0]:.1%}, {pr['recall_ci'][1]:.1%}]  "
                  f"FPR {fpr:.1%} [{pr['fpr_ci'][0]:.1%}, {pr['fpr_ci'][1]:.1%}]  "
                  f"not analyzed {pr['not_analyzed']}")
        print(f"{res['model']:<18} flips {res['flips']} ({(res['flip_rate'] or 0):.1%}), "
              f"refusals {res['refusal_categories']}, served {res['served_models']}, cost {res['cost']}")
    if args.json:
        args.json.write_text(json.dumps({"cases_sha256_note": "see each run's batch-*.json meta",
                                         "results": results}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
