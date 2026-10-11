"""Backtest metrics. Pure functions over result rows; no I/O.

Scoring rules, stated once so every table means the same thing:

* A prediction is **correct** when it names one of the record's acceptable
  classes. Most records accept one; a disposition that did two things (a pin
  and pattern rules) accepts either.
* **needs-human** is an abstention. It is counted as not correct in accuracy,
  and reported separately as coverage, with accuracy on the records where the
  model did commit (selective accuracy). Saying "a human should look" is not a
  wrong answer, but it saves no triage time, and both facts are reported.
* A call that failed, was refused, or came back from a model other than the one
  requested is **not scored as a prediction**. Those are counted on their own
  so a fallback cannot quietly change what the accuracy measures.
* Intervals are 95% Wilson score intervals, as in the false-positive benchmark.
"""

from __future__ import annotations

import statistics
from typing import Any, Iterable

from benchmarks.cve_prescreen import DISPOSITIONS
from benchmarks.false_positive.stats import wilson_interval


def ratio(k: int, n: int) -> dict[str, Any]:
    low, high = wilson_interval(k, n)
    return {
        "k": k,
        "n": n,
        "rate": round(k / n, 4) if n else None,
        "ci95": [round(low, 4), round(high, 4)] if n else None,
    }


def classification(rows: Iterable[dict[str, Any]], key: str = "predicted") -> dict[str, Any]:
    """Accuracy, coverage and a confusion matrix for one predictor.

    Each row carries `truth` (primary class), `acceptable` (list) and `key`
    (the predicted class, or None when the call was not scorable).
    """
    rows = list(rows)
    scored = [r for r in rows if r.get(key)]
    confusion = {t: {p: 0 for p in DISPOSITIONS} for t in DISPOSITIONS}
    correct = 0
    abstained = 0
    for row in scored:
        pred = row[key]
        truth = row["truth"]
        if pred in row["acceptable"]:
            correct += 1
            confusion[pred][pred] += 1
        else:
            confusion[truth][pred] += 1
        if pred == "needs-human":
            abstained += 1
    committed = [r for r in scored if r[key] != "needs-human"]
    committed_correct = sum(1 for r in committed if r[key] in r["acceptable"])
    per_class = {}
    for cls in DISPOSITIONS:
        tp = confusion[cls][cls]
        predicted = sum(confusion[t][cls] for t in DISPOSITIONS)
        actual = sum(confusion[cls].values())
        per_class[cls] = {
            "precision": ratio(tp, predicted),
            "recall": ratio(tp, actual),
        }
    return {
        "records": len(rows),
        "scored": len(scored),
        "unscored": len(rows) - len(scored),
        "accuracy": ratio(correct, len(scored)),
        "coverage": ratio(len(scored) - abstained, len(scored)),
        "selective_accuracy": ratio(committed_correct, len(committed)),
        "confusion": confusion,
        "per_class": per_class,
    }


def binary(rows: Iterable[dict[str, Any]], truth_key: str, pred_key: str) -> dict[str, Any]:
    """Precision and recall of a yes/no predictor (the noise filter)."""
    rows = [r for r in rows if r.get(pred_key) is not None]
    tp = sum(1 for r in rows if r[truth_key] and r[pred_key])
    fp = sum(1 for r in rows if not r[truth_key] and r[pred_key])
    fn = sum(1 for r in rows if r[truth_key] and not r[pred_key])
    tn = sum(1 for r in rows if not r[truth_key] and not r[pred_key])
    return {
        "scored": len(rows),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "false_positive_ids": sorted(r["cve"] for r in rows if not r[truth_key] and r[pred_key]),
        "false_negative_ids": sorted(r["cve"] for r in rows if r[truth_key] and not r[pred_key]),
    }


def _nearest_rank(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * pct // 100))
    return ordered[int(rank) - 1]


def distribution(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "mean": round(statistics.mean(values), 4),
        "median": round(statistics.median(values), 4),
        "p90": round(_nearest_rank(values, 90), 4),
        "max": round(max(values), 4),
        "total": round(sum(values), 4),
    }


def calls(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Per-stage health and spend: ok, refusals, fallbacks, cost and time."""
    results = [r for r in results if r]
    return {
        "calls": len(results),
        "ok": sum(1 for r in results if r.get("ok")),
        "failed": sum(1 for r in results if not r.get("ok")),
        "refusals": sum(1 for r in results if r.get("refusal")),
        "model_mismatch": sum(1 for r in results if r.get("model_mismatch")),
        "models_used": sorted({m for r in results for m in r.get("models_used") or []}),
        "cost_basis": sorted({str(r.get("cost_basis")) for r in results if r.get("cost_basis")}),
        "cost_usd": distribution([float(r["cost_usd"]) for r in results if r.get("cost_usd") is not None]),
        "wall_seconds": distribution([float(r["wall_seconds"]) for r in results if r.get("wall_seconds")]),
        "api_seconds": distribution(
            [r["duration_api_ms"] / 1000.0 for r in results if r.get("duration_api_ms") is not None]
        ),
    }


def extraction(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Exact-match of extracted values against the fields they cite."""
    rows = [r for r in rows if r.get("extraction")]
    values = sum(r["extraction"]["values"] for r in rows)
    exact = sum(r["extraction"]["exact"] for r in rows)
    verdicts: dict[str, int] = {}
    for row in rows:
        for name, count in row["extraction"]["verdicts"].items():
            verdicts[name] = verdicts.get(name, 0) + count
    with_values = [r for r in rows if r["extraction"]["values"]]
    with_expected = [r for r in rows if r["extraction"]["packages_expected"]]
    without_expected = [r for r in rows if not r["extraction"]["packages_expected"]]
    return {
        "records": len(rows),
        "values": ratio(exact, values),
        "verdicts": dict(sorted(verdicts.items())),
        "records_all_exact": ratio(sum(1 for r in with_values if r["extraction"]["all_exact"]), len(with_values)),
        "records_with_invented_value": sum(1 for r in rows if r["extraction"]["invented"]),
        "package_set_exact": ratio(
            sum(1 for r in with_expected if r["extraction"]["package_set_exact"]), len(with_expected)
        ),
        "empty_when_nothing_structured": ratio(
            sum(1 for r in without_expected if not r["extraction"]["packages_listed"]), len(without_expected)
        ),
    }
