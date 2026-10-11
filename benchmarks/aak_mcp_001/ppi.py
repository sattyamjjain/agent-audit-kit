#!/usr/bin/env python3
"""Prediction-powered inference for the true-positive share of AAK-MCP-001 hits.

The question is a proportion: of the 1,311 hits, what share are true positives,
that is servers that really are open (``truly-open`` in ``CODEBOOK.md``)? A
model can label every hit cheaply but is biased in unknown ways; a human labels
only a 150-hit sample but is the ground truth. Prediction-powered inference
(Angelopoulos, Bates, Fannjiang, Jordan and Zrnic, "Prediction-Powered
Inference", *Science* 382, 2023) combines the two: use the model's labels on
everything, and the sample to measure and subtract the model's bias.

For a mean, with model labels ``f`` and human labels ``y``::

    theta_PP = mean(f over the population) + mean(y - f over the labelled sample)

The first term carries the model's coverage, the second (the *rectifier*) its
bias, estimated without bias from the sample, so ``theta_PP`` is unbiased
whatever the model's quality. A good model makes ``y - f`` mostly zero and the
interval narrow; a bad one makes it wide, never wrong.

Three adaptations to this measurement, the first two standard survey sampling:

* **Finite population.** The model labels every hit, so the first term is
  known exactly for THIS corpus and has no sampling variance; only the
  rectifier is estimated, with the finite-population correction. (The paper's
  ``var(f)/N`` term is for an unlabelled set drawn from a larger population;
  ``ppi_mean_iid`` implements that textbook form.) This is the difference
  estimator of model-assisted survey sampling (Sarndal, Swensson and Wretman,
  1992), with the model as the auxiliary variable.
* **Stratified sample.** The 150 hits are a stratified random sample
  (``sample.py``), so each stratum's rectifier is weighted by its population
  share ``W_h = N_h / N``. A stratum sampled in full contributes no variance.
* **Small-sample floor.** See ``stratified_ppi``: with an accurate model the
  plug-in variance of the rectifier is too small, so by default it is floored.

The human-only comparison is the stratified estimate of the same share, with a
Wilson score interval (``benchmarks/false_positive/stats.py``) evaluated at the
design's effective sample size: the effective-n approach of Korn and Graubard
(1998), with Wilson in place of their Clopper-Pearson. The effective n is capped
at the actual n, so the design never claims more precision than a simple random
sample of the same size would.

``unknown`` is neither true nor false, so both bounds are reported: unknown
counted as not truly open (``lower``), and as truly open (``upper``).

    python benchmarks/aak_mcp_001/ppi.py --model-labels /outside/repo/model-labels.jsonl

``--model-labels`` is JSONL of ``{"hit_id": ..., "label": ...}`` or one JSON
object mapping hit_id to label. Verdicts and strata come from the committed
``verdicts.json`` and ``sample.json``. While any verdict is null the script
reports the adjudication as pending and states no estimate.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SAMPLE_JSON = HERE / "sample.json"
VERDICTS_JSON = HERE / "verdicts.json"

LABELS = ("hosted-oauth", "public-by-design", "loopback", "truly-open", "auth-other", "unknown")
POSITIVE = frozenset({"truly-open"})
Z95 = 1.959963984540054


def _stats() -> ModuleType:
    """The Wilson interval the false-positive benchmark already uses, by path
    (benchmarks/ is not a package, and its directories reuse module names)."""
    key = "aak_mcp_001_fp_stats"
    if key in sys.modules:
        return sys.modules[key]
    path = REPO / "benchmarks" / "false_positive" / "stats.py"
    spec = importlib.util.spec_from_file_location(key, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _var(xs: list[float]) -> float:
    """Unbiased sample variance; 0 for fewer than two values."""
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return sum((x - m) ** 2 for x in xs) / (len(xs) - 1)


def _clip(x: float) -> float:
    return min(1.0, max(0.0, x))


# ---------------------------------------------------------------------------
# The textbook form (i.i.d. labelled + unlabelled), for reference and tests
# ---------------------------------------------------------------------------


def ppi_mean_iid(y: list[float], f_labeled: list[float], f_unlabeled: list[float],
                 z: float = Z95) -> tuple[float, tuple[float, float]]:
    """Angelopoulos et al. (2023), mean estimation: labelled pairs ``(y, f)``
    and model labels ``f_unlabeled`` on separate i.i.d. draws.

    ``theta = mean(f_unlabeled) - mean(f_labeled - y)``, variance
    ``var(f_unlabeled)/N + var(f_labeled - y)/n``.
    """
    if not y or len(y) != len(f_labeled) or not f_unlabeled:
        raise ValueError("need n >= 1 labelled pairs and N >= 1 unlabelled predictions")
    rect = [fi - yi for fi, yi in zip(f_labeled, y)]
    theta = _mean(f_unlabeled) - _mean(rect)
    se = math.sqrt(_var(f_unlabeled) / len(f_unlabeled) + _var(rect) / len(rect))
    return theta, (_clip(theta - z * se), _clip(theta + z * se))


# ---------------------------------------------------------------------------
# The form this measurement uses: finite population, stratified sample
# ---------------------------------------------------------------------------


def _by_stratum(units: Iterable[tuple[str, float]]) -> dict[str, list[float]]:
    out: dict[str, list[float]] = defaultdict(list)
    for h, v in units:
        out[h].append(v)
    return out


def stratified_ppi(population: list[tuple[str, float]],
                   sample: list[tuple[str, float, float]],
                   z: float = Z95,
                   small_sample: str | None = "plus-two") -> dict[str, Any]:
    """Stratified, finite-population PPI for a proportion.

    The interval is the paper's normal interval. Its variance is a plug-in, and
    with 150 labels and an accurate model the sample may hold only a handful of
    model/human disagreements, so the plug-in understates it: in a simulation of
    this design the plain interval covered 90% at a 2% model error rate and 68%
    at 1%. ``small_sample="plus-two"`` (the default) floors each stratum's
    rectifier variance at the pooled disagreement rate smoothed the
    Agresti-Coull way, ``(k + 2) / (n + 4)``. That is a bound from above,
    because ``(y - f)**2`` IS the disagreement indicator, so
    ``Var(y - f) <= P(y != f)``. It costs width only when disagreements are rare
    (simulated coverage stays at or above 95% at every error rate tried), and
    leaves the point estimate alone. ``small_sample=None`` is the plain form.

    Args:
        population: ``(stratum, f)`` for every unit, f in {0, 1} the model label.
        sample: ``(stratum, f, y)`` for each sampled unit, y the human label.

    Returns:
        ``estimate``, ``ci`` (clipped to [0, 1]), ``se``, the model-only mean,
        the rectifier, ``disagreements`` and ``warnings``.
    """
    if small_sample not in (None, "plus-two"):
        raise ValueError(f"small_sample must be None or 'plus-two', not {small_sample!r}")
    if not population or not sample:
        raise ValueError("empty population or sample")
    pop = _by_stratum(population)
    smp: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for h, f, y in sample:
        if h not in pop:
            raise ValueError(f"sampled stratum {h!r} is not in the population")
        smp[h].append((f, y))
    big_n = len(population)
    model_mean = _mean([f for _, f in population])
    all_d = [y - f for _, f, y in sample]
    disagreements = sum(1 for x in all_d if x != 0)
    floor = (disagreements + 2) / (len(all_d) + 4) if small_sample == "plus-two" else 0.0
    pooled_var = _var(all_d)
    rect = 0.0
    var = 0.0
    warnings: list[str] = []
    for h, fs in sorted(pop.items()):
        n_h, cap_n = len(smp.get(h, [])), len(fs)
        if n_h == 0:
            raise ValueError(f"stratum {h!r} has no sampled unit; its rectifier is unestimable")
        if n_h > cap_n:
            raise ValueError(f"stratum {h!r}: {n_h} sampled from {cap_n}")
        w = cap_n / big_n
        d = [y - f for f, y in smp[h]]
        rect += w * _mean(d)
        fpc = 1.0 - n_h / cap_n
        if n_h >= 2:
            s2 = _var(d)
        else:
            s2 = pooled_var
            if fpc > 0:
                warnings.append(f"stratum {h!r} has n=1; its rectifier variance is the pooled one")
        var += w * w * fpc * max(s2, floor) / n_h
    if disagreements == 0 and small_sample is None:
        warnings.append(
            "no model/human disagreement in the sample: the plain rectifier variance is 0 "
            "and the interval has no width; use small_sample='plus-two' or read the "
            "human-only Wilson interval"
        )
    theta = model_mean + rect
    se = math.sqrt(var)
    return {
        "estimate": theta,
        "ci": (_clip(theta - z * se), _clip(theta + z * se)),
        "se": se,
        "model_only": model_mean,
        "rectifier": rect,
        "disagreements": disagreements,
        "small_sample": small_sample,
        "warnings": warnings,
    }


def stratified_proportion(strata_sizes: dict[str, int],
                          sample: list[tuple[str, float]],
                          z: float = Z95) -> dict[str, Any]:
    """Human-only: the stratified estimate of a proportion with a Wilson interval.

    Point estimate ``sum_h W_h * mean_h(y)``; design variance with the
    finite-population correction; interval = Wilson at the effective sample
    size ``p(1-p)/var`` (Kish), capped at n. When the design variance is 0 (every
    stratum unanimous) the effective n is the actual n.
    """
    big_n = sum(strata_sizes.values())
    smp = _by_stratum(sample)
    n = len(sample)
    if n == 0 or big_n == 0:
        raise ValueError("empty sample or population")
    est = 0.0
    var = 0.0
    for h, cap_n in sorted(strata_sizes.items()):
        ys = smp.get(h, [])
        if not ys:
            raise ValueError(f"stratum {h!r} has no sampled unit")
        w = cap_n / big_n
        est += w * _mean(ys)
        var += w * w * (1.0 - len(ys) / cap_n) * _var(ys) / len(ys)
    p = _clip(est)
    n_eff = float(n)
    if var > 0 and 0.0 < p < 1.0:
        n_eff = min(float(n), p * (1.0 - p) / var)
    lo, hi = _stats().wilson_interval(p * n_eff, n_eff, z)  # Wilson is defined for real k/n
    return {"estimate": p, "ci": (lo, hi), "n": n, "effective_n": n_eff,
            "positives": sum(1 for _, y in sample if y > 0.5)}


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def read_model_labels(path: Path) -> dict[str, str]:
    """``{hit_id: label}`` from a JSON mapping, a JSON list of records, or JSONL."""
    text = path.read_text(encoding="utf-8").strip()
    try:
        whole = json.loads(text)
    except ValueError:
        whole = None
    if isinstance(whole, dict) and "hit_id" not in whole:
        return {str(k): str(v) for k, v in whole.items()}
    records = whole if isinstance(whole, list) else (
        [whole] if isinstance(whole, dict) else
        [json.loads(line) for line in text.splitlines() if line.strip()]
    )
    return {str(r["hit_id"]): str(r["label"]) for r in records}


def _indicator(label: str | None, positive: frozenset[str], unknown_as: float) -> float:
    if label is None:
        raise ValueError("missing label")
    if label not in LABELS:
        raise ValueError(f"unknown label {label!r}; the codebook's codes are {LABELS}")
    if label == "unknown":
        return unknown_as
    return 1.0 if label in positive else 0.0


def estimate(model: dict[str, str], sample_doc: dict[str, Any], verdicts_doc: dict[str, Any],
             positive: frozenset[str] = POSITIVE) -> dict[str, Any]:
    """Both estimators, for unknown counted as 0 (lower) and as 1 (upper)."""
    frame: dict[str, str] = {}
    for stratum, ids in sample_doc["frame"].items():
        for hid in ids:
            frame[hid] = stratum
    missing = sorted(set(frame) - set(model))
    if missing:
        raise ValueError(f"{len(missing)} population hits have no model label")
    sampled = {row["hit_id"]: row["stratum"] for row in sample_doc["sample"]}
    verdicts = {v["hit_id"]: v.get("verdict") for v in verdicts_doc["verdicts"]}
    if set(verdicts) != set(sampled):
        raise ValueError("verdicts.json and sample.json disagree about which hits were sampled")
    pending = sorted(h for h, v in verdicts.items() if v is None)
    if pending:
        return {"status": "pending", "verdicts_set": len(verdicts) - len(pending),
                "verdicts_total": len(verdicts)}
    sizes: dict[str, int] = defaultdict(int)
    for s in frame.values():
        sizes[s] += 1
    out: dict[str, Any] = {"status": "adjudicated", "positive_labels": sorted(positive),
                           "population": len(frame), "sample": len(sampled)}
    for bound, unknown_as in (("lower", 0.0), ("upper", 1.0)):
        pop = [(frame[h], _indicator(model[h], positive, unknown_as)) for h in sorted(frame)]
        smp = [(sampled[h], _indicator(model[h], positive, unknown_as),
                _indicator(verdicts[h], positive, unknown_as)) for h in sorted(sampled)]
        out[bound] = {
            "ppi": stratified_ppi(pop, smp),
            "human_only": stratified_proportion(dict(sizes), [(s, y) for s, _, y in smp]),
            "model_human_agreement": sum(1 for _, f, y in smp if f == y) / len(smp),
        }
    return out


def _fmt(r: dict[str, Any]) -> str:
    lo, hi = r["ci"]
    return f"{100 * r['estimate']:.1f}% [{100 * lo:.1f}%, {100 * hi:.1f}%]"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model-labels", type=Path, required=True)
    ap.add_argument("--sample", type=Path, default=SAMPLE_JSON)
    ap.add_argument("--verdicts", type=Path, default=VERDICTS_JSON)
    ap.add_argument("--positive", default=",".join(sorted(POSITIVE)),
                    help="comma-separated codes counted as true positives (default: truly-open)")
    ap.add_argument("--out", type=Path, default=None, help="also write the result as JSON")
    args = ap.parse_args(argv)
    positive = frozenset(p.strip() for p in args.positive.split(",") if p.strip())
    result = estimate(
        read_model_labels(args.model_labels),
        json.loads(args.sample.read_text(encoding="utf-8")),
        json.loads(args.verdicts.read_text(encoding="utf-8")),
        positive,
    )
    if args.out:
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["status"] == "pending":
        print(f"adjudication pending: {result['verdicts_set']} of {result['verdicts_total']} "
              f"verdicts set; no estimate is stated until all are")
        return 0
    for bound in ("lower", "upper"):
        r = result[bound]
        print(f"[unknown = {'not ' if bound == 'lower' else ''}{'/'.join(sorted(positive))}]")
        print(f"  PPI         {_fmt(r['ppi'])}   (model-only {100 * r['ppi']['model_only']:.1f}%)")
        print(f"  human-only  {_fmt(r['human_only'])}   (n = {r['human_only']['n']}, "
              f"effective n = {r['human_only']['effective_n']:.1f})")
        for w in r["ppi"]["warnings"]:
            print(f"  warning: {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
