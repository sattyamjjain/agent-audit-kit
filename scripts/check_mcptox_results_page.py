#!/usr/bin/env python3
"""Guard: every rate on the MCPTox RESULTS.md is one its run recorded.

`benchmarks/mcptox/RESULTS.md` is hand-written, and hand-written pages drift:
the FP benchmark's Limitations once described an earlier run under a headline
reporting a later one (`check_fp_results_page.py` exists because of it). This
page is checked the same way, with the patterns that script supplies. Outside
the `## History` section:

- a fraction "k / n" must be one of the (k, n) pairs in `results.json`'s
  `measurement` block;
- a bracketed interval "[a%, b%]" must be the Wilson 95% interval of one of
  those pairs, recomputed with the benchmark's own `stats` module rather than
  read back from the file;
- any other percentage must be one of those pairs' rates or interval ends. A
  percentage naming the confidence level ("95% CI") is not a result.

A number that is none of those describes some other run, or nothing. The page
also has to name the measured dataset commit and AAK package digest, so a page
left behind by a re-measurement fails even where its rates happen to agree.

Callers: `make mcptox-check`, and `tests/test_mcptox_harness.py`, which also
feeds it doctored pages as negative fixtures.

Usage:
    python scripts/check_mcptox_results_page.py    # exit 1 on any disagreement
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.false_positive.stats import pct, wilson_interval  # noqa: E402
from scripts.check_fp_results_page import (  # noqa: E402
    _INTERVAL_RE,
    _PERCENT_RE,
    body_without_history,
)

MCPTOX_DIR = REPO_ROOT / "benchmarks" / "mcptox"
PAGE = MCPTOX_DIR / "RESULTS.md"
RESULTS = MCPTOX_DIR / "results.json"

# "926 / 1,348". The digit classes are disjoint from `\s` and `/`, so this is
# linear (no ReDoS shape for CodeQL to flag).
_FRACTION_RE = re.compile(r"(?<![\d.,])(\d[\d,]*)\s*/\s*(\d[\d,]*)")


def _pairs(node: Any) -> set[tuple[int, int]]:
    """Every (k, n) rate in the measurement block, at any depth."""
    out: set[tuple[int, int]] = set()
    if isinstance(node, dict):
        if isinstance(node.get("k"), int) and isinstance(node.get("n"), int):
            out.add((node["k"], node["n"]))
        for value in node.values():
            out |= _pairs(value)
    elif isinstance(node, list):
        for value in node:
            out |= _pairs(value)
    return out


def expected(results: dict[str, Any]) -> dict[str, Any]:
    """What the page body may state, derived from the committed results."""
    pairs = _pairs(results.get("measurement") or {})
    intervals: set[tuple[str, str]] = set()
    percentages: set[str] = set()
    for k, n in pairs:
        low, high = wilson_interval(k, n)
        intervals.add((pct(low), pct(high)))
        percentages |= {pct(k / n) if n else pct(0.0), pct(low), pct(high)}
    return {
        "pairs": pairs,
        "intervals": intervals,
        "percentages": percentages,
        "must_mention": [
            str((results.get("dataset") or {}).get("commit") or "")[:12],
            str((results.get("aak") or {}).get("package_digest") or "")[:12],
        ],
    }


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def find_disagreements(text: str, numbers: dict[str, Any]) -> list[str]:
    """``RESULTS.md:LINE: ...`` for each statement the run does not support."""
    body = body_without_history(text)
    problems: list[str] = []
    for token in numbers["must_mention"]:
        if not token or token not in body:
            problems.append(f"RESULTS.md: does not name {token!r} from results.json")

    for m in _FRACTION_RE.finditer(body):
        pair = (int(m.group(1).replace(",", "")), int(m.group(2).replace(",", "")))
        if pair not in numbers["pairs"]:
            problems.append(
                f"RESULTS.md:{_line(body, m.start())}: '{m.group(0).strip()}' is not a "
                "k / n pair the run recorded"
            )

    spans: list[tuple[int, int]] = []
    for m in _INTERVAL_RE.finditer(body):
        spans.append(m.span())
        if (m.group(1), m.group(2)) not in numbers["intervals"]:
            problems.append(
                f"RESULTS.md:{_line(body, m.start())}: interval [{m.group(1)}, {m.group(2)}] "
                "is not the Wilson 95% interval of any recorded rate"
            )

    for m in _PERCENT_RE.finditer(body):
        if any(start <= m.start() < end for start, end in spans):
            continue  # judged as a pair above
        if m.group(1) not in numbers["percentages"]:
            problems.append(
                f"RESULTS.md:{_line(body, m.start())}: '{m.group(1)}' is not one of the "
                "run's own rates or interval ends; another run's number belongs in History"
            )
    return problems


def main() -> int:
    for f in (PAGE, RESULTS):
        if not f.is_file():
            sys.stderr.write(f"mcptox-page: {f.relative_to(REPO_ROOT)} is missing\n")
            return 1
    numbers = expected(json.loads(RESULTS.read_text(encoding="utf-8")))
    problems = find_disagreements(PAGE.read_text(encoding="utf-8"), numbers)
    if problems:
        sys.stderr.write("mcptox-page: RESULTS.md is not supported by results.json:\n  "
                         + "\n  ".join(problems) + "\n")
        return 1
    print("mcptox-page: every rate outside History matches results.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
