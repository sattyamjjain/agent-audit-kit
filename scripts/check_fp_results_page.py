#!/usr/bin/env python3
"""Guard: the numbers in the FP benchmark's RESULTS.md describe the run it reports.

`benchmarks/false_positive/RESULTS.md` is written by hand, and it drifted the way
hand-written pages do. The 2026-09-03 run moved the headline to 0 / 1 with a
Wilson interval of [0.0%, 79.3%], while the Limitations section below it kept
describing the 2026-08-24 run: 6 HIGH/CRITICAL findings, [30.0%, 90.3%], a 66.7%
point estimate. `tests/test_false_positive_artifacts_agree.py` checked the
headline, and nothing checked the rest of the page.

This checks the rest. Outside the `## History` section, which is where every
earlier run's numbers belong, each of these must describe the run recorded in
`results.json` and `adjudication.json`:

- a count written "N HIGH/CRITICAL" must equal `high_critical_findings`;
- a bracketed interval "[a%, b%]" must equal the Wilson 95% interval of the
  adjudicated false-positive rate;
- any other percentage must be one of the run's own: the false-positive rate,
  either end of that interval, or the share of configs with a HIGH/CRITICAL
  finding. A percentage naming the confidence level ("95% CI") is not a result.

A number that is none of those is a claim about some other run, and it goes in
the History table. The expected values come from the benchmark's own `stats`
module, so the Wilson arithmetic is not written down a second time here.

Callers: `make fp-check`, and `tests/test_false_positive_artifacts_agree.py`
(which also feeds it the stale bullet as a negative fixture).

Usage:
    python scripts/check_fp_results_page.py    # exit 1 on any disagreement
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.false_positive.stats import pct, wilson_interval  # noqa: E402

FP_DIR = REPO_ROOT / "benchmarks" / "false_positive"
PAGE = FP_DIR / "RESULTS.md"
RESULTS = FP_DIR / "results.json"
ADJUDICATION = FP_DIR / "adjudication.json"

# `\s+` spans a line break, so a count wrapped across two lines is still read.
_COUNT_RE = re.compile(r"(?<![\d.,])(\d[\d,]*)\s+HIGH/CRITICAL\b")
_INTERVAL_RE = re.compile(r"\[\s*(\d+(?:\.\d+)?%)\s*,\s*(\d+(?:\.\d+)?%)\s*\]")
# The confidence level ("Wilson 95% CI", "95% confidence") is not a measurement.
_PERCENT_RE = re.compile(r"(?<![\d.])(\d+(?:\.\d+)?%)(?!\s*(?:CI\b|confidence\b))")
_H2_RE = re.compile(r"^##\s")
_HISTORY_RE = re.compile(r"^##\s+History\b")


def expected() -> dict[str, Any]:
    """The values the page body may state, derived from the committed artifacts."""
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    verdicts = json.loads(ADJUDICATION.read_text(encoding="utf-8")).get("verdicts") or []
    fps = sum(1 for v in verdicts if v.get("verdict") == "false_positive")
    adjudicated = len(verdicts)
    low, high = wilson_interval(fps, adjudicated)
    rate = pct(fps / adjudicated) if adjudicated else pct(0.0)
    return {
        "high_critical": int(results["high_critical_findings"]),
        "interval": (pct(low), pct(high)),
        "percentages": {
            rate, pct(low), pct(high), pct(float(results["high_critical_config_rate"])),
        },
    }


def body_without_history(text: str) -> str:
    """The page with the History section blanked, line numbers preserved."""
    out: list[str] = []
    in_history = False
    for line in text.splitlines():
        if _H2_RE.match(line):
            in_history = bool(_HISTORY_RE.match(line))
        out.append("" if in_history else line)
    return "\n".join(out)


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def find_disagreements(text: str, numbers: Optional[dict[str, Any]] = None) -> list[str]:
    """``RESULTS.md:LINE: ...`` for each number in the body that is not this run's."""
    numbers = numbers or expected()
    body = body_without_history(text)
    problems: list[str] = []

    for m in _COUNT_RE.finditer(body):
        claimed = int(m.group(1).replace(",", ""))
        if claimed != numbers["high_critical"]:
            problems.append(
                f"RESULTS.md:{_line(body, m.start())}: '{' '.join(m.group(0).split())}' "
                f"but the run has {numbers['high_critical']} HIGH/CRITICAL finding(s)"
            )

    interval_spans: list[tuple[int, int]] = []
    low, high = numbers["interval"]
    for m in _INTERVAL_RE.finditer(body):
        interval_spans.append(m.span())
        if (m.group(1), m.group(2)) != (low, high):
            problems.append(
                f"RESULTS.md:{_line(body, m.start())}: interval [{m.group(1)}, {m.group(2)}] "
                f"but the run's Wilson 95% interval is [{low}, {high}]"
            )

    for m in _PERCENT_RE.finditer(body):
        if any(start <= m.start() < end for start, end in interval_spans):
            continue  # judged as a pair above
        if m.group(1) not in numbers["percentages"]:
            problems.append(
                f"RESULTS.md:{_line(body, m.start())}: '{m.group(1)}' is not one of the "
                f"run's own percentages {sorted(numbers['percentages'])}; an earlier "
                f"run's number belongs in the History table"
            )
    return problems


def main() -> int:
    problems = find_disagreements(PAGE.read_text(encoding="utf-8"))
    if problems:
        sys.stderr.write(
            "fp-results-page: RESULTS.md states numbers from a run other than the one "
            "it reports (move them to the History table, or fix them):\n  "
            + "\n  ".join(problems) + "\n"
        )
        return 1
    print("fp-results-page: every number outside History matches the run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
