#!/usr/bin/env python3
"""Guard: the instruction-file slice's RESULTS.md says only what its run supports.

`benchmarks/false_positive/instruction_files/RESULTS.md` is hand-written, like
the MCP slice's page, and is checked the same way (`check_fp_results_page.py`
supplies the patterns), with one more state, because this slice is published
before it is adjudicated:

- **Pending**, while any verdict in `adjudication.json` is null. The page must
  say "pending adjudication". It may state the measured counts: a count written
  "N HIGH/CRITICAL" must equal the run's. It must state no false-positive rate:
  no bracketed interval at all, and the only percentage allowed is the share of
  repositories with a HIGH/CRITICAL finding, which is a measurement, not a
  verdict.
- **Adjudicated**, once every verdict is set. The rate, its Wilson 95% interval
  and the counts must all match, and the page must stop saying "pending".

Either way `adjudication.json` must cover exactly the HIGH/CRITICAL findings in
`results.json`, matched by repository, path, line and rule. A re-run that moves
the findings then invalidates the adjudication instead of keeping verdicts for
findings that no longer exist, and every verdict must be one of
true_positive, false_positive or ambiguous.

Callers: `make fp-instruction-check` (and so `make fp-check`), and
`tests/test_fp_instruction_slice.py`.
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
    _COUNT_RE,
    _INTERVAL_RE,
    _PERCENT_RE,
    body_without_history,
)

SLICE_DIR = REPO_ROOT / "benchmarks" / "false_positive" / "instruction_files"
PAGE = SLICE_DIR / "RESULTS.md"
RESULTS = SLICE_DIR / "results.json"
ADJUDICATION = SLICE_DIR / "adjudication.json"

VERDICTS = frozenset({"true_positive", "false_positive", "ambiguous"})
_KEY = ("repo", "path", "line", "rule_id")
_PENDING_RE = re.compile(r"pending adjudication", re.I)


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def expected(results: dict[str, Any], adjudication: dict[str, Any]) -> dict[str, Any]:
    """What the page may state, plus any disagreement between the two artifacts."""
    problems: list[str] = []
    verdicts = adjudication.get("verdicts") or []
    findings = {tuple(f[k] for k in _KEY) for f in results.get("high_critical") or []}
    judged = [tuple(v.get(k) for k in _KEY) for v in verdicts]
    if len(judged) != len(set(judged)):
        problems.append("adjudication.json lists a finding twice")
    if set(judged) != findings:
        missing = len(findings - set(judged))
        extra = len(set(judged) - findings)
        problems.append(
            f"adjudication.json does not match results.json ({missing} finding(s) without an entry, "
            f"{extra} entry(ies) for findings the run no longer has); re-run "
            "`run.py --init-adjudication` before any verdict is set, or re-adjudicate"
        )
    for v in verdicts:
        if v.get("verdict") is not None and v.get("verdict") not in VERDICTS:
            problems.append(f"verdict {v.get('verdict')!r} is not one of {sorted(VERDICTS)}")
    pending = not verdicts and bool(findings) or any(v.get("verdict") is None for v in verdicts)
    repo_rate = pct(float(results.get("high_critical_repo_rate") or 0.0))
    out: dict[str, Any] = {
        "problems": problems,
        "pending": pending,
        "high_critical": int(results.get("high_critical_findings") or 0),
        "percentages": {repo_rate},
        "interval": None,
    }
    if not pending:
        fps = sum(1 for v in verdicts if v.get("verdict") == "false_positive")
        low, high = wilson_interval(fps, len(verdicts))
        rate = pct(fps / len(verdicts)) if verdicts else pct(0.0)
        out["percentages"] = {repo_rate, rate, pct(low), pct(high)}
        out["interval"] = (pct(low), pct(high))
    return out


def find_disagreements(text: str, numbers: dict[str, Any]) -> list[str]:
    """``RESULTS.md:LINE: ...`` for each statement the run does not support."""
    problems = list(numbers["problems"])
    body = body_without_history(text)
    says_pending = bool(_PENDING_RE.search(body))
    if numbers["pending"] and not says_pending:
        problems.append("RESULTS.md: the slice is pending adjudication but the page does not say so")
    if not numbers["pending"] and says_pending:
        problems.append("RESULTS.md: every verdict is set but the page still says 'pending adjudication'")

    for m in _COUNT_RE.finditer(body):
        claimed = int(m.group(1).replace(",", ""))
        if claimed != numbers["high_critical"]:
            problems.append(
                f"RESULTS.md:{_line(body, m.start())}: '{' '.join(m.group(0).split())}' "
                f"but the run has {numbers['high_critical']} HIGH/CRITICAL finding(s)"
            )

    spans: list[tuple[int, int]] = []
    for m in _INTERVAL_RE.finditer(body):
        spans.append(m.span())
        if numbers["interval"] is None:
            problems.append(
                f"RESULTS.md:{_line(body, m.start())}: interval [{m.group(1)}, {m.group(2)}] "
                "stated while the slice is pending adjudication; no rate exists yet"
            )
        elif (m.group(1), m.group(2)) != numbers["interval"]:
            low, high = numbers["interval"]
            problems.append(
                f"RESULTS.md:{_line(body, m.start())}: interval [{m.group(1)}, {m.group(2)}] "
                f"but the adjudicated Wilson 95% interval is [{low}, {high}]"
            )

    for m in _PERCENT_RE.finditer(body):
        if any(start <= m.start() < end for start, end in spans):
            continue
        if m.group(1) not in numbers["percentages"]:
            what = (
                "the only percentage a pending slice may state is the share of repositories "
                f"with a HIGH/CRITICAL finding, {sorted(numbers['percentages'])}"
                if numbers["pending"]
                else f"not one of the run's own percentages {sorted(numbers['percentages'])}"
            )
            problems.append(f"RESULTS.md:{_line(body, m.start())}: '{m.group(1)}': {what}")
    return problems


def main() -> int:
    for f in (PAGE, RESULTS, ADJUDICATION):
        if not f.is_file():
            sys.stderr.write(f"fp-instruction-page: {f.relative_to(REPO_ROOT)} is missing\n")
            return 1
    numbers = expected(
        json.loads(RESULTS.read_text(encoding="utf-8")),
        json.loads(ADJUDICATION.read_text(encoding="utf-8")),
    )
    problems = find_disagreements(PAGE.read_text(encoding="utf-8"), numbers)
    if problems:
        sys.stderr.write("fp-instruction-page: RESULTS.md is not supported by its run:\n  "
                         + "\n  ".join(problems) + "\n")
        return 1
    state = "pending adjudication" if numbers["pending"] else "adjudicated"
    print(f"fp-instruction-page: RESULTS.md agrees with the run ({state}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
