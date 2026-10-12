#!/usr/bin/env python3
"""Weekly proof that ``scan --llm-scan`` still works against the live Claude API.

Nothing else would notice when it stops. A model gets retired and every request
returns 404; a provider starts declining tool descriptions; a response shape
changes so no verdict parses. Each of those used to look exactly like a clean
scan (see the docstring of agent_audit_kit/llm_scan.py), and the deterministic
test suite cannot see any of them because it never talks to a model.

This runs the real code path, ``run_llm_scan``, over ten synthetic tools in
tests/fixtures/llm_canary/ (five poisoned, five benign, labelled in
labels.json). For each model it fails when:

- any tool went unanalyzed (an AAK-LLM-002: refusal, error, cut-off reply);
- a reply came from a different model than the one requested;
- fewer than ``--min-caught`` of the poisoned tools were flagged;
- more than ``--max-false`` of the benign tools were flagged.

The bars are deliberately loose. This is a smoke alarm for breakage, not a
measurement: the published per-model numbers come from the MCPTox eval in
benchmarks/llm_scan_eval/, which has receipts.

Usage:
    ANTHROPIC_API_KEY=... python scripts/llm_canary.py --model claude-haiku-5-5 --model claude-sonnet-5-5
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from agent_audit_kit.llm_scan import LlmScanReport, run_llm_scan  # noqa: E402

FIXTURE = REPO / "tests" / "fixtures" / "llm_canary"


def check(report: LlmScanReport, labels: dict[str, list[str]], min_caught: int,
          max_false: int) -> list[str]:
    """Every reason this model's run fails the canary; empty when it passes."""
    problems: list[str] = []
    expected = set(labels["poisoned"]) | set(labels["benign"])
    seen = {o.tool.name for o in report.outcomes}
    if seen != expected:
        problems.append(f"expected tools {sorted(expected)}, analyzed set was {sorted(seen)}")
    gaps = [o for o in report.outcomes if o.status == "not_analyzed"]
    for o in gaps:
        problems.append(f"{o.tool.name} not analyzed: {o.why}")
    others = sorted(m for m in report.served_models if m != report.model)
    if others:
        problems.append(f"replies came from {others}, not {report.model}")
    flagged = {o.tool.name for o in report.outcomes if o.status == "flagged"}
    caught = flagged & set(labels["poisoned"])
    false = flagged & set(labels["benign"])
    if len(caught) < min_caught:
        missed = sorted(set(labels["poisoned"]) - caught)
        problems.append(f"caught {len(caught)}/{len(labels['poisoned'])} poisoned tools "
                        f"(minimum {min_caught}); missed {missed}")
    if len(false) > max_false:
        problems.append(f"flagged {len(false)} benign tools (maximum {max_false}): {sorted(false)}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--model", action="append", required=True,
                        help="Claude model id to check; repeat for several.")
    parser.add_argument("--min-caught", type=int, default=4)
    parser.add_argument("--max-false", type=int, default=1)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    args = parser.parse_args(argv)

    labels = json.loads((args.fixture / "labels.json").read_text())
    failed = False
    for model in args.model:
        report = run_llm_scan(args.fixture, model=model)
        for o in report.outcomes:
            verdict = o.verdict
            detail = (verdict.reason if verdict else o.why)[:160]
            print(f"{model}  {o.tool.name:<17} {o.status:<13} {detail}")
        problems = check(report, labels, args.min_caught, args.max_false)
        status = "FAIL" if problems else "ok"
        print(f"{model}: {status} ({report.flagged} flagged, {report.gaps} not analyzed, "
              f"served by {dict(report.served_models)})")
        for p in problems:
            print(f"  - {p}")
        failed = failed or bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
