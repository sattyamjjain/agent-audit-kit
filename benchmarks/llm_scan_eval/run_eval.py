#!/usr/bin/env python3
"""Measure `scan --llm-scan` per model on a labelled set, with receipts.

The requests are built by the product's own code, ``llm_scan.anthropic_request``
over ``llm_scan.render_tool_text``, so the eval measures exactly what a user's
``--llm claude-*`` run sends: the same system prompt, fence, schema and effort.
The replies are parsed by ``llm_scan.parse_anthropic_message``, so a refusal or
a cut-off reply counts the way the CLI counts it, as not analyzed.

It goes through the Message Batches API (half price; results kept 29 days),
whose server-side fallback parameter is rejected, so a refusal is measured as a
refusal. Every request and every raw result is archived under ``--out`` (see
batch.py). Fresh API runs against these receipts are replications: hosted
inference is not deterministic and the current models accept no temperature.

Needs the official SDK, which AAK does not depend on: ``pip install anthropic``.

    python run_eval.py submit  --cases cases.jsonl --model claude-haiku-5-5 --runs 3 --out runs/haiku
    python run_eval.py collect --out runs/haiku
    python run_eval.py submit  --cases cases.jsonl --model claude-opus-5-5 --limit 50 --out runs/opus-pilot
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(HERE))

import batch as ab  # noqa: E402
from agent_audit_kit import llm_scan  # noqa: E402
from agent_audit_kit.scanners.tool_poisoning import _iter_param_descriptions  # noqa: E402


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for c in cases:
        if c.get("label") not in ("malicious", "benign"):
            raise SystemExit(f"case {c.get('case_id')!r}: label must be malicious or benign")
    return cases


def tool_text(case: dict[str, Any]) -> llm_scan.ToolText:
    schema = case.get("input_schema")
    schema_desc = ""
    params: tuple[tuple[str, str], ...] = ()
    if isinstance(schema, dict):
        sd = schema.get("description")
        schema_desc = sd if isinstance(sd, str) else ""
        params = tuple(_iter_param_descriptions(schema, ""))
    return llm_scan.ToolText(
        source="benchmark",
        file_path=str(case["case_id"]),
        line_number=None,
        name=str(case.get("tool") or "<unnamed>"),
        description=str(case.get("description") or ""),
        server=str(case.get("server") or ""),
        schema_description=schema_desc,
        params=params,
    )


def cmd_submit(args: argparse.Namespace) -> int:
    cases = load_cases(args.cases)
    indices = list(range(len(cases)))
    if args.limit:
        rng = random.Random(args.seed)
        mal = [i for i in indices if cases[i]["label"] == "malicious"]
        ben = [i for i in indices if cases[i]["label"] == "benign"]
        k_ben = round(args.limit * len(ben) / len(indices))
        indices = sorted(rng.sample(mal, args.limit - k_ben) + rng.sample(ben, k_ben))
    requests = []
    truncated = 0
    for i in indices:
        rendered, cut = llm_scan.render_tool_text(tool_text(cases[i]))
        truncated += cut
        params = llm_scan.anthropic_request(args.model, rendered, effort=args.effort)
        for run in range(1, args.runs + 1):
            requests.append({"custom_id": f"c{i:05d}-r{run}", "params": params})
    meta = {
        "model": args.model,
        "effort": args.effort,
        "runs": args.runs,
        "cases": str(args.cases),
        "cases_sha256": ab.sha256_file(args.cases),
        "case_indices": indices,
        "limit": args.limit,
        "seed": args.seed,
        "prompt_sha256": llm_scan.PROMPT_SHA256,
        "max_tokens": llm_scan.MAX_OUTPUT_TOKENS,
        "aak_commit": ab.git_commit(REPO),
        "inputs_truncated": truncated,
    }
    cl = ab.client()
    batch_id = ab.submit(cl, requests, meta, args.out)
    (args.out / "LATEST").write_text(batch_id + "\n")
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    batch_id = args.batch or (args.out / "LATEST").read_text().strip()
    cl = ab.client()
    ab.wait(cl, batch_id, poll_seconds=args.poll)
    rows = ab.fetch(cl, batch_id, args.out)
    submitted = json.loads((args.out / f"batch-{batch_id}.json").read_text())
    cost = ab.batch_cost(rows, submitted["meta"]["model"])
    (args.out / f"cost-{batch_id}.json").write_text(json.dumps(cost, indent=1) + "\n")
    print(f"{batch_id}: {len(rows)} results, {cost}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("submit")
    s.add_argument("--cases", type=Path, required=True)
    s.add_argument("--model", required=True)
    s.add_argument("--runs", type=int, default=3)
    s.add_argument("--effort", default="low")
    s.add_argument("--limit", type=int, default=0, help="Stratified sample size for a pilot.")
    s.add_argument("--seed", type=int, default=20261012)
    s.add_argument("--out", type=Path, required=True)
    c = sub.add_parser("collect")
    c.add_argument("--out", type=Path, required=True)
    c.add_argument("--batch", default=None)
    c.add_argument("--poll", type=int, default=30)
    args = ap.parse_args(argv)
    return cmd_submit(args) if args.cmd == "submit" else cmd_collect(args)


if __name__ == "__main__":
    raise SystemExit(main())
