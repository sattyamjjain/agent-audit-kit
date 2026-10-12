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
    python run_eval.py redact  --out runs/haiku --to receipts/haiku

When the labelled set may not be redistributed (MCPTox carries no license),
keep the raw receipts outside the repository and commit only ``redact``'s
output: requests and replies quote the dataset, the redacted rows do not.
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


def redact_row(row: dict[str, Any]) -> dict[str, Any]:
    """A result row with every byte of text removed, for committing.

    Keeps what the scorer and an auditor need: the state the CLI's parser
    assigns, the refusal category, the served model, the message id, token
    usage, and the SHA-256 of the raw row, so anyone holding the raw receipts
    can prove this row came from them. Drops the reply text, which quotes the
    tool description it judged.
    """
    out: dict[str, Any] = {
        "custom_id": row["custom_id"],
        "type": row["type"],
        "row_sha256": ab.sha256_text(json.dumps(row, sort_keys=True)),
    }
    message = row.get("message")
    if message:
        verdict = llm_scan.parse_anthropic_message(message)
        out.update({
            "state": verdict.status,
            "category": verdict.category or None,
            "refusal_category": verdict.refusal_category,
            "message_id": message.get("id"),
            "model": message.get("model"),
            "stop_reason": message.get("stop_reason"),
            "usage": message.get("usage"),
        })
    else:
        out["state"] = "errored"
    return out


def cmd_redact(args: argparse.Namespace) -> int:
    """Write text-free receipts for every batch under --out into --to."""
    args.to.mkdir(parents=True, exist_ok=True)
    for b in sorted(args.out.glob("batch-*.json")):
        submitted = json.loads(b.read_text())
        batch_id = submitted["batch_id"]
        meta = {k: v for k, v in submitted.items() if k != "requests"}
        (args.to / b.name).write_text(json.dumps(meta, indent=1) + "\n")
        rows = [json.loads(line) for line in (args.out / f"results-{batch_id}.jsonl").read_text().splitlines()]
        with (args.to / f"results-{batch_id}.jsonl").open("w") as fh:
            for row in rows:
                fh.write(json.dumps(redact_row(row), sort_keys=True) + "\n")
        cost = args.out / f"cost-{batch_id}.json"
        if cost.is_file():
            (args.to / cost.name).write_text(cost.read_text())
        print(f"{batch_id}: {len(rows)} redacted rows -> {args.to}")
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
    r = sub.add_parser("redact", help="Text-free receipts for committing.")
    r.add_argument("--out", type=Path, required=True, help="Directory with the raw receipts.")
    r.add_argument("--to", type=Path, required=True, help="Directory to write the redacted ones.")
    args = ap.parse_args(argv)
    return {"submit": cmd_submit, "collect": cmd_collect, "redact": cmd_redact}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
