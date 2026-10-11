"""Message Batches with receipts: every request and every raw result archived.

A published number an LLM touched has to be auditable. Each run writes:

- ``<out>/batch-<id>.json``: what was submitted (model, params hash, prompt
  hash, the full request list, timestamps, AAK commit, input-file hashes);
- ``<out>/results-<id>.jsonl``: every raw result exactly as the API returned
  it, keyed by ``custom_id`` (results arrive in any order).

The key is read from ``ANTHROPIC_API_KEY`` only, and nothing here prints it.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# Batch prices are half of list (platform.claude.com pricing, read 2026-10-10;
# re-checked against the claude-api skill's model table on 2026-10-12).
LIST_PRICE_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-opus-5-5": (4.00, 20.00),
    "claude-fable-5-1": (10.00, 50.00),
}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_commit(repo: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def client() -> Any:
    """An SDK client; imported here so scoring works without the SDK installed."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set")
    import anthropic

    # Retries on 429/5xx are the SDK's; keep its default.
    return anthropic.Anthropic()


def submit(cl: Any, requests: list[dict[str, Any]], meta: dict[str, Any],
           out: Path) -> str:
    out.mkdir(parents=True, exist_ok=True)
    batch = cl.messages.batches.create(requests=requests)  # type: ignore[arg-type]
    record = {
        "batch_id": batch.id,
        "created_at": str(batch.created_at),
        "request_count": len(requests),
        "requests_sha256": sha256_text(json.dumps(requests, sort_keys=True)),
        "meta": meta,
        "requests": requests,
    }
    (out / f"batch-{batch.id}.json").write_text(json.dumps(record, indent=1) + "\n")
    print(f"submitted {batch.id}: {len(requests)} requests", flush=True)
    return batch.id


def wait(cl: Any, batch_id: str, poll_seconds: int = 30) -> Any:
    while True:
        batch = cl.messages.batches.retrieve(batch_id)
        counts = batch.request_counts
        print(f"{batch_id}: {batch.processing_status} processing={counts.processing} "
              f"succeeded={counts.succeeded} errored={counts.errored} expired={counts.expired}",
              flush=True)
        if batch.processing_status == "ended":
            return batch
        time.sleep(poll_seconds)


def fetch(cl: Any, batch_id: str, out: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in cl.messages.batches.results(batch_id):
        result = item.result
        row: dict[str, Any] = {"custom_id": item.custom_id, "type": result.type}
        if result.type == "succeeded":
            row["message"] = result.message.to_dict()
        elif result.type == "errored":
            row["error"] = result.error.to_dict() if hasattr(result.error, "to_dict") else str(result.error)
        rows.append(row)
    rows.sort(key=lambda r: r["custom_id"])
    with (out / f"results-{batch_id}.jsonl").open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return rows


def batch_cost(rows: list[dict[str, Any]], model: str) -> dict[str, float]:
    """Dollar cost of a batch's succeeded rows, at half the list price."""
    p_in, p_out = LIST_PRICE_PER_MTOK[model]
    tin = tout = cache_w = cache_r = 0
    for row in rows:
        usage = (row.get("message") or {}).get("usage") or {}
        tin += usage.get("input_tokens") or 0
        tout += usage.get("output_tokens") or 0
        cache_w += usage.get("cache_creation_input_tokens") or 0
        cache_r += usage.get("cache_read_input_tokens") or 0
    usd = (tin * p_in + tout * p_out + cache_w * p_in * 1.25 + cache_r * p_in * 0.1) / 1e6 / 2
    return {"input_tokens": tin, "output_tokens": tout, "cache_write_tokens": cache_w,
            "cache_read_tokens": cache_r, "usd_batch": round(usd, 4)}
