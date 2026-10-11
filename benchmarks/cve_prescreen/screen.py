"""Screen one record: noise filter, classification, extraction check.

`screen()` is what a nightly job would call per open issue, and what the
backtest calls per ground-truth record. The `call` argument is the model
invocation (`runner.run_claude` by default), injectable so the whole flow is
tested offline with canned CLI output.

The candidate combines the two stages in the order a cheap filter should run:
if the noise filter says the record is not agent tooling at all, the candidate
is out-of-scope with `is_noise` set, and the classification is reported beside
it rather than overriding it. Otherwise the classification is the candidate.
Either way it is a candidate: nothing here acts on it.
"""

from __future__ import annotations

from typing import Any, Callable

from benchmarks.cve_prescreen import prompts
from benchmarks.cve_prescreen.context import context_digest
from benchmarks.cve_prescreen.runner import CallResult, run_claude
from benchmarks.cve_prescreen.verify import verify_affected

DEFAULT_NOISE_MODEL = "haiku"
DEFAULT_CLASSIFY_MODEL = "sonnet"

Call = Callable[..., CallResult]


def _stage(
    call: Call, message: str, model: str, system: str, schema: dict[str, Any]
) -> dict[str, Any]:
    result = call(message, model=model, system_prompt=system, schema_json=prompts.schema_json(schema))
    out = result.to_json()
    errors = prompts.validate(schema, result.structured) if result.structured is not None else []
    out["schema_errors"] = errors
    # Scorable only when it answered, as the requested model, in shape.
    out["scorable"] = bool(result.ok and not result.refusal and not result.model_mismatch and not errors)
    return out


def candidate(noise: dict[str, Any] | None, classification: dict[str, Any] | None) -> dict[str, Any]:
    """The combined candidate, with which stage decided it."""
    if noise and noise.get("scorable") and (noise.get("structured") or {}).get("is_noise"):
        return {
            "disposition": "out-of-scope",
            "is_noise": True,
            "decided_by": "noise-filter",
            "rationale": (noise.get("structured") or {}).get("rationale", ""),
        }
    if classification and classification.get("scorable"):
        data = classification.get("structured") or {}
        return {
            "disposition": data.get("disposition"),
            "is_noise": bool(data.get("is_noise")),
            "decided_by": "classifier",
            "rationale": data.get("rationale", ""),
        }
    return {"disposition": None, "is_noise": None, "decided_by": "none", "rationale": ""}


def screen(
    context: dict[str, Any],
    *,
    call: Call = run_claude,
    noise_model: str = DEFAULT_NOISE_MODEL,
    classify_model: str = DEFAULT_CLASSIFY_MODEL,
    stages: tuple[str, ...] = ("noise", "classify"),
) -> dict[str, Any]:
    message = prompts.user_message(context)
    out: dict[str, Any] = {
        "cve": context.get("cve_id"),
        "context_digest": context_digest(context),
        "prompt_version": prompts.PROMPT_VERSION,
        "noise": None,
        "classification": None,
        "extraction": None,
    }
    if "noise" in stages:
        out["noise"] = _stage(call, message, noise_model, prompts.NOISE_SYSTEM, prompts.NOISE_SCHEMA)
    if "classify" in stages:
        stage = _stage(call, message, classify_model, prompts.CLASSIFY_SYSTEM, prompts.CLASSIFY_SCHEMA)
        out["classification"] = stage
        if stage.get("structured") is not None:
            out["extraction"] = verify_affected(context, (stage["structured"] or {}).get("affected"))
    out["candidate"] = candidate(out["noise"], out["classification"])
    return out
