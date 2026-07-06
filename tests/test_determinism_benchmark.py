"""CI fence for the determinism benchmark.

`benchmarks/determinism/run.py` scans a fixed committed corpus N times with the
real engine and asserts one shared finding-set digest (0% variance). This test
runs the benchmark and fails if the engine ever becomes non-deterministic — the
reproducibility claim in `benchmarks/determinism/RESULTS.md` and the README
comparison row is thereby enforced, not just asserted in prose.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "determinism_run", _ROOT / "benchmarks" / "determinism" / "run.py"
)
assert _SPEC and _SPEC.loader
determinism_run = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(determinism_run)


def test_twenty_runs_one_digest() -> None:
    data = determinism_run.run_benchmark(runs=20)
    assert data["corpus_size"] > 0, "corpus must be non-empty"
    assert data["distinct_digests"] == 1, (
        f"engine is non-deterministic: {data['distinct_digests']} distinct "
        f"finding-set digests across {data['runs']} runs"
    )
    assert data["digest"], "a single shared SHA-256 digest must be produced"


def test_digest_is_stable_across_independent_invocations() -> None:
    """Two independent benchmark invocations must agree (cross-process-ish)."""
    a = determinism_run.run_benchmark(runs=3)
    b = determinism_run.run_benchmark(runs=3)
    assert a["digest"] == b["digest"], "digest drifted between invocations"
