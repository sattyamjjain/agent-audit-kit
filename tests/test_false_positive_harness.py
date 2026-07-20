"""Guards for the benign-slice false-positive benchmark.

Asserts (1) the harness output is deterministic across two runs — the whole
benchmark rests on it — and (2) the benign predicate is pure / side-effect-free.
Fast: the determinism check runs on a tiny synthetic slice, not the full 368.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FP_DIR = REPO / "benchmarks" / "false_positive"


def _load(module: str):
    if str(FP_DIR) not in sys.path:
        sys.path.insert(0, str(FP_DIR))
    spec = importlib.util.spec_from_file_location(f"fp_{module}", FP_DIR / f"{module}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _synthetic_slice() -> list[dict]:
    return [
        {"name": "ex/remote-noauth", "registry_status": "active", "auth_mode": "none",
         "transport": "streamable-http",
         "config": {"mcpServers": {"r": {"type": "http", "url": "https://x/mcp"}}}},
        {"name": "ex/remote-auth", "registry_status": "active", "auth_mode": "static-credential",
         "transport": "streamable-http",
         "config": {"mcpServers": {"r": {"type": "http", "url": "https://y/mcp",
                                         "headers": {"Authorization": "Bearer t"}}}}},
        {"name": "ex/stdio", "registry_status": "active", "auth_mode": "local-stdio",
         "transport": "stdio",
         "config": {"mcpServers": {"s": {"command": "uvx", "args": ["some-pkg"]}}}},
    ]


def test_harness_output_is_deterministic_across_two_runs() -> None:
    run = _load("run")
    slice_ = _synthetic_slice()
    a = run.run_benchmark(servers=copy.deepcopy(slice_))
    b = run.run_benchmark(servers=copy.deepcopy(slice_))
    assert a == b, "false-positive harness output differs between runs"
    assert a["finding_set_digest"] == b["finding_set_digest"]
    assert a["benign_slice_n"] == 3


def test_benign_predicate_is_pure() -> None:
    corpus = _load("corpus")
    cve = corpus.cve_feed_identifiers()
    server = {"name": "ex/s", "registry_status": "active", "auth_mode": "static-credential",
              "config": {"mcpServers": {"r": {"type": "http", "url": "https://x", "headers": {}}}}}
    before = copy.deepcopy(server)
    v1 = corpus.is_benign(server, cve)
    v2 = corpus.is_benign(server, cve)
    assert v1 == v2, "is_benign is not deterministic"
    assert server == before, "is_benign mutated its input (side effect)"
    # Predicate excludes no-auth and CVE-feed servers.
    noauth = {**server, "auth_mode": "none"}
    assert corpus.is_benign(server, cve) and not corpus.is_benign(noauth, cve)


def test_benign_slice_is_stable() -> None:
    corpus = _load("corpus")
    a = [s["name"] for s in corpus.benign_slice()]
    b = [s["name"] for s in corpus.benign_slice()]
    assert a == b, "benign_slice is not stable across calls"
    assert a == sorted(a), "benign_slice is not sorted (nondeterministic order)"
    assert len(a) > 0


def test_cve_feed_identifiers_stable_and_lowercased() -> None:
    corpus = _load("corpus")
    ids = corpus.cve_feed_identifiers()
    assert ids == corpus.cve_feed_identifiers()
    assert all(x == x.lower() for x in ids)
