"""Guards for the AAK-MCP-001 measurement in ``benchmarks/aak_mcp_001/``.

The measurement asks how much of the State of MCP report's headline (1,213 of
2,303 configs carry a critical finding, 1,201 of them through AAK-MCP-001)
rests on hits that are not unauthenticated servers at all. These tests hold
the parts that make its numbers trustworthy:

* the hits are the rule's, finding for finding (``measure.scan_corpus`` checks
  every config's re-derived hits against the engine's evidence strings);
* the probe can only send what its contract allows: no credential, no private
  address, two request kinds, one retry, the concurrency and pacing limits;
* nothing written for a labeler or committed carries a secret or a URL that
  should not be there, proven by planting secrets and searching for them;
* the stratified sample is reproducible from the committed frame and the sheet
  is blind;
* the PPI estimator is unbiased and covers at its nominal rate on synthetic
  data with known truth.

Every test is offline. The autouse fixture makes DNS and socket connects raise,
so a regression that sends a request fails here instead of quietly reaching a
third-party server from CI. The one corpus-backed test skips without the
gitignored ``benchmarks/data`` crawl, like the other corpus-backed tests.
"""

from __future__ import annotations

import importlib.util
import json
import random
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import urlsplit

import pytest

REPO = Path(__file__).resolve().parent.parent
M001 = REPO / "benchmarks" / "aak_mcp_001"


def _load(name: str) -> ModuleType:
    """Load a measurement module under the key the modules use for each other."""
    key = f"aak_mcp_001_{name}"
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, M001 / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("an offline test touched the network")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


def _secret(prefix: str, body: str) -> str:
    """A fake credential assembled at runtime, so this file's text holds no
    literal that a secret scanner (AAK's own self-scan included) would match."""
    return prefix + body


# ---------------------------------------------------------------------------
# endpoints.py: host classes, credentials in URLs, RFC 9728 helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url, host_class",
    [
        ("https://mcp.figma.com/mcp", "public"),
        ("https://8.8.8.8/mcp", "public"),
        ("http://localhost:3000/mcp", "loopback"),
        ("http://127.0.0.1:8080/sse", "loopback"),
        ("http://127.1:8080/", "loopback"),  # inet_aton shorthand getaddrinfo still resolves
        ("http://[::1]:9000/mcp", "loopback"),
        ("http://0.0.0.0:8000/mcp", "loopback"),
        ("http://[::ffff:127.0.0.1]/", "loopback"),
        ("http://localhost:${PORT:-8080}/mcp", "loopback"),  # a colon inside the variable
        ("http://10.1.2.3/mcp", "private"),
        ("http://172.16.0.9/mcp", "private"),
        ("https://192.168.0.152/mcp", "private"),
        ("https://100.64.1.1/mcp", "private"),  # CGNAT
        ("http://169.254.169.254/latest", "private"),  # link-local metadata service
        ("http://[fc00::1]/mcp", "private"),  # unique-local
        ("http://host.docker.internal:8000/mcp", "private"),
        ("http://mcp-server:8080/mcp", "private"),  # single-label container name
        ("http://printer.local/mcp", "private"),
        ("https://your-domain.com/mcp", "placeholder"),
        ("http://YOUR_API_URL/mcp", "placeholder"),
        ("https://mcp.example.com/mcp", "placeholder"),
        ("https://api.foo.test/mcp", "placeholder"),
        ("https://${HOST}/mcp", "template"),
        ("https://{tenant}.example-saas.io/mcp", "template"),
        ("${MCP_URL}", "template"),
        ("not a url", "invalid"),
        ("ftp://files.example-real.org/x", "invalid"),
    ],
)
def test_host_class(url: str, host_class: str) -> None:
    assert _load("endpoints").classify_url(url)["host_class"] == host_class


@pytest.mark.parametrize(
    "addr, public",
    [
        ("8.8.8.8", True),
        ("2606:4700::1111", True),
        ("::ffff:8.8.8.8", True),
        ("100.64.0.1", False),
        ("192.0.2.1", False),
        ("198.18.0.1", False),
        ("224.0.0.1", False),
        ("240.0.0.1", False),
        ("0.0.0.0", False),
        ("::ffff:10.0.0.1", False),
        ("2002:c0a8:101::", False),  # 6to4 wrapping 192.168.1.1
        ("64:ff9b::a00:1", False),  # NAT64 wrapping 10.0.0.1
        ("fe80::1", False),
        ("fc00::1", False),
        ("ff02::1", False),
    ],
)
def test_is_public_ip(addr: str, public: bool) -> None:
    import ipaddress

    assert _load("endpoints").is_public_ip(ipaddress.ip_address(addr)) is public


@pytest.mark.parametrize(
    "url, status, where",
    [
        ("https://mcp.example-real.com/mcp", "none", []),
        ("https://mcp.example-real.com/mcp?transport=sse&profile=work", "none", []),
        ("https://a.example-real.com/sk-learn-mcp/x", "none", []),  # a slug, not a key
        ("https://a.example-real.com/model-context-protocol-server-for-issues/mcp", "none", []),
        ("https://user:pw@mcp.example-real.com/", "literal", ["userinfo"]),
        ("https://${USER}:${PASS}@mcp.example-real.com/", "template", ["userinfo"]),
        ("https://mcp.example-real.com/mcp?api_key={api_key}", "template", ["query"]),
        ("https://mcp.example-real.com/mcp?apiKey=", "template", ["query"]),
        ("https://mcp.example-real.com/mcp?customerId=3fa85f64-5717-4562-b3fc-2c963f66afa6",
         "literal", ["query"]),
        ("https://mcp.example-real.com/x/3fa85f64-5717-4562-b3fc-2c963f66afa6/sse", "literal", ["path"]),
        ("https://mcp.example-real.com/mcp/{api_key}/sse", "template", ["path"]),
    ],
)
def test_url_credential(url: str, status: str, where: list[str]) -> None:
    got = _load("endpoints").url_credential(url)
    assert (got["status"], got["where"]) == (status, where)


def test_url_credential_catches_planted_token_shapes() -> None:
    ep = _load("endpoints")
    tokens = [
        _secret("sk-", "proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv"),
        _secret("gh", "p_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zA0bC"),
        _secret("eyJ", "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVl"),
        _secret("xo", "xb-1234567890-abcdefghij"),
        "Zk3QmT8vWx2LpR7nYc4H",  # mixed-case base62, no prefix
        "9f86d081884c7d659a2feaa0c55ad015",  # long hex
    ]
    for tok in tokens:
        for url in (f"https://h.example-real.com/mcp/{tok}/sse",
                    f"https://h.example-real.com/mcp?x={tok}",
                    f"https://h.example-real.com/mcp?token={tok}"):
            assert ep.url_credential(url)["status"] == "literal", url
            assert tok not in ep.redact_url(url), url


def test_query_is_plain() -> None:
    ep = _load("endpoints")
    assert ep.query_is_plain("https://h.example-real.com/mcp?transport=sse&v=2")
    assert not ep.query_is_plain("https://h.example-real.com/mcp?state=a%20b%20c%20d%20e%20f%20g%20h%20i")
    assert not ep.query_is_plain("https://h.example-real.com/mcp?session=abc")
    assert not ep.query_is_plain("https://h.example-real.com/" + "a" * 64)


def test_prm_urls_follow_rfc9728_section_3_1() -> None:
    ep = _load("endpoints")
    # RFC 9728 section 3.1's own example.
    assert ep.prm_urls("https://resource.example.com/resource1") == [
        "https://resource.example.com/.well-known/oauth-protected-resource/resource1",
        "https://resource.example.com/.well-known/oauth-protected-resource",
    ]
    assert ep.prm_urls("https://h.example.com") == ["https://h.example.com/.well-known/oauth-protected-resource"]
    assert ep.prm_urls("https://h.example.com/") == ["https://h.example.com/.well-known/oauth-protected-resource"]
    assert ep.prm_urls("https://H.Example.com:8443/a/b?x=1")[0] == (
        "https://h.example.com:8443/.well-known/oauth-protected-resource/a/b?x=1"
    )
    assert ep.prm_urls("https://h.example.com:443/mcp")[0].startswith("https://h.example.com/.well-known/")


def test_parse_www_authenticate() -> None:
    ep = _load("endpoints")
    # RFC 9728 section 5.1's example challenge.
    got = ep.parse_www_authenticate(
        'Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"'
    )
    assert got == [{"scheme": "Bearer", "params": {
        "resource_metadata": "https://resource.example.com/.well-known/oauth-protected-resource"}}]
    assert ep.resource_metadata_url(got) == "https://resource.example.com/.well-known/oauth-protected-resource"
    two = ep.parse_www_authenticate('Bearer realm="mcp", error="invalid_token", Basic realm="x"')
    assert [c["scheme"] for c in two] == ["Bearer", "Basic"]
    assert two[0]["params"] == {"realm": "mcp", "error": "invalid_token"}
    assert ep.parse_www_authenticate('Bearer error_description="say \\"hi\\""')[0]["params"] == {
        "error_description": 'say "hi"'}
    for junk in ("", "=", ",,,", '="', "Bearer =", "a=b=c, ,=,"):
        ep.parse_www_authenticate(junk)  # tolerant: never raises, always terminates


def test_parse_www_authenticate_is_linear_on_a_crafted_header() -> None:
    ep = _load("endpoints")
    crafted = 'Bearer ' + ', '.join(f'p{i}="{"x" * 50}\\"' for i in range(80))
    start = time.monotonic()
    for _ in range(20):
        ep.parse_www_authenticate(crafted * 4)
    assert time.monotonic() - start < 2.0


# ---------------------------------------------------------------------------
# Redaction, proven by planting secrets and searching for them
# ---------------------------------------------------------------------------


def _planted() -> dict[str, str]:
    return {
        "openai": _secret("sk-", "proj-Q9w8E7r6T5y4U3i2O1p0AsDfGhJk"),
        "github": _secret("github_", "pat_" + "11ABCDEFG0" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5"),
        "anthropic": _secret("sk-ant-", "api03-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0"),
        "jwt": _secret("eyJ", "hbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.ZmFrZXNpZ25hdHVyZTEyMw"),
        "aws": _secret("AKIA", "ABCDEFGHIJKLMNOP"),
        "uuid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "base62": "Tq7Xz2Kp9Lm4Nv8Bc1Rw",
        "password": "hunter2-but-longer",
    }


def _planted_corpus(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    """A tiny corpus whose AAK-MCP-001 hits carry every planted secret, in every
    place a real config hides one: userinfo, query, path, an unrecognized auth
    header, env, and registry free text."""
    s = _planted()
    corpus = tmp_path / "data"
    corpus.mkdir()
    configs = {
        "0001_owner_repo.mcp.json": {"mcpServers": {
            "userinfo": {"type": "http", "url": f"https://admin:{s['password']}@mcp.example-real.com/mcp"},
            "query": {"type": "http", "url": f"https://mcp.example-real.com/mcp?api_key={s['openai']}&x=1"},
            "path": {"type": "sse", "url": f"https://mcp.example-real.com/{s['github']}/sse"},
            "jwt": {"url": f"https://jwt.example-real.com/mcp?state={s['jwt']}"},
            "header": {"type": "http", "url": "https://hdr.example-real.com/mcp",
                       "headers": {"token": s["anthropic"]}},
            "env": {"type": "http", "url": "https://env.example-real.com/mcp",
                    "env": {"API_KEY": s["aws"]}},
            "cap": {"type": "http", "url": f"https://cap.example-real.com/s/{s['uuid']}/mcp"},
            "b62": {"type": "http", "url": f"https://b62.example-real.com/mcp/{s['base62']}"},
            # Loopback is exempt from the rule (report v1.1), a private host is not.
            "local": {"type": "http", "url": "http://localhost:3000/mcp"},
            "lan": {"type": "http", "url": "http://192.168.1.20:3000/mcp"},
            "ok": {"type": "http", "url": "https://ok.example-real.com/mcp",
                   "headers": {"Authorization": "Bearer ${TOKEN}"}},
        }},
    }
    for name, cfg in configs.items():
        (corpus / name).write_text(json.dumps(cfg), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"servers": [{
        "name": "io.example-real/leaky",
        "version": "1.0.0",
        "auth_mode": "none",
        "transport": "streamable-http",
        "registry_status": "active",
        "source_url": f"https://leaky.example-real.com/mcp?key={s['base62']}",
        "config": {"mcpServers": {"leaky": {"type": "http",
                                            "url": f"https://leaky.example-real.com/mcp/{s['openai']}"}}},
    }]}), encoding="utf-8")
    return corpus, manifest, s


def _registry_cache(tmp_path: Path, s: dict[str, str]) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "page-000.json").write_text(json.dumps({"servers": [{"server": {
        "name": "io.example-real/leaky",
        "version": "1.0.0",
        "title": f"Leaky {s['aws']}",
        "description": f"Paste Bearer {s['openai']} into the client, or {s['jwt']}.",
        "websiteUrl": f"https://leaky.example-real.com/?token={s['base62']}",
        "remotes": [{"type": "streamable-http",
                     "url": f"https://leaky.example-real.com/mcp/{s['openai']}",
                     "headers": [{"name": "X-Leak", "isSecret": True, "value": s["anthropic"],
                                  "description": f"for example {s['github']}"}]}],
    }, "_meta": {}}]}), encoding="utf-8")
    return cache


def test_population_redacts_every_planted_secret(tmp_path: Path) -> None:
    measure = _load("measure")
    ep = _load("endpoints")
    corpus, manifest, s = _planted_corpus(tmp_path)
    cache = _registry_cache(tmp_path, s)
    configs = measure.scan_corpus(corpus, manifest)
    hits = [h for c in configs for h in c["hits"]]
    assert {h["server_name"] for h in hits} >= {"userinfo", "query", "path", "jwt", "header", "env",
                                                "cap", "b62", "lan", "leaky"}
    assert "ok" not in {h["server_name"] for h in hits}  # a recognized header is not a hit
    assert "local" not in {h["server_name"] for h in hits}  # nor is a loopback host

    records = measure.population_records(configs, manifest, cache)
    blob = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
    for name, value in s.items():
        assert value not in blob, f"planted {name} secret survived redaction"
    assert ep.leak_report(blob) == []
    # ...and the checker is not vacuous: it finds them in the raw inputs.
    raw = "".join(p.read_text() for p in corpus.iterdir()) + (cache / "page-000.json").read_text()
    found = set(ep.leak_report(raw))
    assert {"openai-key", "github-token", "jwt", "aws-access-key", "url-userinfo",
            "url-uuid-capability", "url-credential-param"} <= found

    out = tmp_path / "population.jsonl"
    assert measure.write_population(records, out) == len(records)
    assert out.read_text() == blob


def test_write_population_refuses_a_leak(tmp_path: Path) -> None:
    measure = _load("measure")
    leaky = [{"hit_id": "x", "url": "https://h.example-real.com/?token=" + _secret("gh", "p_" + "A1" * 18)}]
    with pytest.raises(measure.MeasurementError):
        measure.write_population(leaky, tmp_path / "p.jsonl")
    assert not (tmp_path / "p.jsonl").exists()


def test_population_features(tmp_path: Path) -> None:
    measure = _load("measure")
    corpus, manifest, _ = _planted_corpus(tmp_path)
    configs = measure.scan_corpus(corpus, manifest)
    by_name = {h["server_name"]: h for c in configs for h in c["hits"]}
    assert "local" not in by_name
    assert by_name["lan"]["host_class"] == "private"
    assert by_name["header"]["header_auth"] == "unrecognized-name"
    assert by_name["userinfo"]["url_credential"] == "literal"
    assert by_name["path"]["transport"] == "sse"
    assert measure.probe_candidate(by_name["lan"]) == "non-public host"
    assert measure.probe_candidate(by_name["query"]) == "credential in URL"
    assert measure.probe_candidate(by_name["env"]) is None  # env is not part of the URL


def test_hits_follow_the_rule_on_loopback_and_vscode_maps(tmp_path: Path) -> None:
    """`hits_for` is the rule's predicate, so it moves when the rule does.

    A loopback host is not a hit, and a server in VS Code's `servers` map is
    read like one in `mcpServers`. `scan_corpus` agrees with the engine on the
    same file, so the population is still the rule's.
    """
    measure = _load("measure")
    text = json.dumps({"servers": {
        "remote": {"type": "http", "url": "https://r.example-real.com/mcp"},
        "loop": {"type": "http", "url": "http://127.0.0.2:8080/mcp"},
    }})
    assert [name for name, _, _ in measure.hits_for(text)] == ["remote"]
    corpus = tmp_path / "data"
    corpus.mkdir()
    (corpus / "0001_owner_repo.mcp.json").write_text(text, encoding="utf-8")
    configs = measure.scan_corpus(corpus, None)
    assert [h["server_name"] for c in configs for h in c["hits"]] == ["remote"]


def test_results_json_reproduces_from_the_corpus() -> None:
    """The committed aggregate equals a fresh offline run. Skips without the
    gitignored crawl, like every corpus-backed test (``AAK_MCP001_CORPUS`` points a
    worktree at another checkout's). It also re-asserts the report's figures:
    a run that disagreed with research/state-of-mcp-2026/results.json would
    carry ``equal: false`` and fail the comparison below."""
    measure = _load("measure")
    corpus = measure.default_corpus()
    if not corpus.is_dir() or not any(corpus.glob("*.json")):
        pytest.skip("benchmarks/data not present in this checkout")
    fresh = measure.build_results(corpus, measure.DEFAULT_MANIFEST)
    assert fresh == json.loads((M001 / "results.json").read_text())
    assert all(v["equal"] for v in fresh["step0"]["published_check"].values())


def test_evidence_classes_and_the_joined_headline() -> None:
    """Each hit gets exactly one evidence class from what was observed, and the
    joined scenarios count configs the way Step 0's do."""
    measure = _load("measure")
    base = {"scheme": "https", "url_credential": "none", "url_has_template": False}

    def hit(url: str, host_class: str = "public", **kw: Any) -> dict[str, Any]:
        return {**base, "url": url, "host": url.split("/")[2], "host_class": host_class, **kw}

    def probed(outcome: str) -> dict[str, Any]:
        return {"status": "probed", "initialize": {"outcome": outcome}}

    probe = {
        "https://a.example-real.com/mcp": probed("auth-required"),
        "https://b.example-real.com/mcp": probed("accepted"),
        "https://c.example-real.com/mcp": probed("payment-required"),
        "https://d.example-real.com/mcp": probed("error: timeout"),
        "https://e.example-real.com/mcp": probed("not-found"),
        "https://f.example-real.com/mcp": {"status": "skipped", "skip_reason": "dns dns-error"},
        "https://g.example-real.com/mcp": {"status": "skipped", "skip_reason": "dns non-public"},
    }
    cases = {
        "https://a.example-real.com/mcp": "refused: HTTP 401/403",
        "https://b.example-real.com/mcp": "accepted unauthenticated initialize",
        "https://c.example-real.com/mcp": "refused: HTTP 402",
        "https://d.example-real.com/mcp": "no HTTP answer (timeout or TLS)",
        "https://e.example-real.com/mcp": "other HTTP answer",
        "https://f.example-real.com/mcp": "no DNS answer",
        "https://g.example-real.com/mcp": "non-public host",
        "https://h.example-real.com/mcp": "not in probe log",
    }
    for url, want in cases.items():
        assert measure.evidence_class(hit(url), probe) == want, url
    assert measure.evidence_class(hit("http://localhost/mcp", "loopback", scheme="http"), probe) == "non-public host"
    assert measure.evidence_class(hit("https://${H}/mcp", "template"), probe) == "unresolvable host"
    assert measure.evidence_class(hit("https://i.example-real.com/mcp?api_key=x", url_credential="literal"),
                                  probe) == "not probed: credential or template in URL"
    assert set(cases.values()) <= set(measure.EVIDENCE_CLASSES)

    configs = [
        {"source": "registry", "critical_rules": ["AAK-MCP-001"], "hits": [hit("https://a.example-real.com/mcp")]},
        {"source": "registry", "critical_rules": ["AAK-MCP-001"], "hits": [hit("https://b.example-real.com/mcp")]},
        {"source": "crawl", "critical_rules": ["AAK-MCP-001", "AAK-MCP-002"],
         "hits": [hit("https://a.example-real.com/mcp")]},
        {"source": "crawl", "critical_rules": [], "hits": []},
    ]
    joined = measure.probe_headline(configs, probe, ["2026-10-11"])
    got = {r["scenario"]: r["configs_with_critical"]["n"] for r in joined["scenarios"]}
    assert got == {"as-published": 3, "refused-exempt": 2, "refused-and-non-public-exempt": 2,
                   "only-accepted-count": 2}
    assert joined["hits_by_evidence"]["refused: HTTP 401/403"]["n"] == 2
    assert sum(v["n"] for v in joined["hits_by_evidence"].values()) == joined["hits"] == 3


def test_inside_repo_guard() -> None:
    measure = _load("measure")
    assert measure._inside_repo(REPO / "benchmarks" / "aak_mcp_001" / "population.jsonl")
    assert not measure._inside_repo(Path("/tmp") / "population.jsonl")


# ---------------------------------------------------------------------------
# measure.py: Step 0 arithmetic
# ---------------------------------------------------------------------------


def _cfg(crit: list[str], hits: list[tuple[str, str]]) -> dict[str, Any]:
    return {"critical_rules": crit, "rule_ids": crit,
            "hits": [{"host_class": hc, "scheme": sc} for hc, sc in hits]}


def test_scenarios_on_a_known_table() -> None:
    measure = _load("measure")
    configs = [
        _cfg(["AAK-MCP-001"], [("public", "https")]),
        _cfg(["AAK-MCP-001"], [("loopback", "http")]),
        _cfg(["AAK-MCP-001"], [("private", "http")]),
        _cfg(["AAK-MCP-001"], [("template", "none")]),
        _cfg(["AAK-MCP-001", "AAK-MCP-002"], [("public", "https")]),
        _cfg(["AAK-MCP-002"], []),
        _cfg([], []),
        _cfg([], []),
    ]
    rows = {r["scenario"]: r["configs_with_critical"]["n"] for r in measure.scenario_table(configs)}
    assert rows == {
        "as-published": 6,
        "every-hit-wrong": 2,
        "loopback-exempt": 5,
        "loopback-and-private-exempt": 4,
        "https-downgraded": 5,  # http loopback, http private, template, and the two other-critical
        "loopback-exempt-and-https-downgraded": 4,
    }
    s0 = measure.step0(configs, None)
    assert s0["configs_with_a_critical_other_than_aak_mcp_001"]["n"] == 2
    assert s0["configs_with_critical_but_no_aak_mcp_001"] == 1
    assert s0["aak_mcp_001"]["configs"]["n"] == 5


# ---------------------------------------------------------------------------
# probe.py: what may be sent, and how
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url, reason",
    [
        ("https://mcp.example-real.com/mcp", None),
        ("https://mcp.example-real.com/mcp?transport=sse", None),
        ("http://mcp.example-real.com/mcp", "not https"),
        ("https://localhost/mcp", "non-public host"),
        ("https://10.0.0.1/mcp", "non-public host"),
        ("https://u:p@mcp.example-real.com/mcp", "credential in URL"),
        ("https://mcp.example-real.com/mcp?api_key=abc", "credential in URL"),
        ("https://mcp.example-real.com/mcp?state=a%20long%20free%20text%20value%20here", "credential in URL (suspected)"),
        ("https://mcp.example.com/mcp", "placeholder host"),
        ("https://${HOST}/mcp", "template host"),
        ("https://mcp.example-real.com:99999/mcp", "invalid URL"),
    ],
)
def test_send_gate(url: str, reason: str | None) -> None:
    assert _load("probe").send_gate(url) == reason


def test_requests_carry_no_credential_and_identify_themselves() -> None:
    probe = _load("probe")
    ua = "agent-audit-kit-research (+https://github.com/sattyamjjain/agent-audit-kit)"
    init = probe.request_headers("initialize")
    assert init == {"User-Agent": ua, "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json", "Connection": "close"}
    assert probe.request_headers("prm-root") == {"User-Agent": ua, "Accept": "application/json",
                                                 "Connection": "close"}
    body = json.loads(probe.initialize_body())
    assert body["method"] == "initialize" and body["id"] == 1 and body["jsonrpc"] == "2.0"
    assert body["params"]["protocolVersion"] == probe.PROTOCOL_VERSION
    assert set(body["params"]) == {"protocolVersion", "capabilities", "clientInfo"}
    assert (probe.TIMEOUT_S, probe.MAX_CONNECTIONS, probe.PER_HOST_INTERVAL_S, probe.MAX_RETRIES) == (
        10.0, 4, 1.0, 1)


def _gai(table: dict[str, list[str]]) -> Any:
    def fake(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:  # noqa: A002
        if host not in table:
            raise socket.gaierror("NXDOMAIN")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
                for a in table[host]]
    return fake


def test_resolver_vets_every_address_and_prefers_ipv4() -> None:
    probe = _load("probe")
    log: list[dict[str, Any]] = []
    r = probe.Resolver(getaddrinfo=_gai({
        "pub.example-real.com": ["2606:4700::1111", "93.184.216.34"],
        "mixed.example-real.com": ["93.184.216.34", "10.0.0.7"],
        "rebind.example-real.com": ["127.0.0.1"],
    }), log=log.append)
    assert r.resolve("pub.example-real.com", 443) == {
        "status": "ok", "ip": "93.184.216.34", "addresses": ["2606:4700::1111", "93.184.216.34"]}
    assert r.resolve("mixed.example-real.com", 443)["status"] == "non-public"
    assert r.resolve("rebind.example-real.com", 443)["status"] == "non-public"
    assert r.resolve("gone.example-real.com", 443)["status"] == "dns-error"
    r.resolve("pub.example-real.com", 443)  # cached: no second lookup
    assert [e["host"] for e in log] == ["pub.example-real.com", "mixed.example-real.com",
                                        "rebind.example-real.com", "gone.example-real.com"]
    assert all(e["event"] == "dns" and e["ts"].endswith("Z") for e in log)


def test_host_gate_spaces_request_starts() -> None:
    probe = _load("probe")
    now = [100.0]
    slept: list[float] = []

    def sleep(s: float) -> None:
        slept.append(s)
        now[0] += s

    gate = probe.HostGate(interval=1.0, clock=lambda: now[0], sleep=sleep)
    with gate.slot("a"):
        pass
    now[0] += 0.25
    with gate.slot("a"):
        pass
    with gate.slot("b"):
        pass
    assert slept == [pytest.approx(0.75)]


class _FakeServers:
    """Scripted answers per URL, recording what was sent and when."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, dict[str, str], bytes | None]] = []

    def __call__(self, method: str, url: str, ip: str, headers: dict[str, str],
                 body: bytes | None) -> dict[str, Any]:
        self.calls.append((method, url, ip, dict(headers), body))

        def ok(status: int, hdrs: list[tuple[str, str]], payload: bytes) -> dict[str, Any]:
            return {"ok": True, "status": status, "reason": "", "headers": hdrs, "body": payload,
                    "body_truncated": False, "headers_ms": 3, "elapsed_ms": 4}

        if "flaky" in url:
            return {"ok": False, "error": "timeout", "error_type": "TimeoutError", "elapsed_ms": 10000}
        if "tlsbad" in url:
            return {"ok": False, "error": "tls-certificate", "error_type": "SSLCertVerificationError",
                    "elapsed_ms": 50}
        if method == "POST" and urlsplit(url).hostname == "oauth.example-real.com":
            rm = "https://oauth.example-real.com/.well-known/oauth-protected-resource/mcp"
            return ok(401, [("WWW-Authenticate", f'Bearer resource_metadata="{rm}"'),
                            ("Content-Type", "application/json")], b'{"error":"invalid_token"}')
        if method == "POST" and "elsewhere" in url:
            rm = "https://auth.example-real.com/prm"
            return ok(401, [("WWW-Authenticate", f'Bearer resource_metadata="{rm}"')], b"")
        if method == "POST":
            sse = (b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":'
                   b'"2025-06-18","serverInfo":{"name":"demo","version":"1"},"capabilities":{"tools":{}}}}\n\n')
            return ok(200, [("Content-Type", "text/event-stream"), ("Mcp-Session-Id", "SESSION-VALUE")], sse)
        if "oauth.example-real.com/.well-known/oauth-protected-resource/mcp" in url or url.endswith("/prm"):
            doc = {"resource": "https://oauth.example-real.com/mcp",
                   "authorization_servers": ["https://auth.example-real.com"]}
            return ok(200, [("Content-Type", "application/json")], json.dumps(doc).encode())
        return ok(404, [("Content-Type", "text/html")], b"<html>not here</html>")


_PLAN = {"endpoints": [
    {"endpoint": "https://oauth.example-real.com/mcp", "host": "oauth.example-real.com", "hits": 2,
     "hits_by_source": {"registry": 2}},
    {"endpoint": "https://oauth.example-real.com/v2", "host": "oauth.example-real.com", "hits": 1,
     "hits_by_source": {"crawl": 1}},
    {"endpoint": "https://open.example-real.com/", "host": "open.example-real.com", "hits": 1,
     "hits_by_source": {"crawl": 1}},
    {"endpoint": "https://elsewhere.example-real.com/mcp", "host": "elsewhere.example-real.com", "hits": 1,
     "hits_by_source": {"registry": 1}},
    {"endpoint": "https://lan.example-real.com/mcp", "host": "lan.example-real.com", "hits": 1,
     "hits_by_source": {"crawl": 1}},
    {"endpoint": "https://flaky.example-real.com/mcp", "host": "flaky.example-real.com", "hits": 1,
     "hits_by_source": {"registry": 1}},
    {"endpoint": "https://tlsbad.example-real.com/mcp", "host": "tlsbad.example-real.com", "hits": 1,
     "hits_by_source": {"registry": 1}},
    {"endpoint": "https://gone.example-real.com/mcp", "host": "gone.example-real.com", "hits": 1,
     "hits_by_source": {"registry": 1}},
]}
_PUBLIC = "93.184.216.34"
_DNS = {h: [_PUBLIC] for h in ("oauth.example-real.com", "open.example-real.com", "elsewhere.example-real.com",
                               "auth.example-real.com", "flaky.example-real.com", "tlsbad.example-real.com")}
_DNS["lan.example-real.com"] = ["192.168.1.20"]


def _run(tmp_path: Path, servers: _FakeServers, gate: Any = None, workers: int = 1) -> list[dict[str, Any]]:
    probe = _load("probe")
    raw = tmp_path / "raw.jsonl"
    gate = gate or probe.HostGate(interval=0.0)
    probe.run_probe(_PLAN, raw, transport=servers, getaddrinfo=_gai(_DNS), gate=gate, workers=workers)
    return probe.read_raw(raw)


def test_prober_sends_exactly_the_two_request_kinds(tmp_path: Path) -> None:
    servers = _FakeServers()
    raw = _run(tmp_path, servers)
    sent = [(m, u) for m, u, *_ in servers.calls]
    # Only POST initialize to a planned endpoint, or GET of a well-known / named metadata URL.
    planned = {r["endpoint"] for r in _PLAN["endpoints"]}
    for method, url in sent:
        if method == "POST":
            assert url in planned
        else:
            assert method == "GET"
            assert "/.well-known/oauth-protected-resource" in url or url == "https://auth.example-real.com/prm"
    # The private-resolving and unresolvable hosts are never contacted.
    assert not any(urlsplit(u).hostname in {"lan.example-real.com", "gone.example-real.com"} for _, u in sent)
    # The root metadata is fetched once per host, however many endpoints share it.
    root = "https://oauth.example-real.com/.well-known/oauth-protected-resource"
    assert sent.count(("GET", root)) == 1
    # The resource_metadata URL equal to the path-inserted one is not fetched twice;
    # a cross-host one is fetched (it passed the same gate).
    assert sent.count(("GET", "https://oauth.example-real.com/.well-known/oauth-protected-resource/mcp")) == 1
    assert sent.count(("GET", "https://auth.example-real.com/prm")) == 1
    # One retry on a network error, none on a TLS failure, and no metadata GETs
    # to a host that never answered.
    assert sent.count(("POST", "https://flaky.example-real.com/mcp")) == 2
    assert sent.count(("POST", "https://tlsbad.example-real.com/mcp")) == 1
    assert not any(m == "GET" and ("flaky" in u or "tlsbad" in u) for m, u in sent)
    # Every request is pinned to the vetted address and carries no credential.
    for _, _, ip, headers, _ in servers.calls:
        assert ip == _PUBLIC
        assert not {k.lower() for k in headers} & {"authorization", "cookie", "mcp-session-id", "x-api-key"}
    # Every request attempt is logged with timestamps.
    reqs = [r for r in raw if r["event"] == "request"]
    assert len(reqs) == len(servers.calls)
    assert all(r["ts"].endswith("Z") and r["ts_end"].endswith("Z") for r in reqs)
    # A session id is recorded as present, never by value.
    assert "SESSION-VALUE" not in json.dumps(raw)


def test_probe_summaries(tmp_path: Path) -> None:
    probe = _load("probe")
    raw = _run(tmp_path, _FakeServers())
    per = probe.summarize_by_endpoint(raw)
    assert per["https://oauth.example-real.com/mcp"]["initialize"]["outcome"] == "auth-required"
    assert per["https://oauth.example-real.com/mcp"]["prm"]["with_authorization_servers"] is True
    assert per["https://oauth.example-real.com/v2"]["prm"]["by_variant"]["root"]["http_status"] == 404
    assert per["https://open.example-real.com/"]["initialize"]["outcome"] == "accepted"
    assert per["https://elsewhere.example-real.com/mcp"]["prm"]["served"] is True
    assert per["https://lan.example-real.com/mcp"]["skip_reason"] == "dns non-public"
    assert per["https://gone.example-real.com/mcp"]["skip_reason"] == "dns dns-error"
    assert per["https://flaky.example-real.com/mcp"]["initialize"]["outcome"] == "error: timeout"
    summary = probe.build_summary(raw)
    blob = json.dumps(summary)
    assert "://" not in blob.replace(probe.USER_AGENT, "")
    assert summary["planned_endpoints"] == len(_PLAN["endpoints"])
    assert summary["planned_hits"] == 9
    assert summary["initialize_outcome_hits"]["auth-required"] == 4
    assert summary["retried_requests"] == 1


class _GrantClock:
    """The gate's clock, remembering each thread's last reading on the
    monotonic clock the gate uses and on the wall clock the log uses. The gate
    reads its clock last when it grants a slot, so a transport call made inside
    the slot sees the grant it runs under."""

    def __init__(self) -> None:
        self._local = threading.local()

    def __call__(self) -> float:
        self._local.wall = time.time()
        self._local.at = time.monotonic()
        return float(self._local.at)

    def last(self) -> tuple[float, float]:
        return self._local.at, self._local.wall


def test_probe_respects_concurrency_and_pacing(tmp_path: Path) -> None:
    """At most four requests in flight, one per host, and starts to one host
    spaced by the gate's interval.

    The spacing is read through the gate's own clock. Timing the transport
    calls measured something the gate does not promise: a worker can be
    descheduled between its grant and the call, so two calls can start closer
    together than the grants behind them (a loaded machine measured 18 ms
    against a 19 ms floor). The log is held to the slots instead: each start is
    stamped after its grant and before its transport call, and the summary's
    audit reports the gaps those stamps show.
    """
    probe = _load("probe")
    lock = threading.Lock()
    in_flight: dict[str, int] = {}
    peak = {"all": 0, "host": 0}
    clock = _GrantClock()
    slots: dict[str, list[tuple[float, float, float]]] = {}

    many = {"endpoints": [
        {"endpoint": f"https://h{i % 5}.example-real.com/p{i}", "host": f"h{i % 5}.example-real.com",
         "hits": 1, "hits_by_source": {"registry": 1}} for i in range(15)
    ]}

    def transport(method: str, url: str, ip: str, headers: dict[str, str], body: bytes | None) -> dict[str, Any]:
        host = url.split("/")[2]
        granted, granted_wall = clock.last()
        entered = time.time()
        with lock:
            slots.setdefault(host, []).append((granted, granted_wall, entered))
            in_flight[host] = in_flight.get(host, 0) + 1
            peak["host"] = max(peak["host"], in_flight[host])
            peak["all"] = max(peak["all"], sum(in_flight.values()))
        time.sleep(0.01)
        with lock:
            in_flight[host] -= 1
        return {"ok": True, "status": 404, "reason": "", "headers": [], "body": b"",
                "body_truncated": False, "headers_ms": 1, "elapsed_ms": 1}

    gai = _gai({f"h{i}.example-real.com": [_PUBLIC] for i in range(5)})
    gate = probe.HostGate(interval=0.02, clock=clock)
    probe.run_probe(many, tmp_path / "raw.jsonl", transport=transport, getaddrinfo=gai, gate=gate, workers=4)
    assert peak["all"] <= 4
    assert peak["host"] == 1
    assert sorted(slots) == [f"h{i}.example-real.com" for i in range(5)]
    for host_slots in slots.values():
        grants = [granted for granted, _, _ in host_slots]
        assert len(set(grants)) == len(grants), "every request runs under a grant of its own"
        # The gate's clock, so no delay after a grant can shorten a gap; the
        # slack is float rounding, not time.
        assert min(b - a for a, b in zip(grants, grants[1:])) >= gate.interval - 1e-6

    raw = probe.read_raw(tmp_path / "raw.jsonl")
    stamps: dict[str, list[float]] = {}
    for r in raw:
        if r["event"] == "request":
            stamps.setdefault(r["host"], []).append(datetime.fromisoformat(r["ts"].replace("Z", "+00:00")).timestamp())
    assert sorted(stamps) == sorted(slots)
    for host, host_stamps in stamps.items():
        assert len(host_stamps) == len(slots[host])
        for stamp, (_, granted_wall, entered) in zip(sorted(host_stamps), slots[host]):
            # Stamped in the slot: after the grant, less the stamp's truncation
            # to milliseconds, and before the transport call.
            assert granted_wall - 0.0015 <= stamp <= entered + 1e-6
    seen = probe.build_summary(raw)["observed_limits"]
    gaps = [b - a for t in stamps.values() for a, b in zip(sorted(t), sorted(t)[1:])]
    assert seen["min_same_host_start_gap_s"] == round(min(gaps), 3)
    assert seen["peak_requests_in_flight"] <= 4
    assert seen["non_https_requests"] == 0 and seen["requests_with_userinfo"] == 0


def test_parse_jsonrpc_and_prm() -> None:
    probe = _load("probe")
    rpc = probe.parse_jsonrpc(b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25",'
                              b'"serverInfo":{"name":"s"},"capabilities":{"tools":{},"prompts":{}}}}',
                              "application/json")
    assert rpc["result"] and rpc["protocol_version"] == "2025-11-25" and rpc["capabilities"] == ["prompts", "tools"]
    err = probe.parse_jsonrpc(b'event: message\ndata: {"jsonrpc":"2.0","id":1,"error":{"code":-32001,'
                              b'"message":"Authentication required"}}\n\n', "text/event-stream")
    assert err["result"] is False and err["error_code"] == -32001
    assert probe.parse_jsonrpc(b'{"error":"invalid_token"}', "application/json") is None
    assert probe.parse_jsonrpc(b"<html>", "text/html") is None
    prm = probe.parse_prm(b'{"resource":"https://h.example-real.com/mcp","authorization_servers":'
                          b'["https://as.example-real.com"],"scopes_supported":["a","b"]}',
                          "https://h.example-real.com/mcp")
    assert prm["resource_matches_endpoint"] and prm["authorization_servers_count"] == 1
    assert prm["scopes_supported_count"] == 2
    assert probe.parse_prm(b"not json", "https://h.example-real.com/mcp") == {"json": False}


def test_probe_main_without_the_flag_sends_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    probe = _load("probe")
    measure = _load("measure")
    corpus = tmp_path / "data"
    corpus.mkdir()
    monkeypatch.setattr(measure, "scan_corpus", lambda c, m: [
        {"source": "registry", "hits": [{"host": "x.example-real.com", "host_class": "public",
                                         "scheme": "https", "url_credential": "none",
                                         "url_has_template": False, "url": "https://x.example-real.com/mcp"}]}])

    def boom(*_a: Any, **_k: Any) -> int:
        raise AssertionError("run_probe called without --probe")

    monkeypatch.setattr(probe, "run_probe", boom)
    assert probe.main(["--corpus", str(corpus)]) == 0
    # and --probe refuses a raw log inside the repository
    assert probe.main(["--corpus", str(corpus), "--probe", "--raw-out", str(M001 / "raw.jsonl")]) == 2


# ---------------------------------------------------------------------------
# sample.py: allocation, selection, blindness
# ---------------------------------------------------------------------------


def test_allocate() -> None:
    sample = _load("sample")
    sizes = {"a": 49, "b": 8, "c": 3, "d": 600, "e": 420, "f": 231}
    alloc = sample.allocate(sizes, 150, 4)
    assert sum(alloc.values()) == 150
    assert alloc["c"] == 3  # smaller than the floor: taken whole
    assert alloc["b"] == 4  # the floor
    assert all(alloc[h] >= min(sizes[h], 4) for h in sizes)
    big = {h: alloc[h] / sizes[h] for h in ("d", "e", "f")}
    assert max(big.values()) - min(big.values()) < 0.01  # proportional where no floor binds
    assert sample.allocate(sizes, 150, 4) == alloc
    with pytest.raises(ValueError):
        sample.allocate({"a": 5, "b": 5, "c": 5}, 6, 4)


def test_draw_is_seeded_and_reproducible() -> None:
    sample = _load("sample")
    frame = {"s1": [f"{i:016x}" for i in range(100)], "s2": [f"{i:016x}" for i in range(100, 130)]}
    alloc = {"s1": 10, "s2": 5}
    a = sample.draw(frame, alloc, "seed-a")
    assert a == sample.draw(frame, alloc, "seed-a")
    assert a != sample.draw(frame, alloc, "seed-b")
    assert sum(1 for r in a if r["stratum"] == "s1") == 10
    assert [r["sheet_no"] for r in a] == list(range(1, 16))
    # the sheet order is not grouped by stratum (blindness)
    assert [r["stratum"] for r in a] != sorted(r["stratum"] for r in a)


def _records(n: int) -> list[dict[str, Any]]:
    rng = random.Random(3)
    out = []
    for i in range(n):
        kind = rng.choice(["loopback", "public", "public", "public", "template"])
        status = rng.choice(["auth-required", "accepted", "not-found"])
        out.append({
            "hit_id": f"{i:016x}", "source": rng.choice(["crawl", "registry"]),
            "config_id": f"{i:04d}_owner_repo.mcp.json", "server_name": f"s{i}",
            "url": f"https://h{i}.example-real.com/mcp", "host_class": kind, "url_credential": "none",
            "header_auth": "none", "declared_type": "http", "entry_shape": {"type": "http", "url": "str"},
            "headers": [], "config_hits": 1, "registry": None,
            "probe": {"status": "probed", "initialize": {"outcome": status, "http_status": 401,
                                                          "www_authenticate": [], "ts": "2026-10-11T20:00:00Z"},
                      "prm": {"served": False, "by_variant": {}}},
        })
    return out


def test_sheet_is_blind_and_carries_the_codebook(tmp_path: Path) -> None:
    sample = _load("sample")
    records = _records(400)
    doc = sample.build_sample(records, n=150)
    assert sum(s["n"] for s in doc["strata"]) == 150
    md_path, csv_path = sample.write_sheet(doc, records, tmp_path)
    md, csv_text = md_path.read_text(), csv_path.read_text()
    assert sample.CODEBOOK in md
    for name, _ in sample.STRATA:
        assert name not in md and name not in csv_text, f"stratum {name} leaked into the sheet"
    assert "auth-required" not in csv_text and "accepted" not in csv_text  # no outcome labels
    import csv as _csv

    rows = list(_csv.DictReader(csv_path.open()))
    assert len(rows) == 150 and all(r["verdict"] == "" for r in rows)


def test_import_csv(tmp_path: Path) -> None:
    sample = _load("sample")
    records = _records(200)
    doc = sample.build_sample(records, n=150)
    _, csv_path = sample.write_sheet(doc, records, tmp_path)
    import csv as _csv

    rows = list(_csv.DictReader(csv_path.open()))
    rows[0]["verdict"], rows[0]["note"] = "hosted-oauth", "401 with a Bearer challenge"
    rows[1]["verdict"] = "truly-open"
    with csv_path.open("w", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    verdicts, n = sample.import_csv(csv_path, sample.verdicts_template(doc))
    assert n == 2
    assert [v["verdict"] for v in verdicts["verdicts"][:2]] == ["hosted-oauth", "truly-open"]
    # A re-draw must never wipe verdicts already made by hand.
    paths = {k: tmp_path / f"{k}.json" for k in ("sample", "verdicts", "codebook")}
    sample.write_artifacts(doc, paths["sample"], paths["verdicts"], paths["codebook"])
    paths["verdicts"].write_text(json.dumps(verdicts))
    with pytest.raises(ValueError):
        sample.write_artifacts(doc, paths["sample"], paths["verdicts"], paths["codebook"])
    assert json.loads(paths["verdicts"].read_text())["verdicts"][0]["verdict"] == "hosted-oauth"
    rows[2]["verdict"] = "probably-fine"
    with csv_path.open("w", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with pytest.raises(ValueError):
        sample.import_csv(csv_path, sample.verdicts_template(doc))


def test_committed_sample_reproduces_from_its_frame() -> None:
    sample = _load("sample")
    doc = json.loads((M001 / "sample.json").read_text())
    sizes = {s["stratum"]: s["N"] for s in doc["strata"]}
    assert sizes == {h: len(ids) for h, ids in doc["frame"].items()}
    alloc = sample.allocate(sizes, doc["sample_size"], doc["min_per_stratum"])
    assert {s["stratum"]: s["n"] for s in doc["strata"]} == alloc
    redrawn = sample.draw(doc["frame"], alloc, doc["seed"])
    assert redrawn == doc["sample"]
    verdicts = json.loads((M001 / "verdicts.json").read_text())
    assert [v["hit_id"] for v in verdicts["verdicts"]] == [r["hit_id"] for r in doc["sample"]]
    assert all(v["verdict"] is None or v["verdict"] in sample.LABELS for v in verdicts["verdicts"])
    assert (M001 / "CODEBOOK.md").read_text() == sample.CODEBOOK
    assert sample.LABELS == _load("ppi").LABELS


def test_committed_artifacts_carry_no_third_party_records() -> None:
    ep = _load("endpoints")
    ua = _load("probe").USER_AGENT
    for name in ("results.json", "probe-summary.json", "probe-headline.json", "sample.json", "verdicts.json"):
        text = (M001 / name).read_text()
        assert ep.leak_report(text) == [], name
        assert "://" not in text.replace(ua, ""), f"{name} carries a URL"
    doc = json.loads((M001 / "sample.json").read_text())
    ids = [i for ids in doc["frame"].values() for i in ids]
    assert all(len(i) == 16 and all(c in "0123456789abcdef" for c in i) for i in ids)


def _c(n: int) -> str:
    return f"{n:,}"


def test_results_page_states_the_committed_numbers() -> None:
    """Every table row and headline figure on RESULTS.md, rebuilt from the
    committed JSON. A re-run that moves a number turns this red until the page
    says the new one: the repo's rule that a published number has a checker."""
    page = (M001 / "RESULTS.md").read_text()
    res = json.loads((M001 / "results.json").read_text())
    probe = json.loads((M001 / "probe-summary.json").read_text())
    joined = json.loads((M001 / "probe-headline.json").read_text())
    sample_doc = json.loads((M001 / "sample.json").read_text())
    s0, s1 = res["step0"], res["step1"]
    rows: list[str] = []

    pc = s0["published_check"]
    assert all(v["equal"] for v in pc.values())
    rows += [
        f"| Distinct configs scanned | {_c(pc['distinct_configs_scanned']['published'])} | "
        f"{_c(pc['distinct_configs_scanned']['fresh'])} |",
        f"| Configs with `AAK-MCP-001` | {_c(pc['aak_mcp_001_configs']['published'])} | "
        f"{_c(pc['aak_mcp_001_configs']['fresh'])} |",
        f"| Configs with a critical finding | {_c(pc['configs_with_critical']['published'])} | "
        f"{_c(pc['configs_with_critical']['fresh'])} |",
        f"| Share with a critical finding | {pc['configs_with_critical_pct']['published']}% | "
        f"{pc['configs_with_critical_pct']['fresh']}% |",
    ]
    labels = {
        "as-published": "The rule as shipped",
        "every-hit-wrong": "Every `AAK-MCP-001` hit is a false positive",
        "loopback-exempt": "Loopback hosts exempt",
        "loopback-and-private-exempt": "Loopback and private-network hosts exempt",
        "https-downgraded": "https without a header downgraded below critical",
        "loopback-exempt-and-https-downgraded": "Loopback exempt and https downgraded",
    }
    for r in s0["scenarios"]:
        m, still = r["configs_with_critical"], r["configs_where_aak_mcp_001_stays_critical"]
        rows.append(f"| {labels[r['scenario']]} | {_c(m['n'])} | {m['pct']}% | {_c(still['n'])} |")
    joined_labels = {
        "as-published": "Nothing (as published)",
        "refused-exempt": "A hit on a server that refused the unauthenticated client",
        "refused-and-non-public-exempt": "...or on a loopback or private host",
        "only-accepted-count": "Anything but a hit on a server that accepted the unauthenticated client",
    }
    for r in joined["scenarios"]:
        m = r["configs_with_critical"]
        rows.append(f"| {joined_labels[r['scenario']]} | {_c(m['n'])} | {m['pct']}% |")
    host_labels = {
        "public/https": "public / https", "loopback/http": "loopback / http",
        "private/http": "private network / http", "template/https": "template variable / https",
        "template/none": "template variable / no scheme", "placeholder/https": "placeholder name / https",
    }
    # A subset since report v1.1, when the rule stopped reporting loopback hosts
    # and the loopback / http class went empty.
    assert set(s1["host_class_by_scheme"]) <= set(host_labels)
    rows += [f"| {host_labels[k]} | {_c(v)} |" for k, v in s1["host_class_by_scheme"].items()]
    outcome_rows = {
        "HTTP 401 or 403 (refused)": ["auth-required"],
        "JSON-RPC result (accepted)": ["accepted"],
        "No DNS answer": ["skipped: dns dns-error"],
        "Not found (404, 410)": ["not-found"],
        "Redirect, not followed": ["redirect"],
        "HTTP 402 (payment gate)": ["payment-required"],
        "Server error (5xx)": ["server-error"],
        "Timeout after one retry": ["error: timeout"],
        "Method not allowed (405)": ["method-not-allowed"],
        "TLS failure": ["error: tls-certificate", "error: tls-error"],
        "Other 4xx": ["client-error-other"],
        "Other 2xx without a JSON-RPC result": ["2xx-other"],
    }
    eps, hits = probe["initialize_outcome_endpoints"], probe["initialize_outcome_hits"]
    assert {k for ks in outcome_rows.values() for k in ks} == set(eps)
    for label, keys in outcome_rows.items():
        rows.append(f"| {label} | {_c(sum(eps.get(k, 0) for k in keys))} | "
                    f"{_c(sum(hits.get(k, 0) for k in keys))} |")
    strata_labels = {
        "nonpublic-host": "Loopback or private host",
        "unresolvable-host": "Template, placeholder or unparseable host",
        "credential-elsewhere": "Credential in the URL, or an unrecognized auth header",
        "probe-auth-required": "Public https, `initialize` refused (401/403)",
        "probe-accepted": "Public https, `initialize` accepted",
        "probe-other": "Public https, any other answer or none",
    }
    rows += [f"| {strata_labels[s['stratum']]} | {_c(s['N'])} | {_c(s['n'])} |" for s in sample_doc["strata"]]
    missing = [r for r in rows if r not in page]
    assert not missing, f"RESULTS.md disagrees with the committed JSON on: {missing}"

    ev = joined["hits_by_evidence"]
    refused = ev["refused: HTTP 401/403"]["n"] + ev["refused: HTTP 402"]["n"]
    accepted = ev["accepted unauthenticated initialize"]["n"]
    total = joined["hits"]
    prose = [
        f"{_c(total)} `AAK-MCP-001` hits",
        f"**{_c(refused)} ({100 * refused / total:.1f}%) point at a server",
        f"**{_c(accepted)} ({ev['accepted unauthenticated initialize']['pct']}%) at one that",
        f"**{_c(probe['rfc9728_metadata']['served_any_variant'])} of the "
        f"{_c(probe['rfc9728_metadata']['probed_endpoints'])} endpoints that answered DNS",
        f"({_c(probe['rfc9728_metadata_hits']['served_any_variant'])} hits) served RFC 9728",
        f"**{_c(s0['aak_mcp_001']['findings'])} hits**",
        f"**{_c(s0['configs_with_a_critical_other_than_aak_mcp_001']['n'])} configs "
        f"({s0['configs_with_a_critical_other_than_aak_mcp_001']['pct']}%) carry a",
        f"{_c(probe['requests_sent'])} requests went out",
        f"{_c(probe['observed_limits']['methods']['POST'])} `initialize` POSTs",
        f"{_c(probe['observed_limits']['methods']['GET'])} metadata GETs",
        f"between two requests to one host was {probe['observed_limits']['min_same_host_start_gap_s']} s",
        f"never more than {probe['observed_limits']['peak_requests_in_flight']} requests were",
        f"| {probe['probe']['run_dates_utc'][0]} | {_c(total)} | {_c(refused)} | {_c(accepted)} | "
        f"{sample_doc['sample_size']}, pending |",
    ]
    missing = [p for p in prose if p not in page]
    assert not missing, f"RESULTS.md prose disagrees with the committed JSON on: {missing}"
    assert "TP share" in page and "pending" in page  # no rate may be stated while verdicts are null
    verdicts = json.loads((M001 / "verdicts.json").read_text())
    if any(v["verdict"] is None for v in verdicts["verdicts"]):
        assert "## Status: Steps 2 and 3 pending" in page


# ---------------------------------------------------------------------------
# ppi.py: correctness and coverage on synthetic data with known truth
# ---------------------------------------------------------------------------


def test_ppi_iid_matches_the_closed_form() -> None:
    ppi = _load("ppi")
    y = [1.0, 0.0, 1.0, 1.0]
    f_lab = [1.0, 1.0, 1.0, 0.0]
    f_unl = [1.0, 0.0, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0]
    theta, (lo, hi) = ppi.ppi_mean_iid(y, f_lab, f_unl)
    assert theta == pytest.approx(5 / 8 - 0.0)  # mean(f_unl) - mean(f_lab - y) = 0.625 - 0
    assert lo < theta < hi


def test_stratified_ppi_identities() -> None:
    ppi = _load("ppi")
    rng = random.Random(1)
    pop = [("a", float(rng.random() < 0.3)) for _ in range(300)] + [("b", float(rng.random() < 0.7))
                                                                    for _ in range(200)]
    truth = {i: f for i, (_, f) in enumerate(pop)}
    sampled = rng.sample(range(300), 20) + rng.sample(range(300, 500), 20)
    # A perfect model: the estimate is exactly the truth.
    exact = ppi.stratified_ppi(pop, [(pop[i][0], truth[i], truth[i]) for i in sampled])
    assert exact["estimate"] == pytest.approx(sum(truth.values()) / len(pop))
    # A model that says 0 everywhere: PPI reduces to the human-only stratified estimate.
    y = {i: float(rng.random() < (0.3 if i < 300 else 0.7)) for i in sampled}
    zero = ppi.stratified_ppi([(h, 0.0) for h, _ in pop], [(pop[i][0], 0.0, y[i]) for i in sampled])
    human = ppi.stratified_proportion({"a": 300, "b": 200}, [(pop[i][0], y[i]) for i in sampled])
    assert zero["estimate"] == pytest.approx(human["estimate"])
    # A census stratum contributes no variance.
    census = ppi.stratified_ppi([("a", 0.0)] * 3 + [("b", 1.0)] * 50,
                                [("a", 0.0, 1.0)] * 3 + [("b", 1.0, 1.0)] * 5, small_sample=None)
    assert census["se"] == pytest.approx(0.0) and census["estimate"] == pytest.approx(1.0)
    with pytest.raises(ValueError):
        ppi.stratified_ppi([("a", 0.0), ("b", 0.0)], [("a", 0.0, 0.0)])  # stratum b unsampled


def _coverage(err_fp: float, err_fn: float, small_sample: str | None, reps: int, seed: int) -> dict[str, float]:
    """Monte Carlo coverage for a design shaped like the real one: six strata of
    very different sizes and true-positive rates, 150 labels, floors of 4."""
    ppi = _load("ppi")
    sample = _load("sample")
    rng = random.Random(seed)
    sizes = {"a": 49, "b": 8, "c": 31, "d": 600, "e": 420, "f": 203}
    rates = {"a": 0.0, "b": 0.1, "c": 0.1, "d": 0.02, "e": 0.5, "f": 0.2}
    alloc = sample.allocate(sizes, 150, 4)
    cover = {"ppi": 0, "human": 0}
    bias = {"ppi": 0.0, "human": 0.0}
    for _ in range(reps):
        units: dict[str, list[tuple[float, float]]] = {}
        for h, n in sizes.items():
            for _ in range(n):
                y = float(rng.random() < rates[h])
                f = (0.0 if rng.random() < err_fn else 1.0) if y else (1.0 if rng.random() < err_fp else 0.0)
                units.setdefault(h, []).append((f, y))
        truth = sum(y for us in units.values() for _, y in us) / sum(sizes.values())
        smp = [(h, f, y) for h, us in units.items() for f, y in rng.sample(us, alloc[h])]
        p = ppi.stratified_ppi([(h, f) for h, us in units.items() for f, _ in us], smp,
                               small_sample=small_sample)
        q = ppi.stratified_proportion(sizes, [(h, y) for h, _, y in smp])
        for k, r in (("ppi", p), ("human", q)):
            cover[k] += r["ci"][0] <= truth <= r["ci"][1]
            bias[k] += r["estimate"] - truth
    return {"ppi": cover["ppi"] / reps, "human": cover["human"] / reps,
            "ppi_bias": bias["ppi"] / reps, "human_bias": bias["human"] / reps}


@pytest.mark.parametrize("err_fp, err_fn", [(0.1, 0.1), (0.3, 0.05), (0.02, 0.02), (0.01, 0.0)])
def test_ppi_covers_known_truth(err_fp: float, err_fn: float) -> None:
    """95% intervals on synthetic data with known truth. 600 replications put
    the Monte Carlo standard error near 0.9 points, so 0.93 is a 2-sigma floor."""
    got = _coverage(err_fp, err_fn, "plus-two", reps=600, seed=17)
    assert got["ppi"] >= 0.93, got
    assert got["human"] >= 0.93, got
    assert abs(got["ppi_bias"]) < 0.005 and abs(got["human_bias"]) < 0.005, got


def test_plain_ppi_covers_with_a_middling_model_and_why_the_floor_exists() -> None:
    plain_ok = _coverage(0.1, 0.1, None, reps=600, seed=23)
    assert plain_ok["ppi"] >= 0.93, plain_ok
    # The documented failure the plus-two floor fixes: an accurate model leaves
    # too few disagreements for the plug-in variance.
    plain_bad = _coverage(0.01, 0.0, None, reps=600, seed=23)
    assert plain_bad["ppi"] < 0.9, plain_bad


def _docs(n_pop: int = 300) -> tuple[dict[str, str], dict[str, Any], dict[str, Any]]:
    sample = _load("sample")
    records = _records(n_pop)
    doc = sample.build_sample(records, n=150)
    rng = random.Random(5)
    model = {r["hit_id"]: rng.choice(sample.LABELS) for r in records}
    return model, doc, sample.verdicts_template(doc)


def test_estimate_is_pending_until_every_verdict_is_set() -> None:
    ppi = _load("ppi")
    model, doc, verdicts = _docs()
    assert ppi.estimate(model, doc, verdicts)["status"] == "pending"
    for v in verdicts["verdicts"][:-1]:
        v["verdict"] = "unknown"
    assert ppi.estimate(model, doc, verdicts) == {"status": "pending", "verdicts_set": 149,
                                                  "verdicts_total": 150}


def test_estimate_reports_both_unknown_bounds() -> None:
    ppi = _load("ppi")
    model, doc, verdicts = _docs()
    rng = random.Random(9)
    for v in verdicts["verdicts"]:
        v["verdict"] = rng.choice(["truly-open", "hosted-oauth", "unknown"])
    out = ppi.estimate(model, doc, verdicts)
    assert out["status"] == "adjudicated"
    lo, hi = out["lower"]["human_only"]["estimate"], out["upper"]["human_only"]["estimate"]
    assert lo < hi
    for bound in ("lower", "upper"):
        a, b = out[bound]["ppi"]["ci"]
        assert 0.0 <= a <= out[bound]["ppi"]["estimate"] <= b <= 1.0
    bad = json.loads(json.dumps(verdicts))
    bad["verdicts"][0]["verdict"] = "fine"
    with pytest.raises(ValueError):
        ppi.estimate(model, doc, bad)
