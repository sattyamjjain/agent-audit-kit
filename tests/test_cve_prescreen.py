"""Offline tests for the CVE pre-screen (`benchmarks/cve_prescreen`).

No network and no model: NVD, GHSA and OSV responses are hand-written fixtures
under `tests/fixtures/cve_prescreen/`, `gh` and `claude` are replaced by fakes,
and the committed backtest artifacts are checked against each other.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from benchmarks.cve_prescreen import DISPOSITIONS, backtest, context, ground_truth, metrics, prompts  # noqa: E402
from benchmarks.cve_prescreen import retrieval, runner, screen, verify  # noqa: E402
from benchmarks.cve_prescreen.__main__ import main as cli_main  # noqa: E402

FIX = REPO / "tests" / "fixtures" / "cve_prescreen"
CVE = "CVE-2099-10001"


def _load(name: str) -> Any:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def _context() -> dict[str, Any]:
    return context.build_context(
        CVE,
        _load("nvd_pinnable.json"),
        _load("ghsa_global.json"),
        [_load("ghsa_repository.json")],
        [_load("osv_ghsa.json"), _load("osv_cve.json")],
        {"nvd": "ok", "ghsa": "ok", "osv": "ok"},
    )


# ---------------------------------------------------------------------------
# context
# ---------------------------------------------------------------------------


def test_context_keeps_the_triage_fields_from_all_three_sources() -> None:
    ctx = _context()
    nvd = ctx["nvd"]
    assert nvd["description"].startswith("Example MCP Toolkit")  # the English one, not "es"
    assert nvd["cwes"] == ["CWE-22"]  # deduplicated, NVD-CWE-noinfo dropped
    assert nvd["cvss"][0]["base_score"] == 6.5
    assert nvd["affected"][1] == {
        "vendor": "example", "product": "example-mcp-store",
        "versions": [{"version": "0", "lessThan": "0.9.1", "status": "affected", "versionType": "semver"}],
    }
    assert nvd["cpe_matches"][0]["version_end_excluding"] == "2.4.0"
    assert [g["kind"] for g in ctx["ghsa"]] == ["global", "repository"]
    assert ctx["ghsa"][0]["vulnerabilities"][1]["first_patched_version"] == "0.9.1"
    assert ctx["ghsa"][1]["vulnerabilities"][0]["patched_versions"] == "0.26.2"
    assert "credits" not in json.dumps(ctx)  # no reporter identities in the context
    # The CVE's own OSV record first, whatever order the fetches came back in.
    assert [r["id"] for r in ctx["osv"]] == [CVE, "GHSA-aaaa-bbbb-cccc"]
    git = ctx["osv"][0]["affected"][0]["ranges"][0]
    assert git["extracted_events"] == [{"introduced": "0"}, {"fixed": "2.4.0"}]
    assert ctx["osv"][0]["affected"][0]["versions_listed"] == 3


def test_context_digest_ignores_fetch_order() -> None:
    a = _context()
    b = context.build_context(
        CVE, _load("nvd_pinnable.json"), _load("ghsa_global.json"), [_load("ghsa_repository.json")],
        [_load("osv_cve.json"), _load("osv_ghsa.json")], {"osv": "ok", "ghsa": "ok", "nvd": "ok"},
    )
    assert context.context_digest(a) == context.context_digest(b)


def test_long_advisory_text_is_truncated_and_flagged() -> None:
    adv = dict(_load("ghsa_global.json")[0], description="x" * 5000)
    entry = context.ghsa_entry(adv, "global")
    assert len(entry["description_excerpt"]) == context.DESCRIPTION_EXCERPT_CHARS
    assert entry["description_truncated"] is True


@pytest.mark.parametrize("path, expected", [
    ("ghsa[0].vulnerabilities[1].name", (True, "example-mcp-store")),
    ("osv[1].affected[0].ranges[0].events[1].fixed", (True, "2.4.0")),
    ("nvd.affected[1].versions[0].lessThan", (True, "0.9.1")),
    ("ghsa[0].vulnerabilities[9].name", (False, None)),
    ("ghsa[0].nope", (False, None)),
    ("nvd..description", (False, None)),
    ("ghsa[x].name", (False, None)),
    ("ghsa[0", (False, None)),
    ("ghsa[0]name", (False, None)),
    ("", (False, None)),
    ("a." * 200, (False, None)),
])
def test_resolve_path(path: str, expected: tuple[bool, Any]) -> None:
    assert context.resolve_path(_context(), path) == expected


def test_free_text_is_not_a_citable_field() -> None:
    index = context.structured_values(_context())
    assert "example-mcp-toolkit" in index
    assert not any(v.startswith("Example MCP Toolkit provides") for v in index)
    assert context.structured_packages(_context()) == [
        ("PyPI", "example-mcp-store"), ("PyPI", "example-mcp-toolkit"),
        ("go", "github.com/example/gateway"),
        ("pip", "example-mcp-store"), ("pip", "example-mcp-toolkit"),
    ]


# ---------------------------------------------------------------------------
# retrieval
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_nvd_limiter_never_allows_six_requests_in_thirty_seconds() -> None:
    clock = _Clock()
    limiter = retrieval.SlidingWindowLimiter(clock=clock, sleep=clock.sleep)
    stamps = []
    for _ in range(23):
        limiter.acquire()
        stamps.append(clock.now)
        clock.now += 0.2  # the request itself
    for start in stamps:
        in_window = [t for t in stamps if start <= t < start + retrieval.NVD_WINDOW_SECONDS]
        assert len(in_window) <= retrieval.NVD_MAX_REQUESTS
    assert clock.sleeps, "a burst of 23 must have been made to wait"


class _FakeNet:
    """Fixture-backed stand-ins for urllib (NVD, OSV) and `gh api` (GHSA)."""

    def __init__(self, nvd: Any, statuses: list[int] | None = None) -> None:
        self.nvd = nvd
        self.statuses = list(statuses or [])
        self.http_calls: list[str] = []
        self.gh_calls: list[str] = []

    def http_get(self, url: str) -> tuple[int, Any]:
        self.http_calls.append(url)
        if url.startswith(retrieval.NVD_API):
            if self.statuses:
                return self.statuses.pop(0), None
            return 200, self.nvd
        if url.endswith(CVE):
            return 200, _load("osv_cve.json")
        if url.endswith("GHSA-aaaa-bbbb-cccc"):
            return 200, _load("osv_ghsa.json")
        return 404, None

    def gh_api(self, path: str) -> tuple[int, Any]:
        self.gh_calls.append(path)
        if path.startswith("/advisories?"):
            return 200, _load("ghsa_global.json")
        if path == "/repos/example/example-mcp-toolkit/security-advisories/GHSA-bbbb-cccc-dddd":
            return 200, _load("ghsa_repository.json")
        return 404, None


def _retriever(tmp_path: Path, net: _FakeNet, **kw: Any) -> retrieval.Retriever:
    clock = _Clock()
    limiter = retrieval.SlidingWindowLimiter(clock=clock, sleep=clock.sleep)
    return retrieval.Retriever(
        retrieval.DiskCache(tmp_path), http_get=net.http_get, gh_api=net.gh_api,
        limiter=limiter, sleep=clock.sleep, **kw,
    )


def test_bundle_reads_all_three_sources_and_follows_the_repository_advisory(tmp_path: Path) -> None:
    net = _FakeNet(_load("nvd_pinnable.json"))
    bundle = _retriever(tmp_path, net).bundle(CVE)
    assert bundle.status["nvd"] == "ok" and bundle.status["ghsa"] == "ok"
    assert bundle.status["ghsa_repository"] == "ok"
    assert net.gh_calls == [
        "/advisories?cve_id=CVE-2099-10001",
        "/repos/example/example-mcp-toolkit/security-advisories/GHSA-bbbb-cccc-dddd",
    ]
    # The CVE record, its GHSA alias, then the PYSEC alias, each attempted once.
    osv = [u for u in net.http_calls if u.startswith(retrieval.OSV_API)]
    assert osv == [retrieval.OSV_API + i for i in (CVE, "GHSA-aaaa-bbbb-cccc", "GHSA-bbbb-cccc-dddd", "PYSEC-2099-7")]
    assert {r["id"] for r in bundle.osv} == {CVE, "GHSA-aaaa-bbbb-cccc"}


def test_a_cached_record_costs_no_network_and_offline_refuses_it(tmp_path: Path) -> None:
    net = _FakeNet(_load("nvd_pinnable.json"))
    first = _retriever(tmp_path, net).bundle(CVE)
    calls = len(net.http_calls) + len(net.gh_calls)
    again = _retriever(tmp_path, net)
    second = again.bundle(CVE)
    assert again.network_calls == 0
    assert len(net.http_calls) + len(net.gh_calls) == calls
    assert first.context() == second.context()
    offline = _retriever(tmp_path / "empty", net, offline=True).bundle(CVE)
    assert offline.status["nvd"] == "not-cached" and offline.nvd is None


def test_nvd_throttling_is_retried_and_zero_results_is_not_found(tmp_path: Path) -> None:
    net = _FakeNet(_load("nvd_pinnable.json"), statuses=[403, 503])
    r = _retriever(tmp_path, net)
    assert r.nvd(CVE)["status"] == 200
    assert len([u for u in net.http_calls if u.startswith(retrieval.NVD_API)]) == 3
    empty = _FakeNet({"totalResults": 0, "vulnerabilities": []})
    assert _retriever(tmp_path / "e", empty).nvd("CVE-2099-10002")["status"] == 404


def test_gh_is_called_through_rest_never_graphql(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="[]", stderr="")

    monkeypatch.setattr(retrieval.subprocess, "run", fake_run)
    assert retrieval.gh_api_json("/advisories?cve_id=CVE-2099-10001") == (200, [])
    assert seen == [["gh", "api", "/advisories?cve_id=CVE-2099-10001"]]
    for module in ("retrieval.py", "ground_truth.py", "__main__.py"):
        source = (REPO / "benchmarks" / "cve_prescreen" / module).read_text(encoding="utf-8")
        assert '"graphql"' not in source and "'graphql'" not in source


def test_gh_404_is_reported_as_404(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="gh: Not Found (HTTP 404)")

    monkeypatch.setattr(retrieval.subprocess, "run", fake_run)
    assert retrieval.gh_api_json("/repos/a/b/security-advisories/GHSA-aaaa-bbbb-cccc") == (404, None)


def test_issue_number_resolves_to_its_cve() -> None:
    def gh(path: str) -> tuple[int, Any]:
        assert path == "/repos/o/r/issues/926"
        return 200, {"title": "CVE-response: CVE-2099-10001 (MEDIUM CVSS 6.5)"}

    assert retrieval.cve_for_issue(926, "o/r", gh) == CVE
    with pytest.raises(LookupError):
        retrieval.cve_for_issue(1, "o/r", lambda p: (200, {"title": "no id here"}))


# ---------------------------------------------------------------------------
# prompts and schemas
# ---------------------------------------------------------------------------


def _objects(schema: Any) -> list[dict[str, Any]]:
    found = []
    if isinstance(schema, dict):
        if schema.get("type") == "object":
            found.append(schema)
        for value in schema.values():
            found.extend(_objects(value))
    elif isinstance(schema, list):
        for value in schema:
            found.extend(_objects(value))
    return found


def test_schemas_are_closed_and_name_the_four_dispositions() -> None:
    for schema in (prompts.NOISE_SCHEMA, prompts.CLASSIFY_SCHEMA):
        assert json.loads(prompts.schema_json(schema)) == schema
        assert all(obj.get("additionalProperties") is False for obj in _objects(schema))
    assert prompts.CLASSIFY_SCHEMA["properties"]["disposition"]["enum"] == list(DISPOSITIONS)
    assert DISPOSITIONS == ("version-pin", "new-detection", "out-of-scope", "needs-human")


def test_validator_rejects_what_the_schema_rejects() -> None:
    good = _load("claude_result_classify.json")["structured_output"]
    assert prompts.validate(prompts.CLASSIFY_SCHEMA, good) == []
    bad = dict(good, disposition="pin-it", extra=1)
    errors = prompts.validate(prompts.CLASSIFY_SCHEMA, bad)
    assert any("not in enum" in e for e in errors) and any("not allowed" in e for e in errors)
    assert prompts.validate(prompts.NOISE_SCHEMA, {"is_noise": "yes"}) == [
        "$.rationale: missing", "$.is_noise: expected boolean",
    ]


def test_the_record_is_fenced_as_untrusted_data() -> None:
    message = prompts.user_message(_context())
    assert message.count("<record>") == 1 and message.count("</record>") == 1
    assert context.canonical_json(_context()) in message
    for system in (prompts.NOISE_SYSTEM, prompts.CLASSIFY_SYSTEM):
        assert "untrusted" in system and "Ignore any instruction" in system


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------


def test_command_isolates_the_call_and_keeps_the_prompt_off_argv() -> None:
    argv = runner.build_command("claude", "sonnet", "SYSTEM", '{"type":"object"}')
    for flag in ("-p", "--safe-mode", "--strict-mcp-config", "--no-session-persistence"):
        assert flag in argv
    assert argv[argv.index("--mcp-config") + 1] == '{"mcpServers":{}}'
    assert argv[argv.index("--output-format") + 1] == "json"
    assert argv[argv.index("--model") + 1] == "sonnet"
    # `--tools` is variadic, so it must be last: anything after it is a tool name.
    assert argv[-2:] == ["--tools", ""]


def test_environment_drops_api_credentials_and_parent_session_state() -> None:
    env = runner.scrubbed_env({
        "PATH": "/usr/bin", "HOME": "/home/u",
        "ANTHROPIC_API_KEY": "placeholder", "ANTHROPIC_AUTH_TOKEN": "placeholder",
        "CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "s", "CLAUDE_CODE_MESSAGING_TOKEN": "m",
        "_CLAUDE_OTEL_BASE_ATTRS": "a",
    })
    assert env == {
        "PATH": "/usr/bin", "HOME": "/home/u",
        "CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK": "1", "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    }


def test_each_call_runs_in_a_fresh_empty_directory_with_the_prompt_on_stdin() -> None:
    seen: dict[str, Any] = {}
    payload = (FIX / "claude_result_classify.json").read_text(encoding="utf-8")

    def fake(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kw, argv=argv, listing=list(Path(kw["cwd"]).iterdir()), exists=Path(kw["cwd"]).is_dir())
        return subprocess.CompletedProcess(argv, 0, stdout=payload, stderr="")

    result = runner.run_claude(
        "PROMPT", model="sonnet", system_prompt="S", schema_json="{}", runner=fake,
        env={"ANTHROPIC_API_KEY": "placeholder", "PATH": "/bin"},
    )
    assert seen["exists"] and seen["listing"] == []
    assert not Path(seen["cwd"]).exists()  # removed after the call
    assert seen["input"] == "PROMPT" and "PROMPT" not in seen["argv"]
    assert "ANTHROPIC_API_KEY" not in seen["env"]
    assert result.ok and result.models_used == ["claude-sonnet-5-5"] and not result.model_mismatch
    assert result.cost_usd == 0.032686 and result.cost_basis == "list"


def test_parse_result_flags_refusal_fallback_and_garbage() -> None:
    refusal = runner.parse_result((FIX / "claude_result_refusal.json").read_text(), "", 0, "haiku", 1.0)
    assert refusal.refusal and not refusal.ok and "stop_reason=refusal" in refusal.refusal_signal
    fallback = runner.parse_result((FIX / "claude_result_fallback.json").read_text(), "", 0, "sonnet", 1.0)
    assert fallback.ok and fallback.model_mismatch and fallback.models_used == ["claude-haiku-5-5"]
    garbage = runner.parse_result("not json", "boom", 1, "sonnet", 1.0)
    assert not garbage.ok and garbage.error.startswith("no JSON result") and garbage.raw_excerpt == "boom"
    timeout_like = runner.parse_result('{"is_error": true, "subtype": "error_max_turns"}', "", 1, "haiku", 1.0)
    assert not timeout_like.ok and "error_max_turns" in timeout_like.error


def test_auth_status_keeps_the_method_and_drops_identity() -> None:
    status = json.dumps({
        "loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty",
        "email": "person@example.com", "orgId": "org", "orgName": "Org", "subscriptionType": "max",
    })

    def fake(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        assert argv[1:] == ["auth", "status", "--json"]
        return subprocess.CompletedProcess(argv, 0, stdout=status, stderr="")

    assert runner.auth_status("claude", runner=fake) == {
        "loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty", "subscriptionType": "max",
    }


# ---------------------------------------------------------------------------
# extraction verification
# ---------------------------------------------------------------------------


def _cited(value: str, source: str) -> dict[str, str]:
    return {"value": value, "source": source}


def test_every_extraction_verdict() -> None:
    ctx = _context()
    affected = [{
        "name": _cited("example-mcp-toolkit", "ghsa[0].vulnerabilities[0].name"),
        "ecosystem": _cited("PyPI", "ghsa[0].vulnerabilities[0].ecosystem"),
        "ranges": [
            _cited("< 2.4.0", "ghsa[0].vulnerabilities[0].vulnerable_version_range"),
            _cited("< 2.4.0", "ghsa[0].vulnerabilities[7].vulnerable_version_range"),
        ],
        "fixed_versions": [
            _cited("2.4.1", "ghsa[0].vulnerabilities[0].first_patched_version"),
            _cited("2.4.0", "nvd.description"),
        ],
    }]
    result = verify.verify_affected(ctx, affected)
    assert [c["verdict"] for c in result["checks"]] == [
        "exact", "mismatch", "exact", "bad-path", "invented", "free-text-but-present",
    ]
    assert result["invented"] == 1 and not result["all_exact"]
    assert result["packages_missing"] == ["example-mcp-store", "github.com/example/gateway"]
    assert not result["package_set_exact"]


def test_a_whitespace_only_difference_is_neither_exact_nor_invented() -> None:
    payload = _load("nvd_pinnable.json")
    payload["vulnerabilities"][0]["cve"]["affected"][0]["affectedData"][0]["product"] = "Example Toolkit"
    ctx = context.build_context("CVE-2099-10004", payload, [], [], [], {})
    result = verify.verify_affected(ctx, [
        {"name": _cited("Example Toolkit", "nvd.affected[0].product"), "ranges": [], "fixed_versions": []},
    ])
    assert [c["verdict"] for c in result["checks"]] == ["whitespace"]
    assert result["invented"] == 0 and not result["all_exact"]


def test_placeholder_products_are_not_expected_packages() -> None:
    payload = _load("nvd_pinnable.json")
    for item in payload["vulnerabilities"][0]["cve"]["affected"][0]["affectedData"]:
        item["product"] = "n/a"
    ctx = context.build_context("CVE-2099-10005", payload, [], [], [], {})
    assert context.expected_package_names(ctx) == []
    assert verify.verify_affected(ctx, [])["package_set_exact"]


def test_nvd_products_are_expected_only_when_no_registry_source_names_a_package() -> None:
    assert context.expected_package_names(_context()) == [
        "example-mcp-store", "example-mcp-toolkit", "github.com/example/gateway",
    ]
    nvd_only = context.build_context("CVE-2099-10002", _load("nvd_pinnable.json"), [], [], [], {})
    assert context.expected_package_names(nvd_only) == ["example-mcp-store", "example-mcp-toolkit"]
    assert not verify.verify_affected(nvd_only, [])["package_set_exact"]
    payload = _load("nvd_pinnable.json")
    del payload["vulnerabilities"][0]["cve"]["affected"]
    bare = context.build_context("CVE-2099-10003", payload, [], [], [], {})
    result = verify.verify_affected(bare, [])
    assert result["package_set_exact"] and result["values"] == 0


# ---------------------------------------------------------------------------
# screen
# ---------------------------------------------------------------------------


def _fake_call(noise: bool, disposition: str = "version-pin", model_family: str | None = None) -> Any:
    def call(message: str, *, model: str, system_prompt: str, schema_json: str) -> runner.CallResult:
        used = f"claude-{model_family or model}-5-5"
        if system_prompt == prompts.NOISE_SYSTEM:
            structured: dict[str, Any] = {"is_noise": noise, "rationale": "n"}
        else:
            structured = {
                "is_noise": noise, "disposition": disposition, "rationale": "c",
                "affected": [{
                    "name": _cited("example-mcp-toolkit", "ghsa[0].vulnerabilities[0].name"),
                    "ranges": [], "fixed_versions": [],
                }],
            }
        return runner.CallResult(
            model_requested=model, ok=True, structured=structured, models_used=[used],
            model_mismatch=(model_family is not None and model_family != model),
            cost_usd=0.01, cost_basis="list", wall_seconds=1.0, duration_api_ms=900,
        )
    return call


def test_noise_gate_decides_the_candidate_and_the_classifier_is_kept_beside_it() -> None:
    out = screen.screen(_context(), call=_fake_call(noise=True))
    assert out["candidate"] == {"disposition": "out-of-scope", "is_noise": True,
                                "decided_by": "noise-filter", "rationale": "n"}
    assert out["classification"]["structured"]["disposition"] == "version-pin"
    assert out["extraction"]["exact"] == 1
    assert out["prompt_version"] == prompts.PROMPT_VERSION


def test_a_silent_fallback_is_not_scored() -> None:
    out = screen.screen(_context(), call=_fake_call(noise=False, model_family="opus"))
    assert not out["noise"]["scorable"] and not out["classification"]["scorable"]
    assert out["candidate"]["decided_by"] == "none"


# ---------------------------------------------------------------------------
# ground truth
# ---------------------------------------------------------------------------


def _is_pin(rule_id: str) -> bool:
    return rule_id.startswith(("AAK-MCP-EXAMPLE-", "AAK-MCP-HUB-", "AAK-MCP-STATA-", "AAK-MCP-REMOTE-"))


@pytest.mark.parametrize("text, head, expected", [
    ("**New pin** `AAK-MCP-X-CVE-2099-1-001`: below 1.0.", None, ("version-pin", "new-pin")),
    ("**Out of scope**, non-pinnable. Upgrade.", None, ("out-of-scope", "out-of-scope")),
    ("**Floor raised** on `AAK-MCP-X`: 1.1 to 1.2.", None, ("version-pin", "floor-change")),
    ("Same pin. Fixed in v0.23.0.", None, ("version-pin", "existing-pin")),
    ("**Arm added** to `AAK-MCP-015`: a path.", None, ("new-detection", "new-arm")),
    ("No new rule, no pin: no fixed release. Recorded against `AAK-MCP-SSRF-001`.", None,
     ("new-detection", "existing-detection")),
    ("No new rule, no new pin. Recorded against `AAK-MCP-REMOTE-CVE-2099-1-001`.", None,
     ("version-pin", "existing-pin")),
    ("**In scope, detection rule (not pinned)** `AAK-MCP-UFO-CVE-2099-1-001` (MCP_CONFIG).", None,
     ("new-detection", "new-rule")),
    ("**In scope, pinned + pattern rules.** Pin moved.", None, ("version-pin", "pin-and-detection")),
    ("**Out of scope as a pin, already covered as a class.** It is `AAK-TRANSPORT-004`.", None,
     ("out-of-scope", "out-of-scope-class-covered")),
    ("body", "new pin (was out of scope)", ("version-pin", "new-pin")),
    ("body", "in scope, new pin, no new detection rule", ("version-pin", "new-pin")),
    ("Target: 2099-03-20.", "DEFERRED (`cve-deferred`) — in scope", ("needs-human", "deferred")),
    ("No new rule: the class detector already covers it.", "rule shipped (`AAK-MCP-SSRF-001`)",
     ("new-detection", "existing-detection")),
    ("**In scope, already covered** by `AAK-FLOWISE-001`, whose detector already floors Flowise at 3.1.3.",
     None, ("version-pin", "existing-pin")),
    ("Something with no cue at all.", None, ("", "")),
])
def test_disposition_text_classes(text: str, head: str | None, expected: tuple[str, str]) -> None:
    klass, detail, _, _ = ground_truth.classify_text(text, _is_pin, head=head)
    assert (klass, detail) == expected


@pytest.mark.parametrize("body, expected", [
    ("## Disposition: out of scope\n\nReason.", "out of scope"),
    ("Intro.\n\n### Disposition — DEFERRED\n", "— DEFERRED"),
    ("**Disposition: (c) out of scope.**\n\nWhy.", "out of scope."),
    ("Triaged: **out of scope**, no pin, and the near miss is worth recording.", "out of scope"),
    # No colon: not a statement here; issue_disposition falls back to the first line.
    ("Triaged in #584 (v0.3.76). **Out of scope — no pinnable artifact.**", ""),
    ("Closing as **out of scope**.\n\nKernel driver.", "out of scope"),
    ("Adjudicated IN SCOPE and pinned. Details.", "IN SCOPE and pinned"),
    ("## Disposition\n\nThe statement is on the next line, which is not a statement.", ""),
    ("Thanks, looking now.", ""),
])
def test_comment_statement_forms(body: str, expected: str) -> None:
    assert ground_truth.comment_statement(body) == expected


def test_comment_statement_is_linear_on_hostile_whitespace() -> None:
    started = time.monotonic()
    assert ground_truth.comment_statement("## Disposition" + " " * 200_000 + "\n") == ""
    assert ground_truth.comment_statement("**Disposition:" + " " * 200_000) == ""
    assert time.monotonic() - started < 2.0


def test_v1_subjects_expand_runs_and_skip_context_ids() -> None:
    assert ground_truth.subject_cves(
        "CVE-2099-10101 (CVSS 7.6), CVE-2099-10102 (6.9) — `example-agent` < 4.6.58, like CVE-2099-1"
    ) == ("CVE-2099-10101", "CVE-2099-10102")
    assert ground_truth.subject_cves("CVE-2099-10110 … CVE-2099-10112 (Hub, see CVE-2099-5)") == (
        "CVE-2099-10110", "CVE-2099-10111", "CVE-2099-10112",
    )
    assert ground_truth.split_cells(r"| a | b \| c | d |") == ["a", r"b \| c", "d"]


def test_ledger_and_issues_build_the_expected_records() -> None:
    ledger = (FIX / "ledger_excerpt.md").read_text(encoding="utf-8")
    issues = _load("issues_snapshot.json")
    records, report = ground_truth.build(ledger, issues, since="2099-02-01", is_pin_rule=_is_pin)
    by = {r.cve: r for r in records}
    # The newest row wins: out of scope at 11:00, pinned once the reader landed.
    assert (by["CVE-2099-20001"].disposition, by["CVE-2099-20001"].issue) == ("version-pin", 9001)
    assert by["CVE-2099-20002"].disposition == "out-of-scope"
    assert by["CVE-2099-20003"].acceptable == ["version-pin", "new-detection"]
    assert by["CVE-2099-20004"].detail == "new-arm"
    assert by["CVE-2099-20005"].detail == "existing-pin"
    assert by["CVE-2099-20006"].detail == "existing-detection"
    assert by["CVE-2099-10101"].disposition == by["CVE-2099-10102"].disposition == "version-pin"
    assert [by[f"CVE-2099-1011{i}"].package for i in range(3)] == ["@example/hub"] * 3
    assert by["CVE-2099-10120"].disposition == "new-detection"  # "No version pin" is not a pin
    assert by["CVE-2099-10130"].detail == "new-rule"
    assert by["CVE-2099-10140"].acceptable == ["version-pin", "new-detection"]
    # Issue-only records: the last disposition comment, then the close reason.
    assert by["CVE-2099-30001"].disposition == "out-of-scope" and by["CVE-2099-30001"].source == "issue"
    assert (by["CVE-2099-30002"].disposition, by["CVE-2099-30002"].detail) == ("new-detection", "new-rule")
    assert by["CVE-2099-30003"].detail == "existing-detection"
    assert by["CVE-2099-30005"].detail == "closed-not-planned"
    # Open issues and anything before the window are not ground truth.
    assert "CVE-2099-30004" not in by and "CVE-2099-00500" not in by and "CVE-2099-00001" not in by
    assert report["open_issues_excluded"] == ["CVE-2099-30004"]
    assert report["unlabelled"] == [] and report["ledger_issue_disagreements"] == []


def test_committed_ground_truth_is_internally_consistent() -> None:
    payload = json.loads(backtest.GROUND_TRUTH.read_text(encoding="utf-8"))
    records = [ground_truth.Truth(**r) for r in payload["records"]]
    assert payload["since"] == ground_truth.SINCE
    assert payload["summary"] == ground_truth.summary(records)
    assert payload["report"]["unlabelled"] == []
    for rec in records:
        assert rec.disposition in DISPOSITIONS and rec.disposition in rec.acceptable
        assert rec.section_date >= ground_truth.SINCE or rec.source == "issue"
    noise = {r.cve for r in records if r.is_noise}
    assert noise == set(ground_truth.NOISE)
    assert all(r.disposition == "out-of-scope" for r in records if r.is_noise)
    assert len({r.cve for r in records}) == len(records)


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------


def test_classification_scores_acceptable_classes_and_abstentions() -> None:
    rows = [
        {"truth": "version-pin", "acceptable": ["version-pin"], "p": "version-pin"},
        {"truth": "version-pin", "acceptable": ["version-pin", "new-detection"], "p": "new-detection"},
        {"truth": "out-of-scope", "acceptable": ["out-of-scope"], "p": "version-pin"},
        {"truth": "new-detection", "acceptable": ["new-detection"], "p": "needs-human"},
        {"truth": "new-detection", "acceptable": ["new-detection"], "p": None},
    ]
    m = metrics.classification(rows, "p")
    assert (m["scored"], m["unscored"]) == (4, 1)
    assert m["accuracy"]["k"] == 2 and m["coverage"]["k"] == 3
    assert m["selective_accuracy"]["k"] == 2 and m["selective_accuracy"]["n"] == 3
    assert m["confusion"]["new-detection"]["new-detection"] == 1
    assert m["confusion"]["out-of-scope"]["version-pin"] == 1
    assert m["per_class"]["version-pin"]["precision"]["k"] == 1
    assert m["per_class"]["version-pin"]["precision"]["n"] == 2


def test_binary_metrics_list_every_miss() -> None:
    rows = [
        {"cve": "A", "t": True, "p": True}, {"cve": "B", "t": True, "p": False},
        {"cve": "C", "t": False, "p": True}, {"cve": "D", "t": False, "p": False},
        {"cve": "E", "t": True, "p": None},
    ]
    m = metrics.binary(rows, "t", "p")
    assert (m["tp"], m["fp"], m["fn"], m["tn"], m["scored"]) == (1, 1, 1, 1, 4)
    assert m["false_positive_ids"] == ["C"] and m["false_negative_ids"] == ["B"]
    assert m["precision"]["rate"] == 0.5


# ---------------------------------------------------------------------------
# backtest
# ---------------------------------------------------------------------------


class _StubRetriever:
    def __init__(self) -> None:
        self.ctx = _context()

    def bundle(self, cve: str) -> Any:
        ctx = dict(self.ctx, cve_id=cve)

        class _B:
            status = {"nvd": "ok"}

            def context(self_inner) -> dict[str, Any]:
                return ctx

        return _B()


def test_backtest_runs_at_most_two_calls_at_once_and_resumes(tmp_path: Path) -> None:
    lock = threading.Lock()
    state = {"live": 0, "peak": 0}
    inner = _fake_call(noise=False)

    def call(message: str, **kw: Any) -> runner.CallResult:
        with lock:
            state["live"] += 1
            state["peak"] = max(state["peak"], state["live"])
        time.sleep(0.02)
        try:
            return inner(message, **kw)
        finally:
            with lock:
                state["live"] -= 1

    truths = [
        ground_truth.Truth(cve=f"CVE-2099-4{i:04d}", disposition="version-pin", acceptable=["version-pin"],
                           detail="new-pin", is_noise=False, package="`example-mcp-toolkit` (PyPI)",
                           issue=i, section_date="2099-02-01", source="ledger", evidence="New pin")
        for i in range(8)
    ]
    counts = backtest.run_backtest(truths, _StubRetriever(), tmp_path, concurrency=8, call=call, log=lambda s: None)
    assert counts == {"screened": 8, "skipped": 0, "no_context": 0}
    assert state["peak"] <= backtest.MAX_CONCURRENCY
    again = backtest.run_backtest(truths, _StubRetriever(), tmp_path, call=call, log=lambda s: None)
    assert again["skipped"] == 8 and again["screened"] == 0

    results = backtest.build_results(truths, tmp_path, {"prompt_version": "t", "limitations": ["x"]})
    s = results["summary"]
    assert s["sonnet"]["accuracy"]["k"] == 8 and s["pipeline"]["accuracy"]["k"] == 8
    assert s["ledger_package_named"] == {"k": 8, "n": 8}
    assert s["calls_sonnet"]["calls"] == 8 and s["calls_haiku"]["models_used"] == ["claude-haiku-5-5"]
    page = backtest.render_markdown(results)
    assert page == backtest.render_markdown(json.loads(json.dumps(results)))  # stable through JSON
    assert "| version-pin | 8 | 0 | 0 | 0 |" in page

    # Re-scoring at report time: same context re-verifies, a changed one is listed and kept.
    same = backtest.build_results(truths, tmp_path, {}, context_for=lambda cve: dict(_context(), cve_id=cve))
    assert same["meta"]["extraction_rescored"] == 8 and same["meta"]["context_digest_changed"] == []
    moved = backtest.build_results(truths[:1], tmp_path, {}, context_for=lambda cve: dict(_context(), cve_id="X"))
    assert moved["meta"]["extraction_rescored"] == 0
    assert moved["meta"]["context_digest_changed"] == [truths[0].cve]


def test_committed_results_page_matches_results_json() -> None:
    results = backtest.load_results()
    assert backtest.RESULTS_MD.read_text(encoding="utf-8") == backtest.render_markdown(results)
    assert results["meta"]["prompt_version"] == prompts.PROMPT_VERSION
    assert results["meta"]["prompt_fingerprint"] == backtest.prompt_fingerprint()
    assert results["meta"]["auth_method"] == "claude.ai"
    assert results["meta"]["concurrency"] <= backtest.MAX_CONCURRENCY
    gt_sha = backtest._sha256(backtest.GROUND_TRUTH)
    assert results["meta"]["ground_truth_sha256"] == gt_sha
    assert cli_main(["report", "--check"]) == 0
