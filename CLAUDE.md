# AgentAuditKit

<!-- AUTO-MANAGED: project-description -->
## Overview

**AgentAuditKit** (version tracked in `pyproject.toml` / `agent_audit_kit.__version__`) — Security scanner for MCP-connected AI agent pipelines. The "npm audit" for AI agents.

- **332 rules** across 14 security categories
- **98 scanner modules** including AST-based Python taint analysis plus regex dangerous-sink pattern scanners for TypeScript/JavaScript and Rust (pattern matching, not taint flow)
- **26 CLI commands**: `scan`, `discover`, `pin`, `verify`, `fix`, `score`, `update`, `proxy`, `kill`, `diff`, `suggest`, `watch`, `watch-cve`, `notify`, `install-precommit`, `export-rules`, `verify-bundle`, `sbom`, `report`, `coverage`, `inspect-ide`, `parity`, `corpus`, `pipelock`, `rule`, `scanners`
- **OWASP coverage**: Agentic Top 10 (10/10), MCP Top 10 (10/10), Adversa AI Top 25
- **Compliance mapping** (12 frameworks): EU AI Act, SOC 2, ISO 27001/42001, HIPAA, NIST AI RMF, NSA MCP CSI, + regional (India DPDP, Singapore, Alabama, Tennessee)
- **10 agent platforms** enumerated by `discover` (`discovery.AGENT_CONFIGS`)
- Zero cloud dependencies — fully offline

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

`Makefile` is the task runner — prefer it over raw commands, since several targets
are drift guards that CI also runs.

```bash
# Make targets
make test                # python -m pytest -q
make lint                # ruff check .
make typecheck           # mypy agent_audit_kit
make count-check         # guard: no stale rule/scanner count in ANY tracked *.md (incl. this file)
make report              # regenerate research/state-of-mcp-2026/results.json (offline, deterministic)
make report-check        # fail if results.json is stale vs a fresh run
make corpus              # refresh the MCP Registry corpus manifest (network)
make cve-latency         # recompute docs/cve-latency.md from the CVE ledger
make cve-latency-check   # fail if docs/cve-latency.md is stale (drift guard, runs on tag)
make cve-latency-refresh # top up docs/data/cve-published.json from NVD (network)
make repo-description    # render the GitHub "About" text from RULE_COUNT

# Install (editable)
pip install -e ".[dev]"

# Run the CLI — `aak` is an installed alias for `agent-audit-kit` (same entry point)
aak scan .
aak discover .
aak score .

# Tests
python3 -m pytest                    # all tests
python3 -m pytest tests/test_cli.py  # single file
python3 -m pytest -x                 # stop on first failure

# Lint / type check
ruff check .                         # lint
ruff check --fix .                   # auto-fix lint
mypy agent_audit_kit/                # type check

# Syntax verify
python3 -m py_compile agent_audit_kit/<file>.py

# Build / package
python3 -m build                     # build wheel + sdist

# Docker
docker build -t agent-audit-kit .
```

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

```
agent_audit_kit/
  cli.py               # Click entry point (26 commands: 23 @cli.command + 3 @cli.group)
  rule_lint.py         # Rule-registry hygiene checks behind `aak rule lint`
  engine.py            # Scanner registry + orchestrator (run_scan)
  models.py            # Core dataclasses: Finding, ScanResult, Severity, Category
  scoring/             # Penalty-based scoring (100 → deductions per severity)
  discovery.py         # Agent platform discovery (AGENT_CONFIGS)
  pinning.py, verification.py    # MCP server version pinning + verification
  fix.py, autofix/               # Auto-fix engine and per-rule strategies
  autopr.py            # Draft-PR delivery for mechanical fixes via the `gh` CLI (never handles tokens)
  diff.py              # Diff-based scanning
  llm_scan.py          # LLM-assisted scanning
  vuln_db.py, advisories.py, feeds/, watch.py   # CVE DB, advisories, live feeds, watch/watch-cve
  coverage.py, bundle.py         # Framework coverage; signed rule-bundle export/verify
  rules/
    builtin.py         # 332 RuleDefinition entries (rule registry)
  scanners/            # 98 registered scanners (100 .py files on disk — the registry is authoritative)
    mcp_config.py      # MCP configuration checks
    hook_injection.py  # Hook injection detection
    trust_boundary.py  # Trust boundary violations
    secret_exposure.py # Hardcoded secrets
    supply_chain.py    # Dependency supply chain risks
    agent_config.py    # Agent configuration analysis
    tool_poisoning.py  # Tool poisoning / rug-pull detection
    taint_analysis.py  # Python taint flow analysis (AST source→sink)
    typescript_pattern_scan.py # TypeScript/JS dangerous-sink pattern scan (regex, not taint flow)
    rust_pattern_scan.py       # Rust dangerous-sink pattern scan (regex, not taint flow)
    transport_security.py  # Transport-layer security
    a2a_protocol.py    # Agent-to-Agent protocol checks
    legal_compliance.py    # EU AI Act / SOC 2 / HIPAA mapping
  sessions/            # Session transcript adapters (adapters.py)
  checks/, sanitizers/ # Shared check helpers; input sanitization
  output/              # Report formatters
    console.py, json_report.py, sarif.py, owasp_report.py, compliance.py
    crosswalk.py, coverage_map.py, pdf_report.py, pr_summary.py, sbom.py, aicm.py
  proxy/
    interceptor.py     # MCP proxy interceptor
  ide/, parity/, translators/, integrations/, presets/, remediation/, corpus/, sarif/
  data/                # Static data files (YAML configs, rule metadata)
tests/                 # pytest suite, fixtures-based
  conftest.py          # Shared fixtures (tmp_project, vulnerable_mcp_project, etc.)
  fixtures/            # Test fixture files (JSON configs, env files)
scripts/               # check_counts.py, sync_rule_count.py, sync_scanner_count.py, cve_latency.py, ...
docs/                  # MkDocs documentation site
examples/              # Example projects + case studies (incl. an intentional findings.sarif)
research/              # state-of-mcp-2026 report (regenerated by `make report`)
benchmarks/            # Benchmark crawler
launch/, releases/     # Dated launch notes and release collateral (count-guard exempt)
public/, site/         # Generated coverage/marketing pages
schema/, editors/, ci/ # JSON schema, editor integrations, CI helpers
vscode-extension/      # VS Code extension (TypeScript) — separate subtree, has its own CLAUDE.md
```

**Data flow**: CLI (cli.py) → engine.run_scan() → scanner registry → each scanner's `scan(project_root)` → `list[Finding]` → scoring → output formatter

**Scanner contract**: Every scanner module exports `scan(project_root: Path, ...) -> tuple[list[Finding], set[str]]` where the tuple is (findings, evaluated_rule_ids).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- **Python 3.9+** (`requires-python = ">=3.9"`) — all files start with `from __future__ import annotations`
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_SNAKE` for constants
- **Data models**: `@dataclass` (stdlib), not Pydantic — `Finding`, `ScanResult`, `RuleDefinition`
- **Enums**: `Severity` (5 levels) and `Category` (14 members) as `enum.Enum` with custom comparison operators
- **Type hints**: On all function signatures; `Optional[X]` for nullable, `list[str]` (lowercase generic)
- **Imports**: `from __future__ import annotations` first, then stdlib, then third-party, then local
- **CLI**: Click decorators, exit codes: 0=pass, 1=findings, 2=error
- **Tests**: pytest, fixture-based (`tmp_path`, custom fixtures in `conftest.py`), one test file per scanner
- **Error handling**: `try/except ImportError: pass` for optional scanner imports in registry
- **Docstrings**: Google-style with Args/Returns sections where present

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Scanner registry**: `engine.py` lazy-builds a list of `ScannerRegistration` dataclasses; each wraps a `scan_fn` callable. New scanners are registered via try/except ImportError blocks for backward compatibility.
- **Rule registry**: `rules/builtin.py` defines all 332 rules as `RuleDefinition` dataclasses in a global `RULES` dict, populated by `_r()` helper.
- **Counts are generated, never hand-typed**: `agent_audit_kit/__init__.py` holds `RULE_COUNT` / `SCANNER_COUNT`; `scripts/sync_rule_count.py` and `scripts/sync_scanner_count.py` regenerate them. `scripts/check_counts.py` (`make count-check`) fails if any tracked `*.md` — **including this file** — carries a stale count. Regenerate; do not hand-fix. Dated/historical docs are exempted via the exclusion list in `check_counts.py`.
- **The guard is phrase-based, not number-based**: `check_counts.py` only checks counts written in one of its `PATTERNS` phrasings (`"N rules across"`, `"N scanner modules"`, `"N registered scanners"`, `"N CLI commands"`, ...). A count phrased any other way is never looked at and rots silently while `make count-check` reports clean — the `registered scanners` line in this file sat at a stale value for exactly that reason until its pattern was added. When prose needs a new count phrasing, reuse a guarded one or add it to `PATTERNS` in `scripts/check_counts.py`; that tuple is the single source, and `tests/test_rule_count_sync.py` imports `find_stale_counts()` rather than mirroring it.
- **Count invariants under test**: `tests/test_repo_metadata_sync.py` asserts `SCANNER_COUNT` equals the real `engine._build_registry()` size, so the scanner constant tracks the registry, not the file count in `scanners/`.
- **Finding model**: All scanners produce `Finding` dataclasses with rule_id, severity, category, evidence, remediation, and framework references (OWASP, CVE, Adversa).
- **Scoring**: Penalty-based (start at 100, deduct per severity), clamped to [0,100], mapped to letter grade.
- **Output formatters**: Each module in `output/` takes a `ScanResult` and formats it (console, JSON, SARIF, OWASP, compliance, crosswalk, SBOM, PDF, PR summary).
- **GitHub Action**: `action.yml` at root wraps the CLI for CI/CD integration with SARIF upload.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

- **Recent focus**: CVE-wave triage and pinning (`fix(cve):`, per-wave PRs), replacing proximity heuristics with real data flow (STDIO cmd-injection, SSRF reachability), unauthenticated MCP sidecar dashboards, CVE-to-rule latency published as a guarded number
- **Commit style**: Conventional commits — last 100: `chore` 43, `fix` 29, `docs` 6, `feat` 4, `test` 1. Non-conventional subjects are the long-form PR titles for substantive changes.
- **Release discipline**: counts land via generated `chore(rule-count): auto-sync` commits; release jobs fail fast on a stale GitHub description, a bad docs URL, an open `cve-response` issue, or a derivable count that drifted
- **Branch strategy**: Single `main` branch, PR-based workflow — merged subjects carry the PR number (`… (#606)`). Topic branches follow `feat/`, `fix/`, `chore/`.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

Add project-specific notes, decisions, and context here. This section is never auto-modified.

<!-- END MANUAL -->
