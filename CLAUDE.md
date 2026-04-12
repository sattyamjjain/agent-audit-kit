# AgentAuditKit

<!-- AUTO-MANAGED: project-description -->
## Overview

**AgentAuditKit** (v0.2.0) — Security scanner for MCP-connected AI agent pipelines. The "npm audit" for AI agents.

- **77 rules** across 11 security categories
- **13 scanner modules** including Python/TypeScript/Rust taint analysis
- **9 CLI commands**: `scan`, `discover`, `pin`, `verify`, `fix`, `score`, `update`, `proxy`, `kill`
- **OWASP coverage**: Agentic Top 10 (10/10), MCP Top 10 (10/10), Adversa AI Top 25
- **Compliance mapping**: EU AI Act, SOC 2, ISO 27001, HIPAA, NIST AI RMF
- Zero cloud dependencies — fully offline

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

```bash
# Install (editable)
pip install -e ".[dev]"

# Run the CLI
agent-audit-kit scan .
agent-audit-kit discover .
agent-audit-kit score .

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
  cli.py              # Click CLI entry point (9 commands)
  engine.py            # Scanner registry + orchestrator (run_scan)
  models.py            # Core dataclasses: Finding, ScanResult, Severity, Category
  scoring.py           # Penalty-based scoring (100 → deductions per severity)
  discovery.py         # Agent platform discovery (13 platforms)
  pinning.py           # MCP server version pinning
  verification.py      # Pinned server verification
  fix.py               # Auto-fix engine for fixable rules
  diff.py              # Diff-based scanning
  llm_scan.py          # LLM-assisted scanning
  vuln_db.py           # CVE/vulnerability database
  rules/
    builtin.py         # 77 RuleDefinition entries (rule registry)
  scanners/            # 13 scanner modules, each exports scan() -> (list[Finding], set[str])
    mcp_config.py      # MCP configuration checks
    hook_injection.py  # Hook injection detection
    trust_boundary.py  # Trust boundary violations
    secret_exposure.py # Hardcoded secrets
    supply_chain.py    # Dependency supply chain risks
    agent_config.py    # Agent configuration analysis
    tool_poisoning.py  # Tool poisoning / rug-pull detection
    taint_analysis.py  # Python taint flow analysis
    typescript_scan.py # TypeScript taint analysis
    rust_scan.py       # Rust taint analysis
    transport_security.py  # Transport-layer security
    a2a_protocol.py    # Agent-to-Agent protocol checks
    legal_compliance.py    # EU AI Act / SOC 2 / HIPAA mapping
  output/              # Report formatters
    console.py         # Terminal output with colors
    json_report.py     # JSON report
    sarif.py           # SARIF for GitHub Security tab
    owasp_report.py    # OWASP mapping report
    compliance.py      # Compliance report
  proxy/
    interceptor.py     # MCP proxy interceptor
  data/                # Static data files (YAML configs, rule metadata)
tests/                 # pytest suite (30 test files, fixtures-based)
  conftest.py          # Shared fixtures (tmp_project, vulnerable_mcp_project, etc.)
  fixtures/            # Test fixture files (JSON configs, env files)
vscode-extension/      # VS Code extension (TypeScript) — separate subtree
docs/                  # MkDocs documentation site
benchmarks/            # Benchmark crawler
```

**Data flow**: CLI (cli.py) → engine.run_scan() → scanner registry → each scanner's `scan(project_root)` → `list[Finding]` → scoring → output formatter

**Scanner contract**: Every scanner module exports `scan(project_root: Path, ...) -> tuple[list[Finding], set[str]]` where the tuple is (findings, evaluated_rule_ids).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- **Python 3.9+** — all files start with `from __future__ import annotations`
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_SNAKE` for constants
- **Data models**: `@dataclass` (stdlib), not Pydantic — `Finding`, `ScanResult`, `RuleDefinition`
- **Enums**: `Severity` and `Category` as `enum.Enum` with custom comparison operators
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
- **Rule registry**: `rules/builtin.py` defines all 77 rules as `RuleDefinition` dataclasses in a global `RULES` dict, populated by `_r()` helper.
- **Finding model**: All scanners produce `Finding` dataclasses with rule_id, severity, category, evidence, remediation, and framework references (OWASP, CVE, Adversa).
- **Scoring**: Penalty-based (start at 100, deduct per severity), clamped to [0,100], mapped to letter grade.
- **Output formatters**: Each module in `output/` takes a `ScanResult` and formats it (console, JSON, SARIF, OWASP, compliance).
- **GitHub Action**: `action.yml` at root wraps the CLI for CI/CD integration with SARIF upload.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

- **Recent focus**: CI/CD fixes, documentation (GitLab CI guide, GitHub Pages), marketplace compliance
- **Commit style**: Conventional commits — `fix:`, `docs:`, `chore:`, `ci:`
- **Branch strategy**: Single `main` branch, PR-based workflow

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

Add project-specific notes, decisions, and context here. This section is never auto-modified.

<!-- END MANUAL -->
