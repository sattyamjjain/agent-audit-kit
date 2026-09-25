# AgentAuditKit

<!-- AUTO-MANAGED: project-description -->
## Overview

**AgentAuditKit** (version tracked in `pyproject.toml` / `agent_audit_kit.__version__`) — Security scanner for MCP-connected AI agent pipelines. The "npm audit" for AI agents.

- **362 rules** across 14 security categories
- **103 scanner modules** including AST-based Python taint analysis plus regex dangerous-sink pattern scanners for TypeScript/JavaScript and Rust (pattern matching, not taint flow)
- **27 CLI commands**: `scan`, `discover`, `pin`, `verify`, `fix`, `score`, `update`, `proxy`, `kill`, `diff`, `suggest`, `watch`, `watch-cve`, `notify`, `install-precommit`, `export-rules`, `verify-bundle`, `sbom`, `vex`, `report`, `coverage`, `inspect-ide`, `parity`, `corpus`, `pipelock`, `rule`, `scanners`
- **OWASP coverage**: Agentic Top 10 (10/10), MCP Top 10 (10/10), Adversa AI Top 25
- **Compliance mapping** (14 frameworks): EU AI Act (incl. Art. 50 transparency and Art. 55 packs), SOC 2, ISO 27001/42001, HIPAA, NIST AI RMF, NSA MCP CSI, + regional (India DPDP, Singapore, Alabama, Tennessee, Colorado SB 26-189 ADMT); EU AI Act Art. 50 in force 2026-08-02
- **10 agent platforms** enumerated by `discover` (`discovery.AGENT_CONFIGS`)
- Zero cloud dependencies — fully offline. The only optional dependency is the `taint` extra (tree-sitter), lazy-imported with a heuristic fallback
- **License**: Apache-2.0 (relicensed from MIT)

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

`Makefile` is the task runner — prefer it over raw commands, since most targets
are drift guards that CI also runs. Every generated artifact has a `-check` twin.

```bash
# Core
make test                # python -m pytest -q
make lint                # ruff check .
make typecheck           # mypy agent_audit_kit

# Drift guards (CI's `counts` job: count-check, report-figures-check, sync_scanner_count.py --check, build_coverage_page.py --check)
make count-check         # check_counts.py + sync_rule_count.py --check + sync_rule_doc_pages.py --check: no stale count in ANY tracked *.md (incl. this file)
make report-check        # results.json byte-identical to a fresh run
make report-figures-check # every governed report figure in prose sits inside a `report:` marker
make fp-check            # false-positive benchmark artifacts (slice, results, badge) not stale
make cve-latency-check   # docs/cve-latency.md matches the CVE ledger (runs on tag)
make remediation-corpus-check # remediation-key-corpus.json matches benchmarks/data

# Regenerate (offline, deterministic)
make report              # research/state-of-mcp-2026/results.json from the committed corpus manifest
make fp                  # re-measure the benign-slice FP benchmark; adjudication.json is HUMAN judgement, never regenerated
make cve-latency         # docs/cve-latency.md from the ledger
make remediation-corpus  # remediation-key-corpus.json
make repo-description    # render the GitHub "About" text from RULE_COUNT (paste into Settings > About; not writable from CI)

# Network steps (kept separate from the offline targets on purpose)
make corpus              # refresh the MCP Registry corpus manifest
make cve-latency-refresh # top up docs/data/cve-published.json from NVD
make registry-parity     # does the declared version exist on PyPI? (also daily in CI)
make cve-deferral-check  # every `cve-deferred` issue names a target date (needs gh)

# Install (editable) — [dev] pulls the optional [taint] extra so the tree-sitter data-flow path is tested, not just its fallback
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
ruff check .                         # rule set pinned to E4,E7,E9,F in pyproject — widen it deliberately, never via a ruff bump
ruff check --fix .                   # auto-fix lint
mypy agent_audit_kit/                # type check
python3 -m py_compile agent_audit_kit/<file>.py   # syntax verify a single file

# Build / package
python3 -m build                     # build wheel + sdist (hatchling)
docker build -t agent-audit-kit .    # container image
```

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

```
agent_audit_kit/
  cli.py               # Click entry point (27 commands): flat @cli.command entries, the @cli.group entries (corpus, pipelock, rule), and `scan` attached via add_command
  commands/            # Command bodies split out of cli.py (issue #701); imports flow one way, cli → commands, never back
    _common.py         # SEVERITY_MAP, FAIL_ON_CHOICES, EXIT_* (0 pass / 1 findings / 2 error), config helpers — cli re-exports all of them
    scan.py            # The `scan` command + `_run_scan`
  rule_lint.py         # Rule-registry hygiene checks behind `aak rule lint`
  engine.py            # Scanner registry (`_OPTIONAL_SCANNERS` table) + orchestrator (run_scan)
  models.py            # Core dataclasses: Finding, ScanResult, Severity, Category
  scoring/             # Penalty-based scoring (100 → deductions per severity); aivss.py = AIVSS vector scoring
  discovery.py         # Agent platform discovery (AGENT_CONFIGS)
  pinning.py, verification.py    # MCP server version pinning + verification
  fix.py, autofix/               # Auto-fix engine and per-rule strategies
  autopr.py            # Draft-PR delivery for mechanical fixes via the `gh` CLI (never handles tokens)
  diff.py              # Diff-based scanning
  llm_scan.py          # LLM-assisted scanning
  vuln_db.py, advisories.py, feeds/, watch.py   # CVE DB, advisories, live feeds, watch/watch-cve
  coverage.py, bundle.py         # Framework coverage; signed rule-bundle export/verify
  rules/
    builtin.py         # 362 RuleDefinition entries (rule registry); `get_rule(rule_id)` is the lookup
  scanners/            # 103 registered scanners (105 .py files on disk — the registry is authoritative; the surplus is the two back-compat shims rust_scan/typescript_scan, and `__init__`/`_`-prefixed helpers are not counted). Has its own CLAUDE.md.
    _helpers.py        # make_finding(rule_id, file_path, evidence, line_number) builds a Finding from the registry; SKIP_DIRS; shared regexes
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
    composition.py     # Cross-finding composition chains (Category.COMPOSITION) + the suppression keys run_scan uses
    legal_compliance.py    # EU AI Act / SOC 2 / HIPAA mapping
    eu_ai_act_art50.py, admt_documentation.py  # EU AI Act Art. 50 transparency; Colorado SB 26-189 developer-documentation evidence
  sessions/            # Session transcript adapters (adapters.py)
  checks/, sanitizers/ # Shared check helpers; input sanitization
  output/              # Report formatters
    console.py, json_report.py, sarif.py, owasp_report.py, compliance.py
    crosswalk.py, coverage_map.py, pdf_report.py, pr_summary.py, sbom.py, vex.py (OpenVEX), aicm.py
  proxy/
    interceptor.py     # MCP proxy interceptor
  ide/, parity/, translators/, integrations/, presets/, remediation/, corpus/, sarif/
  data/                # Static data files (YAML configs, rule metadata)
tests/                 # pytest suite, fixtures-based
  conftest.py          # Shared fixtures (tmp_project, vulnerable_mcp_project, clean_mcp_project, project_with_secrets, ...)
  fixtures/            # Test fixture files (JSON configs, env files); fixtures/cves is intentionally vulnerable input, excluded from ruff
scripts/               # check_counts.py, sync_rule_count.py, sync_scanner_count.py, check_report_figures.py, cve_latency.py, ...
rules.json, scanners.json          # Generated exports (sync_rule_count.py / sync_scanner_count.py); scanners.json states the scanner-count invariant
remediation-key-corpus.json        # Generated by `make remediation-corpus`
.github/workflows/     # ci.yml (test + counts jobs), release.yml (gates), sync-rule-count.yml (auto-commits counts), registry-parity.yml (daily), cve-watcher.yml, self-scan.yml, ...
docs/                  # MkDocs documentation site
examples/              # Example projects + case studies (incl. an intentional findings.sarif)
research/              # state-of-mcp-2026 report (regenerated by `make report`)
benchmarks/            # Benchmark crawler + false_positive/ (benign-slice FP benchmark, human-adjudicated)
launch/, releases/     # Dated launch notes and release collateral (count-guard exempt)
public/, site/         # Generated coverage/marketing pages
schema/, editors/, ci/ # JSON schema, editor integrations, CI helpers
vscode-extension/      # VS Code extension (TypeScript) — separate subtree, has its own CLAUDE.md
```

**Data flow**: CLI (cli.py) → engine.run_scan() → scanner registry → each scanner's `scan(project_root)` → `list[Finding]` → composition suppression → scoring → output formatter

**Scanner contract**: Every scanner module exports `scan(project_root: Path, ...) -> tuple[list[Finding], set[str]]` where the tuple is **(findings, scanned file paths relative to `project_root`)**. This line used to say `evaluated_rule_ids`, which is wrong and is the kind of wrong that costs an afternoon: `engine.run_scan` does `all_scanned_files.update(files)` and reports `len(all_scanned_files)` as `files_scanned`, so a scanner that returned rule ids would inflate the file count with rule-id strings. `rules_evaluated` is computed separately, from the active rule set, and no scanner contributes to it.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- **Python 3.9+** (`requires-python = ">=3.9"`) — all files start with `from __future__ import annotations`
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_SNAKE` for constants
- **Data models**: `@dataclass` (stdlib), not Pydantic — `Finding`, `ScanResult`, `RuleDefinition`
- **Enums**: `Severity` (5 levels) and `Category` (14 members) as `enum.Enum` with custom comparison operators
- **Type hints**: On all function signatures; `Optional[X]` for nullable, `list[str]` (lowercase generic)
- **Imports**: `from __future__ import annotations` first, then stdlib, then third-party, then local
- **Optional dependencies**: lazy-import inside the module that needs them and fall back (tree-sitter in the STDIO taint path, reportlab in `pdf_report`); the default install stays dependency-light
- **Lint scope**: ruff `select = ["E4", "E7", "E9", "F"]` with `tests/fixtures/cves` excluded; mypy ignores missing imports only for `reportlab` and `sigstore`
- **CLI**: Click decorators, exit codes: 0=pass, 1=findings, 2=error (`EXIT_*` in `commands/_common.py`)
- **Tests**: pytest, fixture-based (`tmp_path`, custom fixtures in `conftest.py`); one `tests/test_<scanner>.py` per scanner is the norm, CVE-wave scanners are covered by `tests/test_cve_<id>.py`
- **Error handling**: a scanner that fails to import is skipped, unless `run_scan(strict_loading=True)`, which raises `ScannerLoadError`
- **Docstrings**: Google-style with Args/Returns sections where present; long "why" docstrings on guards and post-filters are the house style, keep them

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Scanner registry**: `engine._build_registry()` is the always-on core (`mcp_config`, `hook_injection`, `trust_boundary`, `secret_exposure`, `supply_chain`) plus one loop over the `_OPTIONAL_SCANNERS` table of `(module, display_name, kwargs_keys)` tuples. Adding a scanner is one tuple in that table. The registry is cached per `strict_loading` mode (`reset_registry()` for tests that toggle it).
- **Rule registry**: `rules/builtin.py` defines all 362 rules as `RuleDefinition` dataclasses in a global `RULES` dict, populated by `_r()` helper. Scanners never copy rule metadata: `scanners/_helpers.make_finding(rule_id, ...)` pulls title/severity/category/remediation/references from the registry.
- **Composition suppression**: `run_scan` post-filters `Category.COMPOSITION` findings on the assembled list — a chain is dropped only when every component already carries a non-composition finding at or above the chain's own severity (presence alone would suppress everything, since `AAK-MCP-ATTEST-001` fires on nearly every config). Keys come from `composition.covering_keys` / `suppression_keys`.
- **Counts are generated, never hand-typed**: `agent_audit_kit/__init__.py` holds `RULE_COUNT` / `SCANNER_COUNT`; `scripts/sync_rule_count.py` and `scripts/sync_scanner_count.py` regenerate them. `scripts/check_counts.py` (`make count-check`) fails if any tracked `*.md` — **including this file** — carries a stale count. Regenerate; do not hand-fix. Dated/historical docs are exempted via the exclusion list in `check_counts.py`.
- **The guard is phrase-based, not number-based**: `check_counts.py` only checks counts written in one of its `PATTERNS` phrasings (`"N rules across"`, `"N scanner modules"`, `"N registered scanners"`, `"N CLI commands"`, `"entry point (N commands)"`, ...). A count phrased any other way is never looked at and rots silently while `make count-check` reports clean — the `registered scanners` line in this file sat at a stale value for exactly that reason until its pattern was added, and the `cli.py` line later did the same with `26 commands:` because the colon defeats the `entry point (N commands)` pattern. When prose needs a new count phrasing, reuse a guarded one or add it to `PATTERNS` in `scripts/check_counts.py`; that tuple is the single source, and `tests/test_rule_count_sync.py` imports `find_stale_counts()` rather than mirroring it.
- **Count invariants under test**: `tests/test_repo_metadata_sync.py` asserts `SCANNER_COUNT` equals the real `engine._build_registry()` size, so the scanner constant tracks the registry, not the file count in `scanners/`.
- **Generate + `-check` twin**: every derived artifact (results.json, the FP benchmark, cve-latency.md, the remediation corpus, the counts, the coverage page) has a regenerator and a `--check` that CI runs. The repo's stated rule, from `check_counts.py`: *when a surface rots because nothing looked at it, make something look.*
- **Finding model**: All scanners produce `Finding` dataclasses with rule_id, severity, category, evidence, remediation, and framework references (OWASP MCP/Agentic/AST, CVE, Adversa, incident, AICM).
- **Scoring**: Penalty-based (start at 100, deduct per severity), clamped to [0,100], mapped to letter grade.
- **Output formatters**: Each module in `output/` takes a `ScanResult` and formats it (console, JSON, SARIF, OWASP, compliance, crosswalk, SBOM, OpenVEX, PDF, PR summary).
- **GitHub Action**: `action.yml` at root wraps the CLI for CI/CD integration with SARIF upload.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

- **Recent focus**: compliance packs as first-class features (EU AI Act Art. 50 transparency, Colorado SB 26-189 ADMT developer documentation), an OpenVEX document beside the SBOM, draining CVE waves (`fix(cve):`, per-wave PRs), extracting `scan` out of `cli.py` into `commands/`, the README/docs rewrite, and relicensing MIT → Apache-2.0 (`chore!:`). Versions moved from the 0.3.x line to 0.6.x in the same stretch.
- **Commit style**: Conventional commits — last 100 at time of writing: `chore` 39, `fix` 33, `feat` 8, `docs` 8, `refactor` 2, `test` 1, plus 9 long-form PR titles for substantive changes. This is a rolling window and drifts on every commit; `scripts/check_counts.py` cannot guard it, because a canonical entry derived from `git log` would fail `make count-check` on every commit. Recompute rather than trusting it.
- **Release discipline**: counts land via generated `chore(rule-count): auto-sync` commits; release jobs fail fast on a stale GitHub description, a bad docs URL, an open `cve-response` issue, a `cve-deferred` issue with no target date, or a derivable count that drifted. `registry-parity` runs daily because "declared version exists on PyPI" is time-based and a push-only gate cannot see it.
- **Branch strategy**: Single `main` branch, PR-based workflow — merged subjects carry the PR number (`… (#725)`). Topic branches follow `feat/`, `fix/`, `chore/`, `docs/`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: best-practices -->
## Best Practices

From the Claude Code memory docs (`code.claude.com/docs/en/memory`), applied to this repo:

- Target under 200 lines per CLAUDE.md; longer files reduce adherence. Move single-area detail into the nested files (`agent_audit_kit/scanners/CLAUDE.md`, `vscode-extension/CLAUDE.md`), which load on demand only when files in those directories are read.
- Write instructions concrete enough to verify — "run `make count-check` before committing prose with a number in it", not "keep docs accurate".
- Add to CLAUDE.md when the same correction is typed twice, when a review catches something Claude should have known, or when a new teammate would need the context; leave derivable facts (file lists, dependency lists) to the code.
- Keep root and nested files consistent — contradictory rules get picked arbitrarily. The count guard is the enforcement layer for numbers; CLAUDE.md is context, not enforcement, so anything that must happen at a fixed point belongs in a hook.
- HTML comments, including the AUTO-MANAGED markers here, are stripped before injection and cost no context. `@path` imports load at launch (max four hops); a path in backticks is text, not an import.
- Root CLAUDE.md survives `/compact`; nested files reload as their directories are read. Run `/context` to confirm what loaded.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

Add project-specific notes, decisions, and context here. This section is never auto-modified.

<!-- END MANUAL -->
