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
- Zero cloud dependencies — a default scan is fully offline; network use is opt-in (e.g. `--llm-scan`, `update`, `watch-cve`, `corpus`, `notify`). The only declared extra is `taint` (tree-sitter), lazy-imported with a heuristic fallback; `reportlab` (PDF output) and `sigstore` (bundle signature verification) are undeclared lazy imports that degrade when absent
- **License**: Apache-2.0 (relicensed from MIT)

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

`Makefile` is the task runner — prefer it over raw commands, since most targets
are drift guards that CI also runs. Every generated artifact has a `-check` twin.

```bash
# Core
make test                # python -m pytest -q
make lint                # ruff check . (CI lints only agent_audit_kit/ and tests/); rule set pinned to E4,E7,E9,F in pyproject, widen it deliberately, never via a ruff bump
make typecheck           # mypy agent_audit_kit (CI adds --ignore-missing-imports, so this local run is the stricter one)

# Drift guards (CI's `counts` job: count-check, report-figures-check, sync_scanner_count.py --check, build_coverage_page.py --check)
make count-check         # check_counts.py + sync_rule_count.py --check + sync_rule_doc_pages.py --check: no stale count in ANY tracked *.md (incl. this file)
make report-check        # results.json byte-identical to a fresh run
make report-pdf-check    # the report PDF's source stamp matches results.json (a stamp, not a byte-diff: reportlab embeds a CreationDate); pytest asserts it too
make report-figures-check # every governed report figure in prose sits inside a `report:` marker
make fp-check            # FP benchmark artifacts (slice, results, badge) not stale, and every count, % and CI in RESULTS.md outside ## History matches results.json
make cve-latency-check   # docs/cve-latency.md matches the CVE ledger (runs on tag)
make remediation-corpus-check # remediation-key-corpus.json matches benchmarks/data

# Regenerate (offline, deterministic)
make report              # results.json from the committed corpus manifest, then the report PDF, which needs reportlab (no extra installs it; exits 1 without it)
make report-pdf          # re-render only the PDF from the committed results.json
make fp                  # re-measure the benign-slice FP benchmark; adjudication.json is HUMAN judgement, never regenerated
make cve-latency         # docs/cve-latency.md from the ledger
make remediation-corpus  # remediation-key-corpus.json
make repo-description    # render the GitHub "About" text from RULE_COUNT (paste into Settings > About; not writable from CI)

# Network steps (kept separate from the offline targets on purpose)
make corpus              # refresh the MCP Registry corpus manifest
make cve-latency-refresh # top up docs/data/cve-published.json from NVD
make cve-latency-queue-check # published open-queue row vs the live tracker; runs on the daily CVE cron, deliberately never a release gate
make registry-parity     # does the declared version exist on PyPI? (also daily in CI)
make cve-deferral-check  # every `cve-deferred` issue names a target date (needs gh)

# Install (editable) — [dev] pulls the optional [taint] extra (tree-sitter data-flow path tested, not just its fallback) and MkDocs (docs-hook tests run, not skip)
pip install -e ".[dev]"

# Run the CLI — `aak` is an installed alias for `agent-audit-kit` (same entry point)
aak scan .
aak discover .
aak score .

# Narrower than the make targets
python3 -m pytest tests/test_cli.py -x   # one file, stop on first failure
ruff check --fix .                       # auto-fix lint
python3 -m py_compile agent_audit_kit/<file>.py   # syntax-check one file

# Build / package
python3 -m build                     # build wheel + sdist (hatchling); the wheel excludes **/CLAUDE.md
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
  llm_scan.py          # Opt-in LLM analysis of tool descriptions (`scan --llm-scan`: Anthropic/OpenAI/Gemini APIs or local Ollama)
  vuln_db.py, advisories.py, feeds/, watch.py   # CVE DB, advisories, live feeds, watch/watch-cve
  coverage.py, bundle.py         # `aak coverage` of external manifests (OX-disclosed CVEs, Prisma AIRS); rule-bundle export + optional sigstore verify
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
  checks/, sanitizers/ # Runtime guards shipped to users, each paired with a rule (e.g. checks/openclaw.py ↔ AAK-OPENCLAW-PRIVESC-001); not scanner helpers
  output/              # Report formatters
    console.py, json_report.py, sarif.py, owasp_report.py, compliance.py
    crosswalk.py, coverage_map.py, pdf_report.py, pr_summary.py, sbom.py, vex.py (OpenVEX), aicm.py
  proxy/
    interceptor.py     # MCP proxy interceptor
  ide/ (LSP diagnostics + stdio LSP server), parity/ (runtime parity-check decorator), translators/ (Pipelock → AAK policy), integrations/ (notify sinks)
  presets/ (curated rule-id bundles), remediation/ (SARIF → PR-body hints), corpus/ (digest-pinned IPI/FHI payload refresh), sarif/ (baseline diff, fingerprints)
  data/                # Static data (vuln_db.json, AIVSS defaults, composition boundaries, toxic-flow pairs, payload corpora, Prisma AIRS maps); rule metadata lives in rules/builtin.py
tests/                 # pytest suite, fixtures-based
  conftest.py          # Shared fixtures (tmp_project, vulnerable_mcp_project, clean_mcp_project, project_with_secrets, ...)
  fixtures/            # Test fixture files (JSON configs, env files); fixtures/cves is intentionally vulnerable input, excluded from ruff
scripts/               # check_counts.py, sync_rule_count.py, sync_scanner_count.py, check_report_figures.py, cve_latency.py, render_report_pdf.py, nav_liveness.py, mkdocs_hooks.py, ...
rules.json, scanners.json          # Generated exports (sync_rule_count.py / sync_scanner_count.py); scanners.json states the scanner-count invariant
remediation-key-corpus.json        # Generated by `make remediation-corpus`
.github/workflows/     # ci.yml (test + counts jobs), release.yml (gates), sync-rule-count.yml + coverage-page.yml (bot commits), registry-parity.yml (daily), link-check.yml (lychee + daily nav liveness), mcp-security-index.yml (deploys the docs site to gh-pages), cve-watcher.yml, self-scan.yml, ...
docs/                  # MkDocs site, served under gh-pages /docs/; scripts/mkdocs_hooks.py publishes research/state-of-mcp-2026/ at build time rather than copying it into docs/
examples/              # Example projects + case studies (the committed case-studies/damn-vulnerable-mcp/scan-results.sarif is intentional)
research/              # state-of-mcp-2026 report: results.json + the PDF, stamped (.pdf.source.sha256) with the results.json it was built from; both regenerated by `make report`
benchmarks/            # Benchmark crawler + false_positive/ (benign-slice FP benchmark, human-adjudicated)
launch/, releases/     # Launch notes and per-version release notes; releases/ is count-guard exempt, launch/ only for the files named in EXCLUDE_EXACT
public/, site/         # Generated: JSON badges, corpus manifest and OWASP coverage (public/); the coverage page (site/coverage/, a nightly bot commit)
schema/, editors/, ci/ # JSON schema, editor integrations, CI helpers
vscode-extension/      # VS Code extension (TypeScript) — separate subtree, has its own CLAUDE.md
```

**Data flow**: CLI (cli.py) → engine.run_scan() → scanner registry → each scanner's `scan(project_root)` → `list[Finding]` → composition suppression → scoring → output formatter

**Scanner contract**: Every scanner module exports `scan(project_root: Path, ...) -> tuple[list[Finding], set[str]]` where the tuple is **(findings, scanned file paths relative to `project_root`)**. This line used to say `evaluated_rule_ids`, which is wrong and is the kind of wrong that costs an afternoon: `engine.run_scan` does `all_scanned_files.update(files)` and reports `len(all_scanned_files)` as `files_scanned`, so a scanner that returned rule ids would inflate the file count with rule-id strings. `rules_evaluated` is computed separately, from the active rule set, and no scanner contributes to it.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- **Python 3.9+** (`requires-python = ">=3.9"`, CI matrix 3.9–3.12) — every module with code starts with `from __future__ import annotations`
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_SNAKE` for constants
- **Data models**: `@dataclass` (stdlib), not Pydantic — `Finding`, `ScanResult`, `RuleDefinition`
- **Enums**: `Severity` (CRITICAL…INFO, with custom comparison operators) and `Category` (14 members), both `enum.Enum`
- **Type hints**: On all function signatures; `X | None` (not `Optional[X]`) and lowercase generics (`list[str]`). On 3.9, `X | None` is legal only inside annotations (courtesy of the future import), so keep it out of runtime expressions such as `isinstance` checks or type aliases
- **Imports**: `from __future__ import annotations` first, then stdlib, then third-party, then local
- **Optional dependencies**: lazy-import inside the module that needs them and fall back (tree-sitter in the STDIO taint path, reportlab in `pdf_report`, sigstore in `bundle`); the default install stays dependency-light
- **Lint scope**: ruff `select = ["E4", "E7", "E9", "F"]` with `tests/fixtures/cves` excluded; pyproject's mypy config waives missing imports only for `reportlab` and `sigstore` (CI's `--ignore-missing-imports` is broader)
- **CLI**: Click decorators, exit codes: 0=pass, 1=findings, 2=error (`EXIT_*` in `commands/_common.py`)
- **Tests**: pytest, fixture-based (`tmp_path`, custom fixtures in `conftest.py`); one `tests/test_<scanner>.py` per scanner is the norm, CVE-wave scanners are covered by `tests/test_cve_<id>.py`
- **Error handling**: a scanner that fails to import is skipped, unless `run_scan(strict_loading=True)`, which raises `ScannerLoadError`. One that raises inside `scan()` becomes an INFO `AAK-INTERNAL-SCANNER-FAIL` finding (kept through `--rules` filters and severity floors), and `aak scan` then exits 1 as INCOMPLETE unless `--allow-scanner-failure` (#743)
- **Docstrings**: Google-style with Args/Returns sections where present; long "why" docstrings on guards and post-filters are the house style, keep them

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Scanner registry**: `engine._build_registry()` is the always-on core (`mcp_config`, `hook_injection`, `trust_boundary`, `secret_exposure`, `supply_chain`) plus one loop over the `_OPTIONAL_SCANNERS` table of `(module, display_name, kwargs_keys)` tuples. Adding a scanner is one tuple in that table. The registry is cached per `strict_loading` mode (`reset_registry()` for tests that toggle it).
- **Rule registry**: `rules/builtin.py` defines all 362 rules as `RuleDefinition` dataclasses in a global `RULES` dict, populated by `_r()` helper. Scanners never copy rule metadata: `scanners/_helpers.make_finding(rule_id, ...)` pulls title/severity/category/remediation/references from the registry.
- **Composition suppression**: `run_scan` post-filters `Category.COMPOSITION` findings on the assembled list — a chain is dropped only when every component already carries a non-composition finding at or above the chain's own severity (presence alone would suppress everything, since `AAK-MCP-ATTEST-001` fires on nearly every config). Keys come from `composition.covering_keys` / `suppression_keys`.
- **Counts are generated, never hand-typed**: `agent_audit_kit/__init__.py` holds `RULE_COUNT` / `SCANNER_COUNT`; `scripts/sync_rule_count.py` and `scripts/sync_scanner_count.py` regenerate them. `scripts/check_counts.py` (`make count-check`) fails if any tracked `*.md` — **including this file** — carries a stale count. Regenerate; do not hand-fix. Dated docs are exempt by name (`EXCLUDE_EXACT` / `EXCLUDE_PREFIX`) or by an in-file dated banner (`HISTORICAL_BANNER_RE`), and `funding.json` is checked too (`EXTRA_TRACKED_FILES`).
- **The guard is phrase-based, not number-based**: `check_counts.py` only checks counts written in one of its `PATTERNS` phrasings (`"N rules across"`, `"N scanner modules"`, `"N registered scanners"`, `"N CLI commands"`, `"entry point (N commands)"`, ...). A count phrased any other way is never looked at and rots silently while `make count-check` reports clean — the `registered scanners` line in this file sat at a stale value for exactly that reason until its pattern was added, and the `cli.py` line later did the same with `26 commands:` because the colon defeats the `entry point (N commands)` pattern. When prose needs a new count phrasing, reuse a guarded one or add it to `PATTERNS` in `scripts/check_counts.py`; that tuple is the single source, and `tests/test_rule_count_sync.py` imports `find_stale_counts()` rather than mirroring it. README.md and `docs/**` also get a phrase-blind corroboration sweep for `<n> rules` / `<n> scanners`; this file does not, so `PATTERNS` is its only guard.
- **Count invariants under test**: `tests/test_repo_metadata_sync.py` asserts `SCANNER_COUNT` equals the real `engine._build_registry()` size, so the scanner constant tracks the registry, not the file count in `scanners/`.
- **Generate + `-check` twin**: every derived artifact (results.json, the report PDF, the FP benchmark, cve-latency.md, the remediation corpus, the counts, the coverage page) has a regenerator and a `--check` that CI runs. The repo's stated rule, from `check_counts.py`: *when a surface rots because nothing looked at it, make something look.*
- **Two framework tables**: `aak report --framework` (PDF) reads `output/pdf_report._FRAMEWORK_TITLES`, the table `check_counts.py` counts, and its hand-written `click.Choice` lists every key plus `standards-crosswalk` (a static mapping, no scan). `aak scan --compliance` (console) reads `output/compliance.FRAMEWORKS`, a smaller table without the regional and EU Art. 50/55 packs but with `mcp-2026-roadmap`.
- **Finding model**: All scanners produce `Finding` dataclasses with rule_id, severity, category, evidence, remediation, and framework references (OWASP MCP/Agentic/AST, CVE, Adversa, incident, AICM).
- **Scoring**: Penalty-based (start at 100, deduct per severity), clamped to [0,100], mapped to letter grade.
- **Output formatters**: Each module in `output/` takes a `ScanResult` and formats it (console, JSON, SARIF, OWASP, compliance, crosswalk, SBOM, OpenVEX, PDF, PR summary).
- **GitHub Action**: `action.yml` at root wraps the CLI and writes SARIF (the `sarif-file` output) but does not upload it; callers add `github/codeql-action/upload-sarif` with `security-events: write`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

- **Recent focus**: precision and checkable published numbers over new detections. Rules re-tuned for false positives (AAK-AGENT-002 lowered to LOW beside a new HIGH rule for fetch-and-follow links; AAK-AGENT-005 no longer flags Indic/Arabic joiners, emoji ZWJ or a leading BOM; two pin false positives), a crashed scanner now fails the scan (#743), and published figures gained checkers (the open CVE queue on the latency page, the report PDF stamped and served from the docs site, daily nav liveness, the framework count). CVE disclosures are dispositioned in batch PRs (`chore(cve): disposition #A to #B`). Before that: the EU AI Act Art. 50 and Colorado ADMT packs, OpenVEX beside the SBOM, `scan` extracted into `commands/`, the README/docs rewrite, and MIT → Apache-2.0 (`chore!:`).
- **Commit style**: Conventional commits; `chore` and `fix` dominate, then `feat`/`docs`/`refactor`, and multi-part changes land under long-form PR titles instead (`Drain the …`, `Publish the …`). Most `chore` commits are bots (`aak-bot`'s nightly `chore: refresh public coverage page`, `agent-audit-kit-bot`'s rule-count syncs, dependabot), so read history for intent with `git log --perl-regexp --author='^(?!aak-bot|agent-audit-kit-bot|dependabot)'`. No tally here: a rolling window drifts on every commit and `check_counts.py` cannot guard it.
- **Release discipline**: counts land via generated `chore(rule-count): auto-sync after rules.json change` commits. In `release.yml`, publishing (`pypi`, `docker`, `bundle-and-sign`) needs only `test` (lint, mypy, pytest, `check_counts.py`, a self-scan) and `cve-response-gate`, which fails on any open `cve-response` issue not labelled `cve-deferred` and on any `cve-deferred` issue without a target date. `description-liveness`, `count-liveness` and `cve-latency` turn the run red but gate nothing. Time-based checks run on crons instead: `registry-parity` daily (declared version on PyPI), nav liveness daily in `link-check.yml`, and `--check-queue` on the CVE cron (a published number must not gate a release).
- **Branch strategy**: Single `main` branch, PR-based workflow — merged subjects carry the PR number (`… (#725)`). Topic branches follow `feat/`, `fix/`, `chore/`, `docs/`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: best-practices -->
## Best Practices

From the Claude Code memory docs (`code.claude.com/docs/en/memory`), applied to this repo:

- Target under 200 lines per CLAUDE.md; longer files reduce adherence. Move single-area detail into the nested files (`agent_audit_kit/scanners/CLAUDE.md`, `vscode-extension/CLAUDE.md`), which load on demand only when files in those directories are read.
- Write instructions concrete enough to verify — "run `make count-check` before committing prose with a number in it", not "keep docs accurate".
- Add to CLAUDE.md when the same correction is typed twice, when a review catches something Claude should have known, or when a new teammate would need the context; leave derivable facts (file lists, dependency lists) to the code.
- Keep root and nested files consistent — contradictory rules get picked arbitrarily. The count guard is the enforcement layer for numbers; CLAUDE.md is context, not enforcement, so anything that must happen at a fixed point belongs in a hook.
- Block-level HTML comments, including the AUTO-MANAGED markers here, are stripped before injection and cost no context. `@path` imports load at launch (max four hops); a path in backticks is text, not an import.
- Root CLAUDE.md survives `/compact`; nested files reload as their directories are read. Run `/context` to confirm what loaded.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

Add project-specific notes, decisions, and context here. This section is never auto-modified.

<!-- END MANUAL -->
