# AgentAuditKit

<!-- AUTO-MANAGED: project-description -->
## Overview

**AgentAuditKit** (version tracked in `pyproject.toml` / `agent_audit_kit.__version__`) — Security scanner for MCP-connected AI agent pipelines. The "npm audit" for AI agents.

- **383 rules** across 14 security categories
- **104 scanner modules** including AST-based Python taint analysis plus regex dangerous-sink pattern scanners for TypeScript/JavaScript and Rust (pattern matching, not taint flow)
- **27 CLI commands**: `scan`, `discover`, `pin`, `verify`, `fix`, `score`, `update`, `proxy`, `kill`, `diff`, `suggest`, `watch`, `watch-cve`, `notify`, `install-precommit`, `export-rules`, `verify-bundle`, `sbom`, `vex`, `report`, `coverage`, `inspect-ide`, `parity`, `corpus`, `pipelock`, `rule`, `scanners`
- **OWASP coverage**: Agentic Top 10 (10/10), MCP Top 10 (10/10); rules also carry Adversa AI MCP Top 25 references, as AAK-defined `ADV-*` ids (`output/owasp_report.ADVERSA_TOP_25`)
- **Compliance mapping** (14 frameworks): EU AI Act (incl. Art. 50 transparency and Art. 55 packs), SOC 2, ISO 27001/42001, HIPAA, NIST AI RMF, NSA MCP CSI, + regional (India DPDP, Singapore, Alabama, Tennessee, Colorado SB 26-189 ADMT); EU AI Act Art. 50 in force 2026-08-02
- **10 agent platforms** enumerated by `discover` (`discovery.AGENT_CONFIGS`)
- Zero cloud dependencies — a default scan is fully offline; network use is opt-in (e.g. `--llm-scan`, `update`, `watch-cve`, `corpus`, `notify`). The runtime extras are `taint` (tree-sitter, with a heuristic fallback) and `verify` (sigstore, for `verify-bundle --signature`), both lazy-imported; `reportlab` (PDF output) is an undeclared lazy import that degrades when absent
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
make count-check         # check_counts.py (prose counts in ANY tracked *.md, incl. this file) + sync_rule_count.py --check (badge, anchors, generated docs) + sync_rule_doc_pages.py --check (the SARIF helpUri deep-link set); then render_repo_metadata.py --check-live, which fails when the live GitHub description differs (a RULE_COUNT change stays red until the About is updated) and prints "not compared" but passes when gh cannot read it, as in CI's tokenless counts job
make report-check        # results.json byte-identical to a fresh run
make report-pdf-check    # the report PDF's source stamp matches results.json (a stamp, not a byte-diff: reportlab embeds a CreationDate); pytest asserts it too
make report-figures-check # every governed report figure in prose sits inside a `report:` marker
make fp-check            # FP benchmark artifacts (slice, results, badge) not stale, and every "N HIGH/CRITICAL" count, % and [a%, b%] interval in RESULTS.md outside ## History matches results.json/adjudication.json
make cve-latency-check   # docs/cve-latency.md matches the CVE ledger, offline (pytest asserts it every run; release.yml re-runs it on tag)
make remediation-corpus-check # remediation-key-corpus.json matches benchmarks/data

# Regenerate (offline, deterministic)
make report              # results.json from the local benchmarks/data crawl (gitignored) + the committed registry manifest, then the report PDF, which needs reportlab (no extra installs it; exits 1 without it)
make report-pdf          # re-render only the PDF from the committed results.json
make fp                  # re-measure the benign-slice FP benchmark; adjudication.json is HUMAN judgement, never regenerated
make remediation-corpus  # remediation-key-corpus.json
make repo-description    # render the GitHub "About" text from RULE_COUNT (paste into Settings > About; not writable from CI)
python scripts/sync_rule_count.py --regenerate && python scripts/sync_scanner_count.py   # after a rule/scanner change: rebuild rules.json, then every generated count surface (sync-rule-count.yml runs the same; without --regenerate the stale rules.json is re-read)

# Network steps (kept separate from the offline targets on purpose)
make corpus              # refresh the MCP Registry corpus manifest
make cve-latency         # docs/cve-latency.md from the ledger; its open-queue row reads the live tracker via gh (read=no without it), so render a fixed queue with scripts/cve_latency.py --issues-json FILE
make cve-latency-refresh # top up docs/data/cve-published.json from NVD
make cve-latency-queue-check # published open-queue row vs the live tracker; runs on the daily CVE cron, deliberately never a release gate
make registry-parity     # does the declared version exist on PyPI? (also daily in CI)
make cve-deferral-check  # every `cve-deferred` issue names a target date (needs gh)

# Install (editable) — [dev] pulls the optional [taint] and [verify] extras (tree-sitter data-flow path and a real release signature tested, not just their fallbacks) and MkDocs (docs-hook tests run, not skip)
pip install -e ".[dev]"

# Run the CLI — `aak` is an installed alias for `agent-audit-kit` (same entry point)
aak scan .
aak discover             # no PATH: it inventories agent configs on this machine (a path argument exits 2)
aak score .

# Narrower than the make targets
python3 -m pytest tests/test_cli.py -x   # one file, stop on first failure
ruff check --fix .                       # auto-fix lint
python3 -m py_compile agent_audit_kit/<file>.py   # syntax-check one file

# Build / package
python3 -m build                     # wheel + sdist (hatchling); needs `pip install build`, which [dev] lacks; the wheel excludes **/CLAUDE.md
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
  models.py            # Finding (rule_id, severity, category, evidence, remediation + OWASP MCP/Agentic/AST, CVE, Adversa, incident, AICM refs) and ScanResult dataclasses; Severity, Category enums
  scoring/             # Penalty-based score (100 minus per-severity deductions, clamped to [0,100], mapped to a letter grade); aivss.py = AIVSS vector scoring
  discovery.py         # Agent platform discovery (AGENT_CONFIGS)
  pinning.py           # SHA-256 pins of MCP tool definitions behind `pin`/`verify`; scanners/pin_drift.py and watch.py reuse verify_pins
  verification.py      # `scan --verify-secrets`: probes provider APIs to check whether AAK-SECRET-* keys are live (network)
  fix.py, autofix/               # Auto-fix engine and per-rule strategies
  autopr.py            # Draft-PR delivery for mechanical fixes via the `gh` CLI (never handles tokens)
  diff.py              # `scan --diff REF`: drops findings outside git-changed files (`aak diff` is sarif/diff.py)
  llm_scan.py          # Opt-in LLM analysis of tool descriptions (`scan --llm-scan`: Anthropic/OpenAI/Gemini APIs or local Ollama)
  vuln_db.py, advisories.py, feeds/, watch.py   # CVE DB, advisories, live feeds, watch/watch-cve
  coverage.py, bundle.py         # OX CVE manifest behind `aak coverage --source ox` (prisma-airs is translators/prisma_airs.py); rule-bundle export + optional sigstore verify
  rules/
    builtin.py         # 383 RuleDefinition entries (rule registry); `get_rule(rule_id)` is the lookup
  scanners/            # 104 registered scanners (106 .py files on disk besides `__init__` and the `_`-prefixed helpers — the registry is authoritative; the surplus is the two back-compat shims rust_scan/typescript_scan). Has its own CLAUDE.md, which covers the layout.
    _helpers.py        # make_finding(rule_id, file_path, evidence, line_number) builds a Finding from the registry; SKIP_DIRS; INTERPOLATION_RE
    agent_config.py    # AAK-AGENT-* on root instruction files (AGENTS.md, CLAUDE.md, .cursorrules, ...); 005 exempts only the auto-memory plugin's own section markers, so renaming a section in this file makes it fire
    taint_analysis.py  # Python taint flow (AST source→sink); typescript_pattern_scan.py and rust_pattern_scan.py are regex sink patterns, not taint flow
    tool_poisoning.py  # Tool-description poisoning (AAK-POISON-*); rug-pull drift against pins is pin_drift.py (AAK-RUGPULL-*)
    composition.py     # Capability-graph chains (AAK-COMPOSE-*, Category.COMPOSITION) + the suppression keys run_scan uses
    legal_compliance.py    # Dependency licence/DMCA risk (AAK-LEGAL-*), not framework mapping; the regulatory packs are eu_ai_act_art50.py (Art. 50 transparency) and admt_documentation.py (Colorado SB 26-189)
  sessions/            # Session transcript adapters (adapters.py)
  checks/, sanitizers/ # Runtime guards shipped to users, each paired with a rule (e.g. checks/openclaw.py ↔ AAK-OPENCLAW-PRIVESC-001); not scanner helpers
  output/              # Report formatters; _rule_doc_pages.py is GENERATED by sync_rule_doc_pages.py (which rules' SARIF helpUri deep-links)
    console.py, json_report.py (its camelCase keys are the VS Code extension's input, pinned by tests/test_vscode_json_contract.py), sarif.py, owasp_report.py, compliance.py
    crosswalk.py, coverage_map.py, pdf_report.py, pr_summary.py, sbom.py, vex.py (OpenVEX), aicm.py
  proxy/
    interceptor.py     # MCP proxy interceptor
  ide/ (LSP diagnostics + stdio LSP server), parity/ (runtime parity-check decorator), translators/ (Pipelock policy → AAK config; Prisma AIRS coverage map), integrations/ (notify sinks)
  presets/ (curated rule-id bundles), remediation/ (SARIF → PR-body hints), corpus/ (digest-pinned IPI/FHI payload refresh), sarif/ (baseline diff, fingerprints)
  data/                # Static data (vuln_db.json, the OX CVE manifest, AIVSS defaults, composition boundaries, toxic-flow pairs, payload corpora, Prisma AIRS maps); rule metadata lives in rules/builtin.py
tests/                 # pytest suite, fixtures-based
  conftest.py          # Shared fixtures (tmp_project, vulnerable_mcp_project, clean_mcp_project, project_with_secrets, ...)
  fixtures/            # Per-feature fixture trees; fixtures/cves/<cve>/{vulnerable,negative} is intentionally vulnerable input, excluded from ruff
scripts/               # check_counts.py, sync_rule_count.py, sync_scanner_count.py, check_report_figures.py, cve_latency.py, render_report_pdf.py, nav_liveness.py, mkdocs_hooks.py, ...
rules.json, scanners.json, remediation-key-corpus.json   # Generated: sync_rule_count.py --regenerate / sync_scanner_count.py / make remediation-corpus; scanners.json states the scanner-count invariant
.github/workflows/     # ci.yml (test + counts jobs), release.yml (gates), sync-rule-count.yml + coverage-page.yml (bot commits), registry-parity.yml (daily), link-check.yml (lychee + daily nav liveness), mcp-security-index.yml (deploys the docs site to gh-pages), cve-watcher.yml, self-scan.yml, ...
docs/                  # MkDocs site, served under gh-pages /docs/; scripts/mkdocs_hooks.py publishes research/state-of-mcp-2026/ at build time rather than copying it into docs/
examples/              # Example projects + case studies (the committed case-studies/damn-vulnerable-mcp/scan-results.sarif is intentional)
research/              # state-of-mcp-2026 report: results.json + the PDF, stamped (.pdf.source.sha256) with the results.json it was built from; both regenerated by `make report`
benchmarks/            # Benchmark crawler + false_positive/ (benign-slice FP benchmark, human-adjudicated)
launch/, releases/     # Launch notes; releases/ holds only legacy per-version notes (current ones are CHANGELOG.md). releases/ is count-guard exempt, launch/ only for the files named in EXCLUDE_EXACT
public/, site/         # Generated: the OX coverage badge JSON, corpus manifest and OWASP coverage (public/); the coverage page (site/coverage/, a nightly bot commit)
schema/, editors/, ci/ # OX manifest JSON schema; Zed extension; GitLab CI template
vscode-extension/      # VS Code extension (TypeScript) — separate subtree, has its own CLAUDE.md
```

**Data flow**: `aak scan` (`commands/scan.py` `_run_scan`) → `engine.run_scan()` → each registered `scan(project_root)` → `(findings, files)` → `--rules`/`ignore_paths` filter → composition suppression → back in `_run_scan`: the `--diff` filter, `--verify-secrets`, then `--llm-scan` and `--sessions` findings appended (so never suppressed) → scoring (only with `--score`/`--compliance`/`--owasp-report`) → output formatter

**Scanner contract**: Every scanner module exports `scan(project_root: Path, ...) -> tuple[list[Finding], set[str]]` where the tuple is **(findings, scanned file paths relative to `project_root`)**. This line used to say `evaluated_rule_ids`, which is wrong and is the kind of wrong that costs an afternoon: `engine.run_scan` does `all_scanned_files.update(files)` and reports `len(all_scanned_files)` as `files_scanned`, so a scanner that returned rule ids would inflate the file count with rule-id strings. `rules_evaluated` is computed separately, from the active rule set, and no scanner contributes to it.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- **Python 3.9+** (`requires-python = ">=3.9"`, CI matrix 3.9–3.12): every module with code opens with `from __future__ import annotations`, then imports stdlib, third-party, local, in that order
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_SNAKE` for constants
- **Data models**: `@dataclass` (stdlib), not Pydantic — `Finding`, `ScanResult`, `RuleDefinition`
- **Enums**: `Severity` (CRITICAL…INFO, with custom comparison operators) and `Category` (14 members), both `enum.Enum`
- **Type hints**: On all function signatures; `X | None`, never `Optional[X]` (`tests/test_no_optional_annotations.py` fails on one in `agent_audit_kit/` or `scripts/`), and lowercase generics (`list[str]`). On 3.9, `X | None` is legal only inside annotations (courtesy of the future import), so keep it out of runtime expressions such as `isinstance` checks or type aliases
- **Optional dependencies**: lazy-import inside the module that needs them and fall back (tree-sitter in the STDIO taint path, reportlab in `pdf_report`, sigstore in `bundle`); the default install stays dependency-light
- **Lint scope**: ruff `select = ["E4", "E7", "E9", "F"]` with `tests/fixtures/cves` excluded; pyproject's mypy config waives missing imports only for `reportlab` and `sigstore` (CI's `--ignore-missing-imports` is broader)
- **CLI**: Click decorators, exit codes: 0=pass, 1=findings, 2=error (`EXIT_*` in `commands/_common.py`)
- **Tests**: pytest, fixture-based (`tmp_path`, custom fixtures in `conftest.py`); a scanner's tests live in `tests/test_<module>.py`, a per-CVE `tests/test_cve_<id>.py`, or the release-wave file that introduced it (`tests/test_v0_3_<n>_rules.py`, `tests/test_cves_2026.py`), so grep the rule id
- **Error handling**: a scanner that fails to import is skipped, unless `run_scan(strict_loading=True)`, which raises `ScannerLoadError`. One that raises inside `scan()` becomes an INFO `AAK-INTERNAL-SCANNER-FAIL` finding (kept through `--rules` filters and severity floors), and `aak scan` then exits 1 as INCOMPLETE unless `--allow-scanner-failure` (#743)
- **Docstrings**: Google-style with Args/Returns sections where present; long "why" docstrings on guards and post-filters are the house style, keep them

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Scanner registry**: `engine._build_registry()` is the always-on core (`mcp_config`, `hook_injection`, `trust_boundary`, `secret_exposure`, `supply_chain`) plus one loop over the `_OPTIONAL_SCANNERS` table of `(module, display_name, kwargs_keys)` tuples. Adding a scanner is one tuple in that table. The registry is cached per `strict_loading` mode (`reset_registry()` for tests that toggle it).
- **Rule registry**: `rules/builtin.py` defines all 383 rules as `RuleDefinition` dataclasses in a global `RULES` dict, populated by `_r()` helper. `scanners/_helpers.make_finding(rule_id, ...)` pulls title/severity/category/remediation/references from the registry, so a scanner never copies rule metadata: `tests/test_findings_match_registry.py` fails on a hand-built `Finding(...)` in `scanners/` and on any emitted finding whose fields differ from `RULES` (the one sanctioned override is `ide_task_rce`'s escalated severity, via `dataclasses.replace`).
- **Composition suppression**: `run_scan` post-filters `Category.COMPOSITION` findings on the assembled list — a chain is dropped as soon as any one of its components already carries a non-composition finding at or above the chain's own severity (severity, not presence: `AAK-MCP-ATTEST-001` fires on nearly every config, so presence alone would suppress everything). Keys come from `composition.covering_keys` / `suppression_keys` (a `SKILL.md` keys on the file, an MCP server on its own line).
- **Counts: constants and surfaces generated, prose guarded**: `agent_audit_kit/__init__.py` holds `RULE_COUNT` / `SCANNER_COUNT`; `scripts/sync_rule_count.py --regenerate` and `scripts/sync_scanner_count.py` rewrite them along with the badge, `action.yml`, README anchors and `rules.json`/`scanners.json`, so never hand-edit those. Prose counts, **this file's included**, are hand-written and guarded: `scripts/check_counts.py` (`make count-check`) fails on a stale one in any tracked `*.md`, so bump it in the same PR on the line it names. `SCANNER_COUNT` is asserted equal to the live registry (`tests/test_repo_metadata_sync.py`), not the file count in `scanners/`. Dated docs are exempt by name (`EXCLUDE_EXACT` / `EXCLUDE_PREFIX`) or by an in-file dated banner (`HISTORICAL_BANNER_RE`), and `funding.json` is checked too (`EXTRA_TRACKED_FILES`).
- **The guard is phrase-based, not number-based**: `check_counts.py` only checks counts written in one of its `PATTERNS` phrasings (`"N rules across"`, `"N scanner modules"`, `"N registered scanners"`, `"N CLI commands"`, `"entry point (N commands)"`, ...). A count phrased any other way is never looked at and rots silently while `make count-check` reports clean — the `registered scanners` line in this file sat at a stale value for exactly that reason until its pattern was added, and the `cli.py` line later did the same with `26 commands:` because the colon defeats the `entry point (N commands)` pattern. When prose needs a new count phrasing, reuse a guarded one or add it to `PATTERNS` in `scripts/check_counts.py`; that tuple is the single source, and `tests/test_rule_count_sync.py` imports `find_stale_counts()` rather than mirroring it. README.md and `docs/**` also get a phrase-blind corroboration sweep for `<n> rules` / `<n> scanners`; this file does not, so `PATTERNS` is its only guard.
- **Generate + `-check` twin**: every derived artifact (results.json, the report PDF, the FP benchmark, cve-latency.md, the remediation corpus, the counts, the coverage page) has a regenerator and a `-check`, but CI enforces only some: the counts and the coverage page's figure date (`counts` job), cve-latency.md (pytest, and on tag), the PDF stamp and FP-artifact agreement (pytest). `report-check` and `remediation-corpus-check` need the gitignored `benchmarks/data` crawl and no workflow re-runs the FP benchmark, so run `report-check`, `fp-check` and `remediation-corpus-check` locally when a rule change can move them. The repo's stated rule, from `check_counts.py`: *when a surface rots because nothing looked at it, make something look.*
- **Two framework tables**: `aak report --framework` (PDF) reads `output/pdf_report._FRAMEWORK_TITLES`, the table `check_counts.py` counts, and its hand-written `click.Choice` lists every key plus `standards-crosswalk` (a static mapping, no scan). `aak scan --compliance` (console) reads `output/compliance.FRAMEWORKS`, a smaller table without the regional and EU Art. 50/55 packs but with `mcp-2026-roadmap`; `--compliance aicm` is routed to `output/aicm.py` (CSV) instead.
- **Output formatters**: the scan formatters (console, JSON, SARIF, OWASP, compliance, AICM, PDF, PR summary) take a `ScanResult`; SBOM starts from `project_root` (OpenVEX takes both), and `crosswalk` / `coverage_map` render registry-wide mappings with no scan.
- **GitHub Action**: `action.yml` at root wraps the CLI and writes SARIF (the `sarif-file` output) but does not upload it; callers add `github/codeql-action/upload-sarif` with `security-events: write`. The image's own `ENTRYPOINT` is the CLI (`docker run IMAGE scan /project`); `action.yml` selects the Action-input bridge with `runs.entrypoint: /entrypoint.sh`. Through 0.6.9 the bridge *was* the image entrypoint, so every documented `docker run` exited 2.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

- **Recent focus**: precision, and release assets that work as documented, over new detections. An outside report (#771) drove the AAK-AGENT-* rework: 006 fires on directives rather than contributor links or guardrails, and 001/003 followed it from keywords to commands and instructions (#869), 004 skips a sentence forbidding disclosure of the credential it names, findings take their line from the match offset, and a quadratic per-verb scan became fixed windows. The release assets were exercised the way a user would: the image now runs the CLI, the signed SBOM describes the package (it had listed nothing), and `verify-bundle --signature` works on sigstore 3+. Published numbers kept gaining checkers (the live repo description in count-check, bold-number counts, the FP `RESULTS.md` prose). CVE disclosures are dispositioned in batch PRs (`Disposition #A to #B …`, earlier `chore(cve): disposition #A to #B`), adding a pin or detection arm only where a fixture proves it.
- **Commit style**: Conventional commits; `chore` and `fix` dominate, then `feat`/`docs`/`refactor`, and multi-part changes land under long-form PR titles instead (`Drain the …`, `Publish the …`). Most `chore` commits are bots (`aak-bot`'s nightly `chore: refresh public coverage page`, `agent-audit-kit-bot`'s rule-count syncs, dependabot), so read history for intent with `git log --perl-regexp --author='^(?!aak-bot|agent-audit-kit-bot|dependabot)'`. No tally here: a rolling window drifts on every commit and `check_counts.py` cannot guard it.
- **Release discipline**: a count change lands in the PR that causes it; `agent-audit-kit-bot`'s `chore(rule-count): auto-sync after rules.json change` (`sync-rule-count.yml`, on push to main) only catches leftover drift. In `release.yml`, publishing (`pypi`, `docker`, `bundle-and-sign`) needs only `test` (lint, mypy, pytest, `check_counts.py`, a self-scan) and `cve-response-gate`, which fails on any open `cve-response` issue not labelled `cve-deferred` and on any `cve-deferred` issue without a target date. `description-liveness`, `count-liveness` and `cve-latency` turn the run red but gate nothing. Time-based checks run on crons instead: `registry-parity` daily (declared version on PyPI), nav liveness daily in `link-check.yml`, and `--check-queue` on the CVE cron (a published number must not gate a release). The `docker` job runs the documented `docker run` on the loaded amd64 image before pushing, then pushes amd64 and arm64 (arm64 under QEMU, #885) and runs the pushed arm64 image, so arm64 is checked only after the tags move (`docker-nightly.yml` checks both architectures after its push), and `bundle-and-sign` builds its SBOM with `scripts/release_sbom.py` from the package alone in an empty venv, not `aak sbom .` on this repo, which listed zero components through 0.6.9.
- **Branch strategy**: Single `main` branch, PR-based workflow — merged subjects carry the PR number (`… (#725)`). Topic branches follow `feat/`, `fix/`, `chore/`, `docs/`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: best-practices -->
## Best Practices

From the Claude Code memory docs (`code.claude.com/docs/en/memory`), applied to this repo:

- Target under 200 lines per CLAUDE.md; longer files reduce adherence. Move single-area detail into the nested files (`agent_audit_kit/scanners/CLAUDE.md`, `vscode-extension/CLAUDE.md`), which load on demand only when files in those directories are read.
- Write instructions concrete enough to verify — "run `make count-check` before committing prose with a number in it", not "keep docs accurate".
- Add to CLAUDE.md when Claude repeats a mistake, a review catches something it should have known, a correction gets typed a second time, or a new teammate would need the context. Keep it to facts every session needs: a multi-step procedure belongs in a skill, a rule for one part of the tree in a nested CLAUDE.md or a path-scoped `.claude/rules/` file.
- Keep root and nested files consistent — contradictory rules get picked arbitrarily; `/doctor prompt-audit` reports contradictions and references to files or commands that no longer exist. The count guard is the enforcement layer for numbers; CLAUDE.md is context, not enforcement, so anything that must happen at a fixed point belongs in a hook.
- Block-level HTML comments, including the AUTO-MANAGED markers here, are stripped before injection and cost no context. `@path` imports load at launch (max four hops); a path in backticks is text, not an import. Root CLAUDE.md survives `/compact`, nested files reload as their directories are read, and `/context` shows what loaded.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

Add project-specific notes, decisions, and context here. This section is never auto-modified.

<!-- END MANUAL -->
