# AgentAuditKit — Deep Codebase Analysis

**Version scanned:** v0.2.0
**Stack:** Python 3.9+ · Click CLI · stdlib-first (+ PyYAML) · Hatch build · GitHub Action · Docker · MkDocs
**Report date:** 2026-04-18
**Audience:** Security engineers evaluating the tool as a CI gate; maintainers planning the v0.3 release

---

## 1. Executive summary

AgentAuditKit positions itself as "npm audit for AI agents" — a static analysis tool that scans a project for MCP-connected agent misconfigurations, hook injection, tool poisoning, secret exposure, supply-chain risk, trust-boundary violations, and transport / A2A / legal-compliance gaps. It ships 9 CLI commands, 77 rules across 11 categories, 13 scanner modules, and output formats for console / JSON / SARIF (GitHub Code Scanning) / OWASP / compliance frameworks (EU AI Act, SOC 2, ISO 27001, HIPAA, NIST AI RMF).

The core design is clean: the **scanner registry** pattern in `engine.py` lazily imports each scanner and calls a uniform `scan(project_root, **kwargs) -> (findings, rule_ids)` contract. Findings and rules are modeled as stdlib `@dataclass`es. The CLI is a reasonably complete toolbox (scan, discover, pin, verify, fix, score, update, proxy, kill).

The concerns are **three breakable seams**:
1. Three `AAK-RUGPULL-*` rules are defined in the registry but never fired by any scanner — the rug-pull functionality is implemented *outside* the rule framework, inside `pinning.verify_pins`.
2. `engine.run_scan` runs scanners in a loop **without try/except**. One crash in any scanner aborts the whole scan and you lose findings from every scanner that ran before and after.
3. TypeScript and Rust "taint analysis" (`typescript_scan.py`, `rust_scan.py`) are 4 KB regex-based heuristics — they look like taint analysis to a buyer but don't carry their weight against the name.

Test coverage is the best part of the project: **31 test files, ~6,432 LOC**, and every scanner has a dedicated test file with realistic vulnerable / clean project fixtures.

---

## 2. Repository layout

```
agent-audit-kit/
├── pyproject.toml                       Hatch build, Python 3.9+, Click + PyYAML only
├── action.yml                           GitHub Action: 10 inputs, 4 outputs, Docker entrypoint
├── Dockerfile                           Image used by the GitHub Action
├── .agent-audit-kit.yml                 User config template
├── README.md, CHANGELOG.md, LICENSE
├── agent_audit_kit/                     Main package (20 modules)
│   ├── cli.py (17.9 KB)                 9 Click commands
│   ├── engine.py (4.6 KB)               Scanner registry + orchestrator
│   ├── models.py (3.3 KB)               Finding, ScanResult, Severity, Category
│   ├── scoring.py                       Penalty-based 0–100 + A–F
│   ├── discovery.py                     13 agent-platform discovery
│   ├── pinning.py                       SHA-256 tool-definition pinning
│   ├── verification.py                  Pin verification + secret verification
│   ├── fix.py                           Auto-fix engine (dry-run supported)
│   ├── diff.py                          Diff-based scanning
│   ├── llm_scan.py                      Ollama integration (optional)
│   ├── vuln_db.py                       Bundled + cached vuln DB
│   ├── rules/builtin.py (1,209 lines)   77 RuleDefinition entries
│   ├── scanners/                        13 scanner modules
│   ├── output/                          console, json_report, sarif, owasp_report, compliance
│   ├── proxy/interceptor.py             MCP proxy (JSON-RPC, port 8765)
│   └── data/vuln_db.json                Bundled vulnerability database
├── tests/                               31 test files, ~6,432 LOC
│   ├── conftest.py                      fixtures: vulnerable/clean project variants
│   └── fixtures/                        sample configs, env files, etc.
├── docs/                                MkDocs site
├── benchmarks/                          Performance crawler
├── examples/                            Sample projects
├── vscode-extension/                    Separate TypeScript extension
└── launch/                              Docker launch scripts
```

---

## 3. CLI architecture (`agent_audit_kit/cli.py`)

The nine Click commands and what each actually does:

| Command | Purpose | Notable flags | Exit |
|---|---|---|---|
| `scan` | Default — run all scanners | `--format {console,json,sarif}`, `--severity`, `--rules`, `--exclude-rules`, `--include-user-config`, `--ignore-paths`, `--fail-on`, `--config`, `--ci`, `--verbose`, `--score`, `--owasp-report`, `--compliance {eu-ai-act,soc2,iso27001,hipaa,nist-ai-rmf}`, `--verify-secrets`, `--diff <git-ref>`, `--llm-scan` | 0 pass · 1 findings over threshold · 2 error |
| `discover` | Enumerate MCP servers & hooks across 13 agent platforms | — | 0 · 2 |
| `pin` | Hash all tool definitions into `.agent-audit-kit/tool-pins.json` | — | 0 · 2 |
| `verify` | Compare current tool definitions to the pin file; report additions/removals/modifications | — | 0 pass · 1 mismatch · 2 error |
| `fix` | Auto-apply fixes for rules marked `auto_fixable=True` | `--dry-run` | 0 · 2 |
| `score` | Compute 0–100 score + A–F grade; emit SVG badge with `--badge` | — | 0 |
| `update` | Download latest `vuln_db.json` to `~/.agent-audit-kit/` | — | 0 · 2 |
| `proxy` | Start local MCP proxy server | `--port` (default 8765), `--target <url>` | blocks |
| `kill` | Terminate running proxy (reads PID from `~/.agent-audit-kit/proxy.pid`) | — | 0 |

---

## 4. Engine & scanner registry (`engine.py`)

### Pattern

```python
@dataclass
class ScannerRegistration:
    name: str
    scan_fn: ScanFn                    # (project_root, **kwargs) -> (findings, rule_ids)
    kwargs_keys: list[str]             # e.g. ["include_user_config", "ignore_paths"]
```

`_build_registry()` wraps each optional scanner import in a `try / except ImportError: pass`, which is a clean way to degrade when an optional module (A2A, legal, typescript, rust) has a bug at import time but doesn't protect against **runtime** bugs inside `scan()`.

### `run_scan` flow (lines 91–138)

1. Apply `--rules` and `--exclude-rules` as set filters.
2. For each scanner registration:
   - Build `scanner_kwargs` by intersecting `kwargs_keys` with the caller's keyword args.
   - Call `reg.scan_fn(project_root=project_root, **scanner_kwargs)`.
   - Extend findings; union `files_scanned` and `rules_evaluated`.
3. Return `ScanResult(findings, files_scanned, rules_evaluated, scan_duration_ms)`.

**⚠️ No try/except inside the loop.** A `KeyError`, `UnicodeDecodeError`, or malformed YAML in one project file can take down the entire scan. See §8 Risk 2.

---

## 5. Models (`models.py`)

- `Severity` enum — `CRITICAL(5) / HIGH(4) / MEDIUM(3) / LOW(2) / INFO(1)` with `__lt__/__le__/__gt__/__ge__` defined for numeric comparison.
- `Category` enum — 11 categories: `MCP_CONFIG`, `HOOK_INJECTION`, `TRUST_BOUNDARY`, `SECRET_EXPOSURE`, `SUPPLY_CHAIN`, `AGENT_CONFIG`, `TOOL_POISONING`, `TAINT_ANALYSIS`, `TRANSPORT_SECURITY`, `A2A_PROTOCOL`, `LEGAL_COMPLIANCE`.
- `Finding` — `rule_id, title, description, severity, category, file_path, line_number?, evidence, remediation, cve_references, owasp_mcp_references, owasp_agentic_references, adversa_references`.
- `ScanResult` — findings + files/rules sets + timing + score/grade + helpers (`critical_count`, `high_count`, …, `max_severity`, `exceeds_threshold`, `findings_at_or_above`).

---

## 6. Rule registry (`rules/builtin.py`, 1,209 lines)

Rules are registered with a `_r(...)` macro that stores a `RuleDefinition` into the module-level `RULES` dict. Verified count via `grep -c '^_r('` matches the claimed **77**.

### Distribution by category

| Prefix | Count | Coverage |
|---|---|---|
| `AAK-MCP-*` | 10 | Remote auth, shell metacharacters, env secrets, no timeouts, env exposure, command injection, untrusted URLs, path traversal, dependency confusion, pinning |
| `AAK-SECRET-*` | 9 | API keys, `.env` exposure, `.env` in git, private-key files, hardcoded secrets, cloud creds, GitHub tokens, AWS keys, service accounts |
| `AAK-HOOK-*` | 9 | Hook injection, unchecked / elevated / shell / suspicious hooks, persistence, enumeration, manipulation, exfiltration |
| `AAK-TAINT-*` | 8 | Command injection, code execution, path traversal, SSRF, LLM injection, data exfiltration, XSS, LDAP injection |
| `AAK-TRUST-*` | 7 | Trust-boundary violations, untrusted sources, privilege escalation, cross-boundary data flow |
| `AAK-A2A-*` | 7 | JSON-RPC, auth, encryption, rate limiting, input validation, trust, versioning |
| `AAK-SUPPLY-*` | 6 | Vulnerable packages, typosquatting, package confusion, install scripts |
| `AAK-POISON-*` | 6 | Capability confusion, deceptive descriptions, privilege escalation, tool confusion, malicious tools, rug pulls |
| `AAK-AGENT-*` | 5 | Exposed keys, default creds, insecure config, missing headers, version disclosure |
| `AAK-TRANSPORT-*` | 4 | Non-HTTPS, cert validation, pinning, TLS version |
| `AAK-LEGAL-*` | 3 | EU AI Act, HIPAA, SOC 2 |
| `AAK-RUGPULL-*` | 3 | ⚠️ **Dead** — defined (lines 1137–1172) but never fired by any scanner |
| **Total** | **77** | |

---

## 7. Scanner modules (13)

Each of the 13 scanners exports `scan(project_root: Path, **kwargs) -> tuple[list[Finding], set[str]]`. All 77 *live* rules are reached by at least one scanner. The dead ones are `AAK-RUGPULL-001/002/003`.

| Scanner | Size | What it does |
|---|---|---|
| `mcp_config.py` | 9.4 KB | Parses `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.continue/config.json`, and similar. Rules `AAK-MCP-001..010`. |
| `secret_exposure.py` | 11.0 KB | Regex sweep across 42 extensions (`.env`, `.json`, `.yml`, `.py`, `.js`, `.ts`, `.toml`, …) skipping `node_modules/.git/dist/build/__pycache__/venv/...`. Rules `AAK-SECRET-001..009`. |
| `hook_injection.py` | 8.4 KB | Scans `.claude/settings.json` and `.claude/settings.local.json` for shell injection / privilege escalation / persistence patterns. Rules `AAK-HOOK-001..009`. |
| `trust_boundary.py` | 5.7 KB | Cross-agent / cross-tool trust violations. Rules `AAK-TRUST-001..007`. |
| `supply_chain.py` | 19.5 KB | `package.json`, Python, Rust dependency scanning; typosquatting, preinstall/postinstall risk. Rules `AAK-SUPPLY-001..006`. |
| `agent_config.py` | 6.3 KB | Per-agent config checks (exposed keys, default creds, missing security headers, version leak). Rules `AAK-AGENT-001..005`. |
| `tool_poisoning.py` | 9.3 KB | Hidden-instruction / capability-confusion / deceptive-description detection. Rules `AAK-POISON-001..006`. |
| `taint_analysis.py` | 9.5 KB | **Python AST-based** taint tracking. Sinks include `os.system/popen`, `subprocess.run`, `eval/exec/compile`, `open/Path`, `requests/urllib`, LangChain tools. Rules `AAK-TAINT-001..008`. |
| `transport_security.py` | 5.4 KB | HTTPS enforcement, certificate validation, pinning, TLS version. Rules `AAK-TRANSPORT-001..004`. |
| `a2a_protocol.py` | 11.7 KB | JSON-RPC 2.0 validation, auth, rate limiting, versioning. Rules `AAK-A2A-001..007`. |
| `legal_compliance.py` | 5.5 KB | EU AI Act, HIPAA, SOC 2 mapping. Rules `AAK-LEGAL-001..003`. |
| `typescript_scan.py` | 4.0 KB | ⚠️ Regex-based only — no AST, thin coverage compared to the Python analyzer. |
| `rust_scan.py` | 4.4 KB | ⚠️ Regex-based only — same limitation. |

---

## 8. Scoring, formatters, discovery, pinning, proxy

### Scoring (`scoring.py`)
Base 100, deductions **-20 CRITICAL, -10 HIGH, -5 MEDIUM, -2 LOW, 0 INFO**. Clamped to `[0,100]`. Letter grade: `A≥90 · B≥75 · C≥60 · D≥40 · F<40`. Badge renderer emits a color-coded SVG.

### Output formatters (`output/`)
- `console.py` — colorized table
- `json_report.py` — flat JSON array
- `sarif.py` — SARIF 2.1.0, GitHub Code Scanning compatible
- `owasp_report.py` — matrix across MCP Top 10 / OWASP Agentic Top 10 / Adversa Top 25
- `compliance.py` — checklist for EU AI Act, SOC 2, ISO 27001, HIPAA, NIST AI RMF

### Discovery (`discovery.py`)
Walks for 13 agent platform configs:
- Project-level: Claude Code (`.mcp.json`, `.claude/settings.json`), Cursor, VS Code Copilot, Windsurf, Amazon Q, Goose, Continue, Roo, Kiro.
- User-level: Claude Code (`~/.claude.json`), Gemini CLI (`~/.gemini/settings.json`), Goose (`~/.config/goose/config.yaml`), Continue (`~/.continue/config.json`).

### Pinning & verification
- `pinning._hash_tool()` = `SHA-256(name : description : inputSchema_json)` — integrity only, no authenticity (no HMAC or signing).
- `create_pins()` writes `.agent-audit-kit/tool-pins.json`.
- `verification.verify_findings()` runs active verification of detected secrets when `--verify-secrets` is passed, and reads both the bundled `agent_audit_kit/data/vuln_db.json` and the cached `~/.agent-audit-kit/vuln_db.json` (cached wins).

### Auto-fix (`fix.py`)
Identifies findings whose rule has `auto_fixable=True`, dispatches to a rule-specific fix function. `--dry-run` prevents writes. **No rollback** — fixes are direct file edits.

### LLM scan (`llm_scan.py`)
Optional, hits `http://localhost:11434/api/generate` (Ollama), model `gemma2:2b`, analyzes MCP tool descriptions for hidden instructions. Silently degrades if Ollama isn't running.

### MCP proxy (`proxy/interceptor.py`)
JSON-RPC 2.0 listener on port 8765 with a 100 req / 60 s per-`client_id` limiter and a 50-connection cap. Read-only — logs `tools/call` traffic but doesn't rewrite it. PID file at `~/.agent-audit-kit/proxy.pid`.

---

## 9. Testing

**31 test files, ~6,432 LOC.** Every scanner has a dedicated test file using a fixture-based style (`vulnerable_mcp_project`, `clean_mcp_project`, `vulnerable_settings_project`, `clean_settings_project`, `project_with_secrets`, `project_with_package_risks` — all in `tests/conftest.py`, copying from `tests/fixtures/` to `tmp_path`).

Also covered: scoring (`test_scoring.py`), SARIF output, OWASP report, compliance output, pinning, verification, fix, discovery, proxy, LLM scan, examples, diff-based scanning, vuln DB.

**Genuine gap:** no tests for graceful scanner failure — the "one scanner crashes, whole scan fails" behavior (Risk 2) is unexercised.

---

## 10. GitHub Action (`action.yml`)

10 inputs (`path, severity, fail-on, format, upload-sarif, include-user-config, rules, exclude-rules, ignore-paths, config`), 4 outputs (`findings-count, critical-count, high-count, sarif-file, exit-code`). Runs via Docker image built from `Dockerfile`. Supports automatic SARIF upload to the GitHub Code Scanning tab.

---

## 11. Top risks & improvement opportunities

1. **Dead RUGPULL rules.** `AAK-RUGPULL-001/002/003` are registered in `rules/builtin.py` (lines 1137–1172) but `grep -r 'AAK-RUGPULL' agent_audit_kit/scanners/` returns nothing. Rug-pull detection does work via `pinning.verify_pins`, it just doesn't use the rule framework, which means those findings bypass the `--rules` / `--exclude-rules` filter, the OWASP/compliance mappings, and the SARIF rule-registry export. Fix: either drop the three definitions, or emit them from `verification.py` with proper `rule_id`.
2. **No exception handling around scanner invocation** in `engine.run_scan` (lines 119–128). A `UnicodeDecodeError` in `secret_exposure.py` on a binary masquerading as `.env`, or a `yaml.YAMLError` in `mcp_config.py`, kills the entire scan. Fix: wrap each scanner call in `try / except Exception`, log the failure, and emit an INFO-level `AAK-INTERNAL-SCANNER-FAIL` finding so the CI signal isn't silently degraded.
3. **Fragile regex for secret detection.** `secret_exposure.py` uses simple `sk-[a-zA-Z0-9]{20,}`-style patterns, no entropy thresholding, no format-specific validators (e.g. Stripe `sk_live_` prefix length + checksum, AWS access key `^AKIA[0-9A-Z]{16}$`). Expect false positives on test fixtures and high-entropy UUIDs. Fix: entropy filter or integrate `detect-secrets` ruleset.
4. **TypeScript & Rust "taint analysis" are aspirational.** 4 KB regex modules are not parity with the Python AST analyzer. Either rename them to `typescript_regex_scan.py` / `rust_regex_scan.py` in the docs so users don't over-estimate coverage, or integrate `typescript-eslint`'s AST (there's a usable Python bridge via `npx`) and `tree-sitter-rust` via `py-tree-sitter`.
5. **Taint-sink blind spots** in the Python analyzer: SQL injection (`sqlite3`, `psycopg2`, `sqlalchemy.text`), template injection (`jinja2.Template`, `mako.Template`), deserialization (`pickle.loads`, `yaml.load`, `xml.etree`), path-is-symlink issues (`Path.resolve` bypasses). Fix: extend `_SINKS`.
6. **LLM scan hard-depends on Ollama** — acceptable for local use, but friction for CI. Offer a `--llm-scan-provider` flag with `anthropic` / `openai` fallbacks, or cache previous scan results keyed on the hash of the tool description so CI doesn't re-pay the cost every run.
7. **No fix rollback.** `fix.py` edits files directly. A buggy fix with a read-modify-write race could destroy user code. Fix: write an `.agent-audit-kit/fix-log.json` + `.bak` for every rewritten file, surface a `agent-audit-kit fix --revert` subcommand.

---

## 12. Bottom line

AgentAuditKit is a **useful, coherent** security scanner in a genuinely new niche (MCP + agent configs) and its test coverage is strong. The three most pressing fixes are: (a) integrate rug-pull detection into the rule framework, (b) make scanner failures non-fatal, and (c) level up the TypeScript/Rust analyzers so they match the Python one. Beyond that, invest in entropy-based secret detection and an expanded Python sink catalog. The scoring, output, discovery, pinning, and GitHub Action layers are already production-ready.
