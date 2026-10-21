# Module: agent_audit_kit/scanners

<!-- AUTO-MANAGED: module-description -->
## Purpose

Every detector lives here as one module with a `scan()` entry point. The engine (`../engine.py`) imports each module, calls `scan(project_root, **declared_kwargs)`, and merges the results; a scanner never sees what its peers found. Rule metadata (title, severity, category, remediation, references) lives in `../rules/builtin.py`, not here — a scanner names a `rule_id` and the registry supplies the rest.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
scanners/
  _helpers.py            # make_finding(); find_line_number()/find_line_numbers()/placed() (batch placement, #1052); SKIP_DIRS + in_skip_dir(); INTERPOLATION_RE; linear_find() and PatternSpans (linear-time lookups); read_text_capped() with CONFIG_/SOURCE_/MANIFEST_MAX_BYTES; the refusing parsers loads_json/loads_jsonc/loads_toml/load_yaml/parse_python with walk_tree()/refusing_overflow(); the shared readers mcp_server_maps()/iter_mcp_servers() (mcpServers and VS Code's servers), iter_hook_handlers()/hook_command(), url_host()/is_loopback_url(), declares_mcp_sdk()
  _ssrf_reach.py         # SSRF call-site reachability (does the URL argument derive from caller input?); used only by ssrf_patterns.py
  _ts_stdio_taint.py     # TS/JS STDIO data-flow helper for mcp_stdio_params (AAK-MCP-STDIO-CMD-INJ-002); the only tree-sitter import, optional
  _dependency_pins.py, _manifest_deps.py, _versions.py   # Version pins outside the CVE pin table: manifest declarations (requirements, PEP 621/Poetry tables, package.json), version-range spans, and the table's own deciding policy; `aak fix` raises pins through `raise_to_fix` here
  _launchers.py, _http_routes.py   # npx/uvx launch grammar (`launch_subject` also keys the engine's AAK-MCP-007/AAK-SUPPLY-001 dedup); route and middleware registrations out of Go, TS/JS and Python source (AAK-MCP-016/-020, AAK-MCPWN-001)
  rust_scan.py, typescript_scan.py   # Back-compat shims for the *_pattern_scan modules; unregistered, no detection of their own (each warns, then calls the real scan())
  <topic>.py             # One scanner per module: mcp_*, ssrf_*, skill_*, hook_*, oauth_*, taint_analysis, composition, per-CVE/wave
                         # modules, regulatory packs (eu_ai_act_*, admt_documentation, india_pii, state_privacy, healthcare_ai)
```

- **Contract**: `scan(project_root: Path, ...) -> tuple[list[Finding], set[str]]`. The set is **scanned file paths relative to `project_root`** — never rule ids; `run_scan` counts that set as `files_scanned`.
- **Kwargs**: the engine passes only the keys a scanner declared in its registry tuple (`include_user_config`, `ignore_paths`); a scanner that takes none declares `[]`, as every `_OPTIONAL_SCANNERS` entry currently does (only four of the always-on core take one). `run_scan` re-applies `ignore_paths` to every finding after the scan, so a new scanner does not need that kwarg for correctness.
- **Crashes surface, they are not swallowed**: an exception escaping `scan()` becomes an INFO `AAK-INTERNAL-SCANNER-FAIL` finding, and `aak scan` then exits 1 as INCOMPLETE unless `--allow-scanner-failure`. Catch the specific per-file parse/IO errors (`json.JSONDecodeError`, `yaml.YAMLError`, `OSError`, `UnicodeDecodeError`) as nearly every scanner here does; a blanket `except` around the whole body turns a crash into a silent clean pass. Read files through `read_text_capped(path, CONFIG_MAX_BYTES | SOURCE_MAX_BYTES)` (a FIFO, device or over-cap file raises `FileNotRead`, an `OSError`, before it is opened) and parse through `loads_json` / `loads_jsonc` / `loads_toml` / `load_yaml` / `parse_python`, with `walk_tree` or `refusing_overflow` around a recursive walk: a hostile file is refused as a `Refused*` subclass of the error the reader already catches, `run_scan` files one INFO `AAK-INTERNAL-SCANNER-FAIL` against that file, and the scan is INCOMPLETE at the cost of that file alone (#993, #1053). `tests/test_walk_tree.py` fails on a bare `ast.unparse` or a visitor started outside `walk_tree`.
- **Registration**: one `(module, display_name, kwargs_keys)` tuple in `_OPTIONAL_SCANNERS` in `../engine.py`; the always-on core (`mcp_config`, `hook_injection`, `trust_boundary`, `secret_exposure`, `supply_chain`) is built in `_build_registry()`, below that table. An ImportError skips the scanner unless `run_scan(strict_loading=True)`.
- **`_`-prefixed modules are helpers, never scanners**: the count scripts exclude them, so shared logic belongs there and a second public module for one detector creates a phantom count entry.
- **Peers import each other's `_`-named functions** (importer ← source): `quoted_shell_interp` and `_ssrf_reach` ← `taint_analysis`, `mcp_atlassian` / `mcp_cve_pins_2026_07` ← `supply_chain` (and `supply_chain` lazily ← the pin table's `_Pin` / `_deciding_declaration`), `composition` ← `mcp_config`, `mcp_destination_guard` ← `ssrf_toctou` (so #870's `_is_validator_name` change moved AAK-MCP-DEST-UNVALIDATED-001 too), `skill_poisoning` ← `agent_config`, `mcp_server_card` ← `tool_poisoning`, `mcp_http_noauth_server` / `mcp_transport_session_unauth` ← `mcp_server_auth`, `hook_injection` / `agentic_skills` / `session_splice` ← `skill_composition._parse_frontmatter`, `eu_ai_act_art50` ← `admt_documentation` and `healthcare_ai`, `_dependency_pins` ← `mcp_cve_pins_2026_07` and `supply_chain` (its `read_manifest` / `pinned_dependency` judge the pins in langchain_vuln, neo4j_cve, ssrf_redirect, ssrf_toctou, transport_limits and dns_rebind, and `aak fix` raises them through `raise_to_fix`), among others; grep for importers before renaming or changing one.
- **Composition**: `composition.py` also exports `covering_keys` / `suppression_keys`; `run_scan` uses them to drop a chain whose components already carry findings at or above the chain's severity, and in the same pass stands AAK-MCP-007 down on a launch AAK-SUPPLY-001 reports in the same file at or above its severity (`_launchers.launch_subject` keys the pair); both run on the assembled list, after `--rules` and `ignore_paths`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- Build findings with `_helpers.make_finding(rule_id, file_path, evidence, line_number=None, related_locations=None)` and never construct `Finding(...)` here: `tests/test_findings_match_registry.py` fails on it, and on any emitted field that differs from `RULES`. Only severity may differ (`ide_task_rce` escalates AAK-IDE-TASK-001 to CRITICAL): `dataclasses.replace` the `make_finding` result, then list the module with its reason in that test's `SEVERITY_OVERRIDE_MODULES` and the rule with its allowed severities in `SEVERITY_OVERRIDE_RULES`.
- Rule ids are `AAK-<AREA>-<NNN>` (`AAK-MCP-014`, `AAK-HOOK-003`) or, for most newer rules, `AAK-<AREA>-<TOPIC>-<NNN>` (`AAK-MCP-STDIO-UNBOUNDED-BUFFER-001`, `AAK-MCP-ATLASSIAN-CVE-2026-27825-001`). The id must already exist in `RULES`: `make_finding` resolves it through `get_rule()`. A retired id (`RETIRED_RULE_IDS` in `../rules/builtin.py`) cannot be registered again, and `tests/test_retired_rules.py` fails when a scanner or a data file still names one; give a replacement a new id. A few ids (`AAK-MCP-NOAUTH-DEFAULT`, `AAK-SKILL-UNTRUSTED-EXEC-PATH`) carry no number; give a new rule one.
- Skip vendored trees with `in_skip_dir(path, project_root)` (pass a private set as the third argument), never `any(part in SKIP_DIRS for part in path.parts)`: the parts of an absolute path include the directories the project lives in, so a checkout under `build/` (Bitbucket, Travis) lost every finding. `tests/test_skip_dirs.py` fails on the hand-rolled form. Attach a `line_number` so SARIF and the VS Code extension can place the diagnostic. With a regex match, take the line from the match offset (as `agent_config._line_at` does): `find_line_number(raw, key)` returns the first line containing the key, which piles repeated matches onto one line that GitHub code scanning folds into a single alert (#792). Keep `find_line_number` for keys from parsed configs.
- Prefer real data flow over proximity heuristics. Where a heuristic remains as the fallback (tree-sitter absent), the finding's evidence says which path ran (`mcp_stdio_params` tags the fallback `[proximity heuristic …]`) and the tests cover both.
- Bound per-match lookups to a fixed window (`agent_config._NEAR`), never the whole prefix: per-verb prefix reads made a crafted line quadratic (#844). `test_a_long_crafted_line_scans_in_linear_time` in `tests/test_agent_config.py` is the timing test to copy. For many keys in one file, `find_line_numbers(raw, keys)` or `placed()` replaces a loop of `find_line_number` calls (#1052).
- Never let a set's order reach a finding: sort or tuple it. Three scanners listed findings, or named a config or trusted skill, in hash-seed order until `tests/test_finding_order.py` (six processes, six `PYTHONHASHSEED`s) pinned them (#1043).
- In `agent_config.py`, a rule on instruction files reports the instruction, not the word (006 in #843, 001/003 in #869). Reuse its guardrail readers rather than adding another: `_forbidden` covers a negation over the match, including a comma list ("Do not push to `main`, bypass hooks, or skip checks"), and `_prohibited_lines` covers a "### NEVER" heading or a colon lead-in, fence-aware.
- Adding a scanner, in order: rule(s) in `../rules/builtin.py` → this module → the registry tuple in `../engine.py` → `tests/test_<module>.py` with a detecting and a non-detecting case (CVE waves use `tests/test_cve_<id>.py`) → `python scripts/sync_rule_count.py --regenerate` (rebuilds `rules.json`, then `RULE_COUNT`, the README badge and anchors, `action.yml`, `docs/rules.md`; without the flag it re-reads the committed `rules.json` and a new rule goes uncounted) and `python scripts/sync_scanner_count.py` (`SCANNER_COUNT`, `scanners.json`, README anchor) → `make count-check`. Never hand-edit a generated count.
- A CVE version pin is a row, not a module: a `_Pin` in `mcp_cve_pins_2026_07._PINS` (`floor=None` means presence-only) or, for a platform that ships only as an image, an `_ImagePin` in `container_image_pins.py`, or, for an MCP SDK coordinate in a Gradle or Maven manifest, a `_JvmPin` in `jvm_mcp_sdk_pins.py`; older floors (Doris, Serena) live in `supply_chain.py`; a pin that must sit beside a code check in its own module is a `DependencyPin` read through `_dependency_pins.read_manifest` / `pinned_dependency`, never a regex of its own. Set `_Pin.ecosystem` when the name exists on both registries: unscoped, npm `praisonai` was compared against the PyPI floor, the mistake `langchain_vuln` made with npm `@langchain/*` until #934. Tests go in the matching `tests/test_<module>.py`.
- `SCANNER_COUNT` is asserted equal to the live registry (`tests/test_repo_metadata_sync.py`), so a *registered* module that stops importing, which the engine skips silently outside `strict_loading`, fails CI. A module never added to `_OPTIONAL_SCANNERS` is caught only by `check_counts.py`'s `scanners.json` arithmetic, and only until `sync_scanner_count.py` re-runs and records it under `unregistered_shims`: check that list in the diff.
- Long "why" docstrings on suppression logic and heuristics are the house style; keep them when refactoring.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `agent_audit_kit.models` — `Finding`, `Severity`, `Category`
- `agent_audit_kit.rules.builtin` — `get_rule`, imported by `_helpers.py` alone (for `make_finding`); no scanner module reads `RULES` or calls `get_rule` itself
- `agent_audit_kit.pinning` (`pin_drift`), `agent_audit_kit.vuln_db` (`supply_chain`, lazy-imported), `agent_audit_kit.redaction` (`mcp_config`, `hook_injection`, `_launchers`: what of a launch argument or env value may appear in evidence), and `../data/` files read by path (`toxic_flow`, `skill_composition`, `ipi_wild_corpus`, `mcp_fhi`)
- Detection is stdlib (`re`, `json`, `ast`, `pathlib`) plus `pyyaml` for YAML configs and `tomli`/`tomllib` for TOML
- Optional: `tree-sitter` + `tree-sitter-typescript` (`pip install "agent-audit-kit[taint]"`) for the STDIO data-flow path in `_ts_stdio_taint.py`; absent → proximity fallback

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add scanner-specific notes here. This section is never auto-modified.

<!-- END MANUAL -->
