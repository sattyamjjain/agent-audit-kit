# Module: agent_audit_kit/scanners

<!-- AUTO-MANAGED: module-description -->
## Purpose

Every detector lives here as one module with a `scan()` entry point. The engine (`../engine.py`) imports each module, calls `scan(project_root, **declared_kwargs)`, and merges the results; a scanner never sees what its peers found. Rule metadata (title, severity, category, remediation, references) lives in `../rules/builtin.py`, not here — a scanner names a `rule_id` and the registry supplies the rest.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
scanners/
  _helpers.py            # make_finding(), find_line_number(), SKIP_DIRS, the shared INTERPOLATION_RE
  _ssrf_reach.py         # SSRF call-site reachability (does the URL argument derive from caller input?); used only by ssrf_patterns.py
  _ts_stdio_taint.py     # TS/JS STDIO data-flow helper for mcp_stdio_params (AAK-MCP-STDIO-CMD-INJ-002); the only tree-sitter import, optional
  rust_scan.py, typescript_scan.py   # Back-compat re-export shims for the *_pattern_scan modules; unregistered, run no detection
  <topic>.py             # One scanner per module: mcp_*, ssrf_*, skill_*, hook_*, oauth_*, taint_analysis, composition,
                         # regulatory packs (legal_compliance, eu_ai_act_art50, admt_documentation), per-CVE/wave modules
```

- **Contract**: `scan(project_root: Path, ...) -> tuple[list[Finding], set[str]]`. The set is **scanned file paths relative to `project_root`** — never rule ids; `run_scan` counts that set as `files_scanned`.
- **Kwargs**: the engine passes only the keys a scanner declared in its registry tuple (`include_user_config`, `ignore_paths`); a scanner that takes none declares `[]`, as every `_OPTIONAL_SCANNERS` entry currently does (only the always-on core takes kwargs). `run_scan` re-applies `ignore_paths` to every finding after the scan, so a new scanner does not need that kwarg for correctness.
- **Crashes surface, they are not swallowed**: an exception escaping `scan()` becomes an INFO `AAK-INTERNAL-SCANNER-FAIL` finding, and `aak scan` then exits 1 as INCOMPLETE unless `--allow-scanner-failure`. Catch the specific per-file parse/IO errors (`json.JSONDecodeError`, `yaml.YAMLError`, `OSError`, `UnicodeDecodeError`) as nearly every scanner here does; a blanket `except` around the whole body turns a crash into a silent clean pass.
- **Registration**: one `(module, display_name, kwargs_keys)` tuple in `_OPTIONAL_SCANNERS` in `../engine.py`; the always-on core (`mcp_config`, `hook_injection`, `trust_boundary`, `secret_exposure`, `supply_chain`) is built in `_build_registry()`, below that table. An ImportError skips the scanner unless `run_scan(strict_loading=True)`.
- **`_`-prefixed modules are helpers, never scanners**: the count scripts exclude them, so shared logic belongs there and a second public module for one detector creates a phantom count entry.
- **Peers import each other's `_`-named functions**: `quoted_shell_interp` ← `taint_analysis`, `mcp_atlassian` / `mcp_cve_pins_2026_07` ← `supply_chain`, `composition` ← `mcp_config`, among others; grep for importers before renaming or changing one.
- **Composition**: `composition.py` also exports `covering_keys` / `suppression_keys`; `run_scan` uses them to drop a chain whose components already carry findings at or above the chain's severity.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- Build findings with `_helpers.make_finding(rule_id, file_path, evidence, line_number=None, related_locations=None)` and never construct `Finding(...)` here: `tests/test_findings_match_registry.py` fails on it, and on any emitted field that differs from `RULES`. Only severity may differ (`ide_task_rce` escalates AAK-IDE-TASK-001 to CRITICAL): `dataclasses.replace` the `make_finding` result, then list the module with its reason in that test's `SEVERITY_OVERRIDE_MODULES` and the rule with its allowed severities in `SEVERITY_OVERRIDE_RULES`.
- Rule ids are `AAK-<AREA>-<NNN>` (`AAK-MCP-014`, `AAK-HOOK-003`) or, for most newer rules, `AAK-<AREA>-<TOPIC>-<NNN>` (`AAK-MCP-STDIO-UNBOUNDED-BUFFER-001`, `AAK-MCP-ATLASSIAN-CVE-2026-27825-001`). The id must already exist in `RULES`: `make_finding` resolves it through `get_rule()`.
- Walk trees with `SKIP_DIRS` and attach a `line_number` so SARIF and the VS Code extension can place the diagnostic. With a regex match, take the line from the match offset (as `agent_config._line_at` does): `find_line_number(raw, key)` returns the first line containing the key, which piles repeated matches onto one line that GitHub code scanning folds into a single alert (#792). Keep `find_line_number` for keys from parsed configs.
- Prefer real data flow over proximity heuristics. Where a heuristic remains as the fallback (tree-sitter absent), the module docstring says which path ran and the tests cover both.
- Bound per-match lookups to a fixed window (`agent_config._NEAR`), never the whole prefix: per-verb prefix reads made a crafted line quadratic (#844). `test_a_long_crafted_line_scans_in_linear_time` in `tests/test_agent_config.py` is the timing test to copy.
- Adding a scanner, in order: rule(s) in `../rules/builtin.py` → this module → the registry tuple in `../engine.py` → `tests/test_<module>.py` with a detecting and a non-detecting case (CVE waves use `tests/test_cve_<id>.py`) → `python scripts/sync_rule_count.py --regenerate` (rebuilds `rules.json`, then `RULE_COUNT`, the README badge and anchors, `action.yml`, `docs/rules.md`; without the flag it re-reads the committed `rules.json` and a new rule goes uncounted) and `python scripts/sync_scanner_count.py` (`SCANNER_COUNT`, `scanners.json`, README anchor) → `make count-check`. Never hand-edit a generated count.
- `SCANNER_COUNT` is asserted equal to the live registry (`tests/test_repo_metadata_sync.py`), so a *registered* module that stops importing, which the engine skips silently outside `strict_loading`, fails CI. A module never added to `_OPTIONAL_SCANNERS` is caught only by `check_counts.py`'s `scanners.json` arithmetic, and only until `sync_scanner_count.py` re-runs and records it under `unregistered_shims`: check that list in the diff.
- Long "why" docstrings on suppression logic and heuristics are the house style; keep them when refactoring.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `agent_audit_kit.models` — `Finding`, `Severity`, `Category`
- `agent_audit_kit.rules.builtin` — `get_rule`, imported by `_helpers.py` alone (for `make_finding`); no scanner module reads `RULES` or calls `get_rule` itself
- `agent_audit_kit.pinning` (`pin_drift`), `agent_audit_kit.vuln_db` (`supply_chain`, lazy-imported), and `../data/` files read by path (`toxic_flow`, `skill_composition`, `ipi_wild_corpus`, `mcp_fhi`)
- Detection is stdlib (`re`, `json`, `ast`, `pathlib`) plus `pyyaml` for YAML configs and `tomli`/`tomllib` for TOML
- Optional: `tree-sitter` + `tree-sitter-typescript` (`pip install "agent-audit-kit[taint]"`) for the STDIO data-flow path in `_ts_stdio_taint.py`; absent → proximity fallback

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add scanner-specific notes here. This section is never auto-modified.

<!-- END MANUAL -->
