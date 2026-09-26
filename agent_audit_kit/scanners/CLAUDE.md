# Module: agent_audit_kit/scanners

<!-- AUTO-MANAGED: module-description -->
## Purpose

Every detector lives here as one module with a `scan()` entry point. The engine (`../engine.py`) imports each module, calls `scan(project_root, **declared_kwargs)`, and merges the results; a scanner never sees what its peers found. Rule metadata (title, severity, category, remediation, references) lives in `../rules/builtin.py`, not here — a scanner names a `rule_id` and the registry supplies the rest.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
scanners/
  _helpers.py            # make_finding(), find_line_number(), SKIP_DIRS, shared regexes (INTERPOLATION_RE)
  _ssrf_reach.py         # SSRF reachability helper shared by the ssrf_* scanners
  _ts_stdio_taint.py     # TS/JS STDIO data-flow helper (tree-sitter, optional) — the only module that imports it
  rust_scan.py, typescript_scan.py   # Back-compat re-export shims for the *_pattern_scan modules; unregistered, run no detection
  <topic>.py             # One scanner per module: mcp_*, ssrf_*, skill_*, hook_*, oauth_*, taint_analysis, composition,
                         # regulatory packs (legal_compliance, eu_ai_act_art50, admt_documentation), per-CVE/wave modules
```

- **Contract**: `scan(project_root: Path, ...) -> tuple[list[Finding], set[str]]`. The set is **scanned file paths relative to `project_root`** — never rule ids; `run_scan` counts that set as `files_scanned`.
- **Kwargs**: the engine passes only the keys a scanner declared in its registry tuple (`include_user_config`, `ignore_paths`); a scanner that takes none declares `[]`, as every `_OPTIONAL_SCANNERS` entry currently does (only the always-on core takes kwargs). `run_scan` re-applies `ignore_paths` to every finding after the scan, so a new scanner does not need that kwarg for correctness.
- **Crashes surface, they are not swallowed**: an exception escaping `scan()` becomes an INFO `AAK-INTERNAL-SCANNER-FAIL` finding, and `aak scan` then exits 1 as INCOMPLETE unless `--allow-scanner-failure`. Catch the specific per-file parse/IO errors (`json.JSONDecodeError`, `yaml.YAMLError`, `OSError`, `UnicodeDecodeError`) as nearly every scanner here does; a blanket `except` around the whole body turns a crash into a silent clean pass.
- **Registration**: one `(module, display_name, kwargs_keys)` tuple in `_OPTIONAL_SCANNERS` in `../engine.py`; the always-on core (`mcp_config`, `hook_injection`, `trust_boundary`, `secret_exposure`, `supply_chain`) is constructed directly above that table. An ImportError skips the scanner unless `run_scan(strict_loading=True)`.
- **`_`-prefixed modules are helpers, never scanners**: the count scripts exclude them, so shared logic belongs there and a second public module for one detector creates a phantom count entry.
- **Composition**: `composition.py` also exports `covering_keys` / `suppression_keys`; `run_scan` uses them to drop a chain whose components already carry findings at or above the chain's severity.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- Build findings with `_helpers.make_finding(rule_id, file_path, evidence, line_number=None, related_locations=None)`; construct `Finding(...)` by hand only when a field must differ from the registry, and say why in a comment.
- Rule ids are `AAK-<AREA>-<NNN>` (`AAK-MCP-014`, `AAK-HOOK-003`) or a descriptive slug for CVE-driven rules (`AAK-MCP-STDIO-UNBOUNDED-BUFFER-001`). The id must already exist in `RULES`: `make_finding` resolves it through `get_rule()`.
- Walk trees with `SKIP_DIRS`; attach a `line_number` (via `find_line_number(raw, key)` when a key is known) so SARIF and the VS Code extension can place the diagnostic.
- Prefer real data flow over proximity heuristics. Where a heuristic remains as the fallback (tree-sitter absent), the module docstring says which path ran and the tests cover both.
- Adding a scanner, in order: rule(s) in `../rules/builtin.py` → this module → the registry tuple in `../engine.py` → `tests/test_<module>.py` with a detecting and a non-detecting case (CVE waves use `tests/test_cve_<id>.py`) → `python scripts/sync_scanner_count.py` and `python scripts/sync_rule_count.py` (regenerate `SCANNER_COUNT`/`RULE_COUNT`, `scanners.json`/`rules.json`, README anchors, `docs/rules.md`) → `make count-check`. Never hand-edit a count.
- `tests/test_repo_metadata_sync.py` asserts the registry size equals `SCANNER_COUNT`, so a module that imports fine but is missing from `_OPTIONAL_SCANNERS` fails in CI, not silently at runtime.
- Long "why" docstrings on suppression logic and heuristics are the house style; keep them when refactoring.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `agent_audit_kit.models` — `Finding`, `Severity`, `Category`
- `agent_audit_kit.rules.builtin` — `RULES`, `get_rule`
- Detection is stdlib (`re`, `json`, `ast`, `pathlib`) plus `pyyaml` for YAML configs and `tomli`/`tomllib` for TOML
- Optional: `tree-sitter` + `tree-sitter-typescript` (`pip install "agent-audit-kit[taint]"`) for the STDIO data-flow path in `_ts_stdio_taint.py`; absent → proximity fallback

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add scanner-specific notes here. This section is never auto-modified.

<!-- END MANUAL -->
