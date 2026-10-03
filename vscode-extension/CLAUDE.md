# VS Code Extension — AgentAuditKit

<!-- AUTO-MANAGED: module-description -->
## Purpose

VS Code extension providing in-editor security scanning for MCP configuration files. Activates on JSON, YAML, and JSONC files and shells out to the `agent-audit-kit` CLI, surfacing findings as editor diagnostics.

Versioned independently of the Python package (its own `version` in `package.json`; the manifest's `license` mirrors the root Apache-2.0), and not yet published to the Marketplace.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
vscode-extension/
  src/
    extension.ts       # Entry point — activate/deactivate, runs the CLI via child_process.execFile, publishes diagnostics
    sarifReader.ts     # SARIF → diagnostics: loadSarif, applySarifToDiagnostics, registerSarifCommands
  package.json         # Manifest — contributes.configuration + contributes.commands
  package-lock.json    # Gitignored (vscode-extension/.gitignore): local only, so the repo does not lock devDependency versions
  tsconfig.json        # TypeScript config
  README.md            # Marketplace-facing readme
  .vscodeignore        # Package exclusions
  out/                 # Compiled JS output (generated, untracked)
```

- **Activation**: `onLanguage:json`, `onLanguage:yaml`, `onLanguage:jsonc`
- **Settings**: `agent-audit-kit.enable`, `agent-audit-kit.severity` (critical…info, default `low`), `agent-audit-kit.autoScanOnSave`
- **Commands** (declared in `contributes.commands` and registered in code): `agent-audit-kit.scan`, `agent-audit-kit.showOutput`, `agent-audit-kit.loadSarif`
- **Output**: `./out/extension.js` (`main` in the manifest)
- **Scan path**: `extension.ts` invokes the CLI via `child_process.execFile` — the extension carries no scanning logic of its own, so in-editor results always match `agent-audit-kit scan`.
- **Two diagnostic collections**: scans write to `agent-audit-kit`, SARIF imports to `agent-audit-kit-sarif`, so an imported report never overwrites live scan results.
- **CLI contract**: `AuditFinding` / `AuditReport` in `extension.ts` mirror the camelCase keys of `output/json_report.py`, read from `scan <folder> --format json --severity <sev>`. `tests/test_vscode_json_contract.py` parses those interfaces and fails when `json_report.py` stops writing a key they read.

**A command needs both halves.** `registerCommand` in code makes it callable; `contributes.commands` in the manifest makes it reachable from the Command Palette. `sarifReader.ts` was unreachable for a long stretch because `activate()` never called `registerSarifCommands`, and the two scan commands were registered but undeclared, so none of the extension's commands appeared in the palette. When adding a command, do both, then confirm with `npm run compile` that `out/extension.js` requires the new module.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Language**: TypeScript, compiled with `tsc` (no bundler)
- **Build**: `npm run compile` (`tsc -p ./`)
- **Watch**: `npm run watch` (`tsc -watch -p ./`)
- **Lint**: `npm run lint` (`eslint src --ext ts`) — note `eslint` is not in `devDependencies`, so this script needs it installed separately
- **Package**: `npx @vscode/vsce package`; its `vscode:prepublish` script runs `npm run compile` first, so a package never ships a stale `out/`
- **Engine**: VS Code `^1.85.0`
- **Category**: `Linters`
- The root `ruff` / `mypy` targets do not cover it, and root `pytest` only reads its sources as text (`tests/test_vscode_json_contract.py` pins the CLI contract above) — this subtree has no test suite. `.github/workflows/vscode-extension.yml` runs `npm install` and `vsce package` (which compiles first) on any change under `vscode-extension/`, and it is the only CI job that builds this code, so a red one on a Dependabot PR is real. Dependabot covers its devDependencies in one grouped npm PR, except `@types/vscode`, which moves with `engines.vscode` by hand because vsce refuses types newer than the engine, and `@types/node` majors, which would describe a newer Node than VS Code bundles. CodeQL analyses `src/` as `javascript-typescript`; `paths` in `codeql.yml` keeps the repo's deliberately vulnerable JS fixtures out. `tsconfig.json` lists `types: ["node", "vscode"]` because TypeScript 7 no longer loads every `@types/*` package by default. Verify changes with `npm run compile` locally.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

Everything is a devDependency; the manifest has no `dependencies` block.

- `@types/vscode` — VS Code API types, `^1.85.0` like `engines.vscode`; with no tracked lockfile a fresh install resolves the newest 1.x types, so `tsc` will not flag an API newer than the 1.85 floor
- `@types/node` — Node.js types
- `typescript` — compiler
- `@vscode/vsce` — extension packaging

No runtime dependencies beyond the VS Code API itself. The extension relies on the `agent-audit-kit` CLI being installed and on `PATH`, which is a runtime prerequisite rather than a package dependency.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add extension-specific notes here. This section is never auto-modified.

<!-- END MANUAL -->
