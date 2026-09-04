# VS Code Extension — AgentAuditKit

<!-- AUTO-MANAGED: module-description -->
## Purpose

VS Code extension providing in-editor security scanning for MCP configuration files. Activates on JSON, YAML, and JSONC files and shells out to the `agent-audit-kit` CLI, surfacing findings as editor diagnostics.

Versioned independently of the Python package (its own `version` in `package.json`), and not yet published to the Marketplace.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
vscode-extension/
  src/
    extension.ts       # Entry point — activate/deactivate, runs the CLI, publishes diagnostics
    sarifReader.ts     # SARIF → diagnostics. Wired up in v0.3.87 (see below)
  package.json         # Manifest — contributes.configuration + commands (all 3 declared)
  tsconfig.json        # TypeScript config
  README.md            # Marketplace-facing readme
  .vscodeignore        # Package exclusions
  out/                 # Compiled JS output (generated, untracked)
```

- **Activation**: `onLanguage:json`, `onLanguage:yaml`, `onLanguage:jsonc`
- **Settings**: `agent-audit-kit.enable`, `agent-audit-kit.severity`, `agent-audit-kit.autoScanOnSave`
- **Output**: `./out/extension.js` (`main` in the manifest)
- **Scan path**: `extension.ts` invokes the CLI via `child_process.execFile` — the extension carries no scanning logic of its own, so in-editor results always match `agent-audit-kit scan`.

**`sarifReader.ts` is wired up as of v0.3.87.** It had been dead code since it was written: it exports `loadSarif`, `applySarifToDiagnostics` and `registerSarifCommands`, but `extension.ts` never imported it and `package.json` declared no `contributes.commands`, so nothing could reach it from code or from the UI. Both halves are now done — `activate()` calls `registerSarifCommands(context)`, and the manifest declares all three commands. Note the second half was a wider gap than this module: `agent-audit-kit.scan` and `agent-audit-kit.showOutput` were registered in code and undeclared too, so **none** of the extension's commands appeared in the Command Palette. All three are declared now. The SARIF reader uses its own diagnostic collection (`agent-audit-kit-sarif`) distinct from the extension's own `agent-audit-kit`, so imported findings do not overwrite scanned ones. Verified by `npm run compile`: `out/sarifReader.js` is emitted and required by `out/extension.js`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Language**: TypeScript, compiled with `tsc` (no bundler)
- **Build**: `npm run compile` (`tsc -p ./`)
- **Watch**: `npm run watch` (`tsc -watch -p ./`)
- **Lint**: `npm run lint` (`eslint src --ext ts`) — note `eslint` is not in `devDependencies`, so this script needs it installed separately
- **Package**: `npx @vscode/vsce package`
- **Engine**: VS Code `^1.85.0`
- **Category**: `Linters`
- Not covered by the root `pytest` / `ruff` / `mypy` targets — this subtree has no test suite, and CI does not build it. Verify changes with `npm run compile` locally.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

Everything is a devDependency; `dependencies` is empty.

- `@types/vscode` — VS Code API types (pinned to the same minor as `engines.vscode`)
- `@types/node` — Node.js types
- `typescript` — compiler
- `@vscode/vsce` — extension packaging

No runtime dependencies beyond the VS Code API itself. The extension relies on the `agent-audit-kit` CLI being installed and on `PATH`, which is a runtime prerequisite rather than a package dependency.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add extension-specific notes here. This section is never auto-modified.

<!-- END MANUAL -->
