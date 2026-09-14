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
  package-lock.json    # Locked devDependencies
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

**A command needs both halves.** `registerCommand` in code makes it callable; `contributes.commands` in the manifest makes it reachable from the Command Palette. `sarifReader.ts` was unreachable for a long stretch because `activate()` never called `registerSarifCommands`, and the two scan commands were registered but undeclared, so none of the extension's commands appeared in the palette. When adding a command, do both, then confirm with `npm run compile` that `out/extension.js` requires the new module.

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
- Not covered by the root `pytest` / `ruff` / `mypy` targets — this subtree has no test suite, and no workflow under `.github/workflows/` builds it. Verify changes with `npm run compile` locally.

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
