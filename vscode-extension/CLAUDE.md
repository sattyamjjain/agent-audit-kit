# VS Code Extension — AgentAuditKit

<!-- AUTO-MANAGED: module-description -->
## Purpose

VS Code extension that provides in-editor security scanning for MCP configuration files. Activates on JSON, YAML, and JSONC files and runs AgentAuditKit scans on save.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
vscode-extension/
  src/
    extension.ts       # Extension entry point — activate/deactivate, diagnostics provider
  package.json         # Extension manifest — contributes configuration, activation events
  tsconfig.json        # TypeScript config
  out/                 # Compiled JS output
```

- **Activation**: `onLanguage:json`, `onLanguage:yaml`, `onLanguage:jsonc`
- **Settings**: `agent-audit-kit.enable`, `agent-audit-kit.severity`, `agent-audit-kit.autoScanOnSave`
- **Output**: `./out/extension.js` (compiled from TypeScript)

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Language**: TypeScript 5.3+
- **Build**: `npm run compile` (tsc)
- **Watch**: `npm run watch` (tsc --watch)
- **Lint**: `npm run lint` (eslint src --ext ts)
- **Package**: `npx @vscode/vsce package`
- **Engine**: VS Code ^1.85.0

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `@types/vscode` ^1.85.0 — VS Code API types
- `@types/node` ^20.11.0 — Node.js types
- `typescript` ^5.3.3 — Compiler
- `@vscode/vsce` ^2.22.0 — Extension packaging

All dependencies are devDependencies (no runtime deps beyond VS Code API).

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add extension-specific notes here. This section is never auto-modified.

<!-- END MANUAL -->
