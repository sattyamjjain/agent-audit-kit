# AgentAuditKit Zed Extension

Surfaces AAK findings as inline LSP diagnostics in Zed.

## Install

1. Install AAK in your environment so `agent-audit-kit` is on `PATH`:

   ```bash
   pip install agent-audit-kit
   ```

2. Install this extension via Zed → Extensions → install local extension and
   point at this directory (`editors/zed/`).

3. Reload Zed. Open a Python / TypeScript / Rust file in a project — diagnostics
   are published on save.

## How it works

The extension launches `agent-audit-kit inspect-ide . --serve`. The CLI
implements a minimal stdio LSP loop that runs the scanner against the
opened document and replies with `textDocument/publishDiagnostics`.

## See also

- VS Code extension: `vscode-extension/`
- CLI: `agent-audit-kit inspect-ide --format text` for one-shot output.
