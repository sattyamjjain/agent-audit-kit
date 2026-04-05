# AgentAuditKit VS Code Extension

Security scanner for MCP-connected AI agent pipelines, integrated directly into VS Code.

## Features

- Runs `agent-audit-kit scan` automatically on file save for JSON, YAML, and JSONC files
- Displays findings as inline diagnostics (errors, warnings, info) in the Problems panel
- Provides quick-fix code actions with remediation guidance from scan results
- Configurable severity threshold and auto-scan behavior

## Prerequisites

Install the `agent-audit-kit` CLI tool before using this extension:

```bash
pip install agent-audit-kit
```

Verify it is available on your PATH:

```bash
agent-audit-kit --version
```

## Installation

### From Source

```bash
cd vscode-extension
npm install
npm run compile
```

Then press `F5` in VS Code to launch an Extension Development Host with the extension loaded.

### Package as VSIX

```bash
npm install
npm run compile
npx @vscode/vsce package
```

Install the resulting `.vsix` file via **Extensions > Install from VSIX...** in VS Code.

## Configuration

Open **Settings** and search for `agent-audit-kit`:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `agent-audit-kit.enable` | boolean | `true` | Enable or disable the scanner |
| `agent-audit-kit.severity` | string | `low` | Minimum severity to report (`critical`, `high`, `medium`, `low`, `info`) |
| `agent-audit-kit.autoScanOnSave` | boolean | `true` | Automatically scan on file save |

## How It Works

1. When you save a JSON, YAML, or JSONC file, the extension runs `agent-audit-kit scan --format json` against the workspace folder.
2. The JSON output is parsed and each finding is mapped to a VS Code diagnostic at the reported file and line.
3. Diagnostics appear in the editor gutter and the Problems panel with severity levels:
   - **Error** for CRITICAL and HIGH findings
   - **Warning** for MEDIUM findings
   - **Information** for LOW and INFO findings
4. Quick-fix code actions display the remediation text from each finding.

## Development

```bash
npm install
npm run watch   # recompile on changes
```

Press `F5` to launch the Extension Development Host for testing.
