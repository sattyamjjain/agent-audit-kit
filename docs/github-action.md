# GitHub Action reference

The Action runs the scanner in this repository's Docker image and writes SARIF.
It does **not** upload that SARIF to Code Scanning: add the
`github/codeql-action/upload-sarif` step, as below, with `security-events: write`.

```yaml
permissions:
  security-events: write   # required for the upload
  contents: read
  issues: write            # only for comment-on-pr

steps:
  - uses: actions/checkout@v4
  - uses: sattyamjjain/agent-audit-kit@v0.6.35
    id: scan
    with:
      fail-on: high
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}   # only for comment-on-pr
  - uses: github/codeql-action/upload-sarif@v3
    if: always()           # upload even when the scan step failed the build
    with:
      sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

What the SARIF carries is in the CLI reference's
[SARIF Integration](cli.md#sarif-integration) section.

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `severity` | `low` | Minimum severity to report: `critical`, `high`, `medium`, `low`, `info` |
| `fail-on` | `high` | Fail at this severity or above (`none` = never fail) |
| `format` | `sarif` | Output format: `sarif`, `json`, `console` |
| `upload-sarif` | `true` | Prints a notice that names the `sarif-file` output and the upload step to add. The Action never uploads itself |
| `include-user-config` | `false` | Also read user-level state outside the project: `~/.claude.json`, `~/.claude/settings.json`, the npx and uv launcher caches, and the editor extension folders |
| `rules` | | Comma-separated rule IDs to run (default: all) |
| `exclude-rules` | | Comma-separated rule IDs to skip |
| `preset` | | A curated rule preset, such as `mcp-ox-2026-04`; the CLI's `--preset` |
| `ignore-paths` | | Comma-separated paths to exclude |
| `config` | | Path to `.agent-audit-kit.yml` |
| `comment-on-pr` | `true` | On a `pull_request` event with `GITHUB_TOKEN` in the step's env, post one sticky comment summarising the findings and update it on later runs. A Markdown table goes to the job summary on every run |
| `fingerprint-strategy` | `auto` | SARIF fingerprints: `auto` (content hash when the source is present, else location hash), `line-hash` (always content hash) or `disabled` |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Count of CRITICAL findings |
| `high-count` | Count of HIGH findings |
| `sarif-file` | Path to the SARIF file, for the upload step |
| `exit-code` | 0 = pass, 1 = findings at or above `fail-on`, 2 = error |

---
## VS Code Extension

A VS Code/Cursor extension is available in `vscode-extension/`:

```bash
cd vscode-extension && npm install && npm run compile
```

Provides inline diagnostics on file save with quick-fix suggestions.

---