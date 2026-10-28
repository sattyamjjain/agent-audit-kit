# AAK-STARTUP-HOOK-NPM-INSTALL-001

**npm lockfile entry with an install script in an MCP project**

| Field | Value |
|---|---|
| Severity | LOW |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.28 |
| Scanner | `agent_audit_kit/scanners/startup_hooks.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities) |

## What it catches

npm records `"hasInstallScript": true` on each `package-lock.json` entry whose
package has a `preinstall`, `install` or `postinstall` script. `npm install` and
`npm ci` run those scripts with the installing user's access, before any code of
the project runs: the npm counterpart of a Python startup hook, and the usual way
a malicious npm release runs. In a project that runs an MCP server, each such
entry is reported, so a new one shows up in review.

A project counts as an MCP project when its lockfile resolves
`@modelcontextprotocol/sdk`, `@anthropic-ai/mcp` or
`@anthropic-ai/claude-agent-sdk`, when a manifest beside it declares an MCP SDK,
or when an `.mcp.json` beside it declares a server.

## What it does not catch

- What a script does: the rule reads the flag, not the script.
- lockfileVersion 1, `yarn.lock` and `pnpm-lock.yaml`, which do not record
  install scripts. `node_modules` is never walked and npm is never run.
- A project whose `.npmrc`, beside the lockfile, sets `ignore-scripts=true` is
  not reported. A `--ignore-scripts` passed on a command line is not seen.

## How to fix

Check that each listed package needs its script (native builds such as esbuild
and sharp do), then install with `npm ci --ignore-scripts`, or set
`ignore-scripts=true` in the project's `.npmrc`, and run the scripts you need
yourself with `npm rebuild <package>`.
