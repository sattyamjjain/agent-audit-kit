# AAK-RUNTIME-ADV-002

**Runtime named by a floating tag on a line an advisory fixed**

| Field | Value |
|---|---|
| Severity | INFO |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.28 |
| Scanner | `agent_audit_kit/scanners/runtime_advisories.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities) |

## What it catches

A runtime an advisory covers, named without a release, on a line that has a fix:

- `FROM node:24`, `FROM node:24-alpine`, `FROM node:lts`, `FROM node`, `FROM php:8`
- a version file that names only a line (`.nvmrc` `24`)
- a managed runtime on a fixed line (`runtime: nodejs22` in app.yaml), where the
  platform picks the patch release

Whether the image or platform already runs the fixed release cannot be told from
the file, so this is a note, not a finding of an affected runtime. A floating
name on a line with no fixed release (`FROM node:20`) is AAK-RUNTIME-ADV-001,
since every release on that line is affected.

## How to fix

Pin a full version (`node:24.22.1-slim`) or an image digest. For a managed
runtime, confirm in the platform's release notes that it runs the fixed release.
