# AAK-RUNTIME-ADV-001

**Declared Node.js, PHP or Python runtime below the fixed release on its line**

| Field | Value |
|---|---|
| Severity | CRITICAL (from the advisory; a KEV entry is CRITICAL) |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.28 |
| Scanner | `agent_audit_kit/scanners/runtime_advisories.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities), ASI05 (Unexpected Code Execution) |
| CVE | [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618), [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619) (PHP2Shell), [CVE-2026-111497](https://nvd.nist.gov/vuln/detail/CVE-2026-111497) (Brotli in Node.js) |

## What it catches

A runtime release that an advisory in AAK's bundled advisory file covers, named
anywhere the project states which runtime it runs:

| Where | Example that fires |
|---|---|
| Dockerfile `FROM` (official `node`, `php`, `python` images) | `FROM node:24.22.0-slim`, `FROM php:8.4.26-fpm` |
| Version files | `.nvmrc` `22.23.3`, `.tool-versions` `nodejs 20.19.0` |
| `engines.node` in package.json | `">=18"`, judged at 18.0.0, the lowest release it admits |
| Managed runtimes | `runtime: nodejs20` (app.yaml), `runtime: nodejs18.x` (serverless.yml) |
| MCP server launchers | `"command": "~/.nvm/versions/node/v24.22.0/bin/node"` |

A release is judged against the fixed release on its own line: the major for
Node.js, major.minor for PHP and Python. A line that got no fixed release (an
end-of-life line, such as Node.js 20 or PHP 8.1) is affected at every patch, and
the evidence gives its end-of-life date from endoflife.date.

## The advisories bundled with v0.6.28

| Advisory | Runtime | Fixed in | KEV |
|---|---|---|---|
| CVE-2026-109618, PHP2Shell (OOM corruption) | PHP from 7.3.0 | 8.2.35, 8.3.36, 8.4.27, 8.5.12 | added 2026-10-26, due 2026-10-29 |
| CVE-2026-109619, PHP2Shell (stale global state) | PHP from 5.4.0 | 8.2.35, 8.3.36, 8.4.27, 8.5.12 | added 2026-10-26, due 2026-10-29 |
| CVE-2026-111497, Brotli decoder | Node.js from 10.16.0 and 11.7.0 | 22.23.4, 24.22.1, 26.12.1 | added 2026-10-27, due 2026-11-10 |

The file is `agent_audit_kit/data/runtime_advisories.json`; each entry records
its source URL and the date it was read. A copy at
`~/.agent-audit-kit/runtime_advisories.json` is read first. A scan never fetches it.
No Python advisory is in the file, so a Python runtime is read and reported by
nothing today.

## What it does not catch

- An image pinned by digest alone, an image built from an earlier stage, and
  images from other publishers (`bitnami/node`, `cimg/node`).
- A version set through an `ARG` without a default, or outside the files above
  (a CI job's `setup-node`, a shell).
- What actually runs: `engines.node` says what a package supports, and a
  managed runtime's patch release is the platform's.

## How to fix

Move to the fixed release on the same line, or to a supported line that has
one, and pin the full version or the image digest. An end-of-life line gets no
fix: upgrade the line, then rebuild every image built on the old base.
