# AAK-RUNTIME-ADV-003

**Lockfile or exact pin puts a library bundling an affected codec below its fix**

| Field | Value |
|---|---|
| Severity | CRITICAL (from the advisory; a KEV entry is CRITICAL) |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.28 |
| Scanner | `agent_audit_kit/scanners/runtime_advisories.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities), ASI05 (Unexpected Code Execution) |
| CVE | [CVE-2026-111497](https://nvd.nist.gov/vuln/detail/CVE-2026-111497), [GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) |

## What it catches

CVE-2026-111497 is an out-of-bounds write in Google's Brotli decoder (1.0.3
through 1.2.0) on a crafted stream; CISA added it to KEV on 2026-10-27. Google
fixed it in 1.0.10, 1.1.1 and 1.2.1. Python's two Brotli bindings bundle the
decoder, and PyPI carries only the 1.2 line's fix:

| Package | Affected | Fixed |
|---|---|---|
| `Brotli` | from 1.0.3, below 1.2.1 | 1.2.1 |
| `brotlicffi` | from 1.0.3, below 1.2.1.0 | 1.2.1.0 |

The rule reports a lockfile entry (`uv.lock`, `poetry.lock`, `Pipfile.lock`,
`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) or an exact pin
(`brotlicffi==1.2.0.2`) below the fix. Versions compare on every number, so
brotlicffi's four-part versions are read correctly.

## What it does not catch

- A range (`Brotli>=1.0`): it does not say which release is installed.
- A copy of the decoder vendored in other code, a system `libbrotli`, or the
  copy Node.js bundles (that is AAK-RUNTIME-ADV-001).

## How to fix

Upgrade to Brotli 1.2.1 or brotlicffi 1.2.1.0 and re-lock. Until then, do not
decompress Brotli data from a source you do not trust.
