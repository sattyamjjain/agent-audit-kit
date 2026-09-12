# Why AgentAuditKit works the way it does

The reasoning that used to sit above the fold in the README. It is a
better argument than it was a landing page.

## Auto-PR for mechanical fixes

```bash
agent-audit-kit scan . --format sarif -o run.sarif
agent-audit-kit suggest run.sarif --auto-pr --dry-run   # see the plan
agent-audit-kit suggest run.sarif --auto-pr             # open a draft PR
```

Off by default, and deliberately narrow:

- **Allow-listed rules only.** If any pending fix is for a rule outside `AUTO_PR_ALLOWLIST`, the whole run refuses rather than opening a partial PR. The allow-list is an explicit literal, not `auto_fixable` — marking a new rule auto-fixable does not, on its own, make AAK push it.
- **Draft, never merged.** A mechanical edit nobody reviewed is a diff, not a decision.
- **No credentials.** Delivery runs through your existing `gh auth`. AAK never asks for, stores, or reads a token, so it cannot exceed the access you already granted `gh`.
- **Refuses on a dirty tree**, so your uncommitted work is never swept into its branch.

Fixes whose correct form depends on how the project is deployed or wired — adding an auth dependency to a route, rewriting a quoted shell string as a parameterised call, flipping a bind address off `0.0.0.0` — are reported but never auto-edited. The PR body says so too.

---
## Supply chain

Every `v*` release publishes:

- **Wheel + sdist** on PyPI via OIDC Trusted Publisher
- **Docker image** on GHCR (`ghcr.io/sattyamjjain/agent-audit-kit:<tag>`) with SLSA provenance attestation. Provenance is attached by the release flow, so it covers **version tags**; the nightly rebuild that refreshes `:latest` and `:nightly` scans the image with Trivy but attaches no attestation, so pin a version tag if you need provenance
- **Sigstore keyless-signed rule bundle** (`rules.json` + `rules.json.sha256`)
- **CycloneDX + SPDX SBOM** (`sbom.cdx.json`, `sbom.spdx.json`)
- **OpenVEX 0.2.0 exploitability document** (`vex.openvex.json`) — joins to the SBOM on purl; never claims `not_affected`, which needs a reachability justification a static scan cannot establish

Verify a bundle:

```bash
agent-audit-kit verify-bundle rules.json --signature rules.json.sigstore
```

---
## State of MCP Security 2026

The measured numbers live in the report itself, not here. Copying them into a
second file is how a figure goes stale: `scripts/sync_rule_count.py` regenerates
the headline numbers in `README.md` from `results.json` and asserts them in CI,
and it does not know about this page.

Read [State of MCP Security 2026](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md)
([how to cite](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md#how-to-cite-this-report)),
the [frozen pre-2026-07-28 baseline](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/baseline/mcp-security-baseline-v1.0-2026-07-27.json),
and the [corpus manifest](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/corpus/registry-manifest.json).
