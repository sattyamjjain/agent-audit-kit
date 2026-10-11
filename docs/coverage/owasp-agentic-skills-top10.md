# OWASP Agentic Skills Top 10 — AgentAuditKit coverage leaderboard

> **Generated file — do not edit by hand.** Run `python scripts/gen_coverage.py` to regenerate; CI fails if it drifts (`scripts/gen_coverage.py --check`).

## Methodology

Every row is derived from the live AAK rule registry (`agent_audit_kit/rules/builtin.py`): a rule lands in a category iff it declares that category in its OWASP references. Coverage labels are **reproducible thresholds, not self-assessment** — **Full** = ≥ 3 mapped rules, **Partial** = 1–2, **None** = 0. Deterministic and offline: same registry → same table, byte-for-byte.

**AAK covers 6/10 categories** with ≥ 1 deterministic rule. Rule IDs are listed so the claim is auditable — click through to `docs/rules/`. Source taxonomy: <https://owasp.org/www-project-agentic-skills-top-10/>.

Taxonomy version: **1.0 (2026)** (an OWASP incubator project). Coverage is partial on purpose: a rule ships only where a static check over a skill bundle gives a deterministic answer. The notes column says whether an uncovered category is outside what a static scan can see or simply unwritten.

| OWASP | Title | Coverage | # rules | Rule IDs | Notes |
| --- | --- | :---: | :---: | --- | --- |
| **AST01** | Malicious Skills | Full | 5 | `AAK-SKILL-001`, `AAK-SKILL-002`, `AAK-SKILL-003`, `AAK-SKILL-004`, `AAK-SKILL-006` |  |
| **AST02** | Supply Chain Compromise | Partial | 1 | `AAK-AST02-001` |  |
| **AST03** | Over-Privileged Skills | Partial | 1 | `AAK-COMPOSE-003` |  |
| **AST04** | Insecure Metadata | Full | 3 | `AAK-AST04-001`, `AAK-SKILL-004`, `AAK-SKILL-005` |  |
| **AST05** | Untrusted External Instructions | None | 0 | — | Gap, not a boundary: no rule yet reads the external documents a skill tells the agent to load. `AAK-AST02-001` flags unpinned code and packages, not textual instructions. |
| **AST06** | Weak Isolation | None | 0 | — | Whether a skill is sandboxed is a property of the runtime that loads it, not of anything in the bundle. |
| **AST07** | Update Drift | Partial | 1 | `AAK-AST02-001` | `AAK-AST02-001` covers the pinning half. Detecting that a *deployed* skill drifted from its known-good version needs the deployed copy and a baseline, which a repository scan does not have. |
| **AST08** | Poor Scanning | None | 0 | — | A risk about a registry's scanning process; nothing in a bundle records whether the marketplace scanned it. |
| **AST09** | No Governance | None | 0 | — | Organisational: inventories, approval workflows, revocation. Not a property of any file. |
| **AST10** | Cross-Platform Reuse | Partial | 1 | `AAK-AST10-001` |  |
