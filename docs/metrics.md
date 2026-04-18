# Weekly metrics

Updated every Monday alongside the MCP Security Index snapshot.

## Baseline (v0.3.0 launch, 2026-04-18)

| Metric | Value |
|---|---|
| GitHub stars | ~3 |
| GitHub forks | 0 |
| PyPI installs/month | <30 |
| VS Code extension installs | 0 |
| GHCR image pulls | 0 |
| Rules shipped | 124 |
| Scanner modules | 24 |
| CVE-to-rule median latency | n/a (no cycle yet) |
| MCP Security Index servers | 0 (pre-launch) |
| External PRs merged | 0 |
| Open issue median age | n/a |

## 30-day target (2026-05-18)

| Metric | Target |
|---|---|
| GitHub stars | 400 |
| PyPI installs/month | 3,000 |
| Rules shipped | 140 |
| CVE-to-rule median | <36h |
| Index servers covered | 500 |
| External PRs merged | 5 |
| Coordinated disclosures in-progress | 3 |

## 90-day target (2026-07-17)

| Metric | Target |
|---|---|
| GitHub stars | 1,200 |
| PyPI installs/month | 40,000 |
| VS Code extension installs | 2,500 |
| Rules shipped | 180 |
| CVE-to-rule median | ≤24h |
| Index servers covered | 1,000 |
| External PRs merged | 20 |
| Coordinated disclosures published | 5 |
| OWASP project status | reference-tool candidate |

## Data sources

- GitHub stars/forks: `gh api repos/sattyamjjain/agent-audit-kit | jq '.stargazers_count, .forks_count'`
- PyPI installs: `pypistats overall agent-audit-kit`
- VS Code installs: extension Marketplace API
- GHCR pulls: GHCR container registry metrics
- Rule count: `python -c "from agent_audit_kit.rules.builtin import RULES; print(len(RULES))"`
- CVE-to-rule latency: `CHANGELOG.cves.md` shipped-at timestamps vs NVD publication dates
- Index coverage: `benchmarks/site/data/index.json`
- PR + issue: `gh pr list --state merged --json mergedAt | jq '.[].mergedAt'`

## What to stop doing if the numbers don't move

If stars stall 2 weeks post-launch:

1. Increase the cadence of "State of MCP Security" blog to **twice
   weekly** instead of weekly.
2. Prioritize **VS Code extension installs** (easier win than stars).
3. Revisit competitive positioning in `docs/comparisons.md` and
   identify what else the field has done in the meantime.

Do NOT:

- Rewrite the scanner.
- Lower the compliance-evidence bar.
- Add an account/login gate to unlock "premium" features.
- Drop the deterministic-rules commitment.
