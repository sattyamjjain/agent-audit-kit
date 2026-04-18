# Claude Code — Execution Prompt for agent-audit-kit

Paste everything below the line into a fresh Claude Code session opened in the root of this repository. Do not edit. Do not add follow-up instructions.

---

You are taking over the `agent-audit-kit` repository and executing a 90-day plan to take it from single-digit GitHub stars to 1,000+ as the de-facto "npm audit for AI agents." This prompt is the full brief. Keep a running TODO list. When a session ends, re-read this prompt and resume from the first unchecked item.

## 0. Ground rules

- Today is after April 18, 2026. The MCP spec in force is 2025-11-25. 30+ MCP CVEs were disclosed between January and March 2026. Verify every CVE you code a rule for via NVD before writing detection logic.
- Python 3.9+, pytest, mypy, ruff. Stdlib + minimal deps (click, PyYAML). Do not add heavyweight deps.
- Every new rule must come with: an NVD/MITRE link (or vendor advisory), a positive fixture (vulnerable), a negative fixture (safe), a remediation snippet, and an OWASP/CWE/Adversa mapping. No rule ships without all six.
- Conventional commits. Feature branches. Squash merges. One rule-family per PR.
- Do not fabricate CVE numbers. If a search returns no authoritative source, flag `UNVERIFIED` and stop; do not invent.

## 1. Read before you start

Read in order:

1. `CLAUDE.md`
2. `../agent-airlock/ECOSYSTEM_STATE_2026-04.md` — shared ecosystem brief
3. `ROADMAP_2026.md` — 90-day plan for this repo
4. `../agent-airlock/LAUNCH_PLAYBOOK_2026.md` — shared growth tactics
5. `agent_audit_kit/rules/builtin.py` — understand the 77 existing rules
6. `agent_audit_kit/scanners/*.py` — understand the 13 scanner modules
7. `tests/conftest.py` — fixture patterns
8. Run `pytest -v` and `agent-audit-kit scan .` on the repo's own fixtures to confirm baseline

If any referenced file is missing, STOP and tell me.

## 2. Phase 0 — baseline verification

1. `pip install -e ".[dev]"` — clean install.
2. `pytest -v` — record green count. All existing tests must stay green.
3. `ruff check . && mypy agent_audit_kit/` — zero errors before you touch anything.
4. `agent-audit-kit scan tests/fixtures/vulnerable_mcp_project` — confirm rule catalog is firing.
5. Tag `v0.2.0-pre-april-2026`.
6. Open a GitHub issue "v0.3.0 — 2026 CVE wave + AAK Response SLA" with a checklist copied from ROADMAP §2.1 and §2.2.

## 3. Phase 1 — clean up dead weight (Week 0)

1. **Retire 3 dead RUGPULL rules** listed in ROADMAP. Replace with deprecation shims that print a `DeprecationWarning` and point to the new rules. Do not hard-delete — users have CI pipelines pinned to rule IDs.
2. **Exception hardening in `engine.run_scan`**: wrap each scanner invocation in try/except, log the failure, continue with remaining scanners, and surface the error in the report rather than crashing the scan. Add a test that induces a scanner crash and asserts the scan still completes.
3. **Rename or rewrite the TS/Rust "taint analysis" modules.** The current name overstates what they do. Rename to `typescript_pattern_scan.py` / `rust_pattern_scan.py` if they're really pattern-based, OR invest the week to make them real taint tracers using tree-sitter AST walks. Pick one — document which in the PR.
4. **Fix scanner-registration flakiness**: the try/except ImportError pattern silently skips scanners if a transitive dep fails to import. Add an opt-in `--strict-loading` flag that fails loudly, and log warnings in default mode.

## 4. Phase 2 — 2026 CVE rule families (Week 1–4)

Ship these rule families in order. Each is one PR.

- **AAK-MCP-011 through AAK-MCP-020** — ten rules corresponding to the 2026 MCP CVE wave listed in ROADMAP §2.1. Each rule: NVD link, positive + negative fixtures, remediation.
- **AAK-MCP-SSRF-001..005** — SSRF patterns in MCP tool implementations (unvalidated URL fetch, localhost bypass, metadata service access, DNS rebinding, redirect chain abuse).
- **AAK-MCP-OAUTH-001..005** — OAuth 2.1 misconfigurations (missing PKCE, S256 alg absent, token passthrough, confused-deputy, DPoP absence where required by 2025-11-25).
- **AAK-HOOK-RCE-001..003** — Claude Code hook script injection patterns (including CVE-2025-59536 regression).
- **AAK-LANGCHAIN-PATH-TRAVERSAL-001..003** — LangChain tool path traversal patterns.
- **AAK-MARKETPLACE-MANIFEST-001..004** — rules for `.claude-plugin/marketplace.json` security: unsigned manifests, unsafe permissions, typosquat detection, maintainer-takeover heuristics.
- **AAK-ROUTINE-SCHEDULED-001..003** — Routines security (Apr 14 2026 research preview): unrestricted scheduled triggers, cron-injection, permission-escalation via routine.
- **AAK-A2A-001..005** — Agent-to-Agent protocol violations: missing mutual auth, unbounded delegation, transitive trust, replay, schema confusion.
- **AAK-MCP-TASKS-LEAK-001..003** — Tasks primitive (SEP-1686) leakage patterns: unauth task read, task enumeration, cross-tenant task access.
- **AAK-SKILL-POISON-001..005** — Poisoned skill detection: hidden tool calls, unicode steganography, exfil via structured output, description hijacking, prompt injection in skill frontmatter.

For each rule-family PR:

1. Web-search the upstream CVE / advisory / spec before writing detection logic.
2. Use tree-sitter for AST-based detection where feasible; regex only as a fallback with a follow-up AST issue.
3. Add to `agent_audit_kit/rules/builtin.py` with full `RuleDefinition` (severity, category, OWASP mapping, Adversa mapping, CWE, remediation).
4. Add fixtures under `tests/fixtures/cves/<rule-id>/vulnerable/` and `.../safe/`.
5. Update `docs/` with an auto-generated rule-catalog page.

## 5. Phase 3 — AAK Response SLA infrastructure (Week 2–3, parallel)

1. **48h CVE-to-rule SLA**: GitHub Action that watches NVD's MCP keyword feed, auto-files an issue tagged `cve-response`, and blocks release until the issue is closed.
2. **Sigstore-signed rule bundles**: sign every release with Sigstore. Verify on install via a new `agent-audit-kit verify-bundle` command. Web-search `sigstore.dev` for the current signing flow.
3. **Auditor-ready PDF compliance reports**: new `agent-audit-kit report --format pdf --framework eu-ai-act|soc2|iso27001|hipaa|nist-ai-rmf`. Generate via ReportLab (OK to add this dep — auditors need PDFs). Include findings → framework-article mapping.
4. **`agent-audit-kit report --sbom`** — emit CycloneDX and SPDX SBOMs covering the scanned project's MCP servers and versions. Web-search `cyclonedx.org` for the current schema.

## 6. Phase 4 — MCP Security Index (Week 4–6)

This is the leaderboard-ownership growth play.

1. **Crawler**: discovers MCP servers from `anthropics/claude-plugins-official`, `claudemarketplaces.com`, `aitmpl.com`, `buildwithclaude.com`, and the top 500 GitHub results for `topic:mcp-server`. Store in `benchmarks/crawler/`.
2. **Scanner runner**: runs the full agent-audit-kit rule catalog against each MCP server weekly.
3. **Index site**: publish `mcp-security-index.com` (or `index.agentauditkit.dev`) as a static site with per-server grades A–F, rule-hit breakdown, and week-over-week trends. Hosted on Cloudflare Pages.
4. **Disclosure policy**: every discovered vuln goes to the maintainer first with a 90-day disclosure window. Publish the policy at `docs/disclosure-policy.md` before crawling.
5. **Weekly State of MCP Security** blog post summarizing new findings, trends, and the worst-graded servers. This is the Aider-leaderboard play.

## 7. Phase 5 — distribution and packaging (Week 5–6)

1. **VS Code extension** (the `vscode-extension/` subtree): wire up live scanning on save, CodeLens on findings, SARIF panel. Publish to the VS Code Marketplace and Open VSX. Web-search the VS Code publisher docs for the 2026 publishing flow.
2. **GitHub Action**: polish `action.yml` to surface findings in the GitHub Security tab via SARIF. Add an opinionated `agent-audit-kit/scan@v1` action manifest. Submit to GitHub Marketplace.
3. **GitLab CI template**: `.gitlab/agent-audit-kit.yml` one-line include. Submit to the GitLab template catalog.
4. **Pre-commit hook**: `agent-audit-kit install-precommit`.
5. **Docker image**: publish `ghcr.io/<owner>/agent-audit-kit` with scheduled rebuilds.
6. **PyPI v0.3.0** tagged release with SBOM + Sigstore signatures.

## 8. Phase 6 — launch (end of Week 6)

Launch only after Phase 2 (rule families) is 100% merged and the MCP Security Index has been seeded with at least 200 servers. Do not launch on a Friday.

1. **Target**: Tuesday 13:00 UTC.
2. **HN**: "Show HN: We scanned 500 MCP servers for 2026 CVEs — here's the leaderboard." Link the index, not the repo. Stay in the thread 4 hours. Draft canned answers in `docs/launch/hn-faq.md`.
3. **Reddit**: `/r/netsec` is the #1 channel for this repo. Also `/r/ClaudeAI`, `/r/LocalLLaMA`, `/r/mcp`.
4. **X thread**: 8 tweets, lead with a screenshot of the worst-graded major server, tail with repo link. Drafts in `docs/launch/x-thread.md`.
5. **Press**: email theregister, darkreading, securityweek, thehackernews with a 1-paragraph pitch and an embargo option. Drafts in `docs/launch/press.md`.
6. **Release notes**: attach the SBOM + Sigstore bundle.

## 9. Competitive positioning

Write `docs/comparisons.md` covering vs Snyk Agent Scan, Checkmarx, Invariant (post-Snyk acquisition), and Lakera. Key differentiators to emphasize, in order:

1. Fully OSS, no auth, no cloud account required
2. Compliance-evidence PDFs (SOC 2 / EU AI Act / HIPAA mapping) — competitors gate this behind enterprise tiers
3. Deterministic rule-based (no LLM calls, no data exfil)
4. Regional: Indian DPDP Act support out of the box
5. 48h CVE-to-rule SLA — publicly tracked

Do NOT claim "more accurate than Snyk." Make verifiable claims.

## 10. Research discipline

For every new rule:

1. Web-search the CVE (NVD + vendor advisory + any public POC).
2. Paste the three URLs + retrieval date into the rule's docstring `REFERENCES` block.
3. If the CVE has no public POC, construct your fixture from the advisory alone and mark the test `@pytest.mark.inferred_from_advisory`.
4. Maintain `docs/research-log.md` with date/topic/URLs/conclusion per session.

## 11. Metrics

Update `docs/metrics.md` weekly:

- GitHub stars, forks
- PyPI + VS Code extension + GHCR image installs
- MCP Security Index servers covered
- New CVEs added this week
- CVE-to-rule latency (hours)
- External PRs merged
- Open issue SLA %

Target at 90 days: 1,200 stars, 40k PyPI downloads, 500 servers indexed, median CVE-to-rule ≤ 36h.

## 12. Do-not list

- Do not ship rules without fixtures and a spec/CVE link.
- Do not add LLM calls to the scanner core — deterministic is the moat.
- Do not disclose vulns publicly before the 90-day window expires.
- Do not fabricate CVE numbers or advisory links.
- Do not launch without the MCP Security Index live and seeded.

## 13. When stuck

- If a CVE is unclear, triangulate NVD + vendor advisory + any blog write-up; if still ambiguous, file an issue and skip to the next rule rather than guessing.
- If tree-sitter grammar for a language is out of date, file an upstream issue and fall back to regex with a `TODO: AST` marker.
- If a scan is slow, profile with `cProfile` before optimizing.
- If stars don't move two weeks post-launch, increase the cadence of the "State of MCP Security" blog to twice weekly and prioritize VS Code extension installs over stars.

Begin with Phase 0. Open PRs as you go. Ping me in the roadmap issue when Phase 2 is 100% merged before starting the MCP Security Index.
