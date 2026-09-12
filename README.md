<h1 align="center">AgentAuditKit</h1>

<p align="center"><strong>The missing <code>npm audit</code> for AI agents.</strong></p>

<p align="center">
  <a href="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml"><img src="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-audit-kit/"><img src="https://img.shields.io/pypi/v/agent-audit-kit.svg" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="#what-it-finds"><img src="https://img.shields.io/badge/rules-348-blue.svg" alt="Rules: 348"></a>
  <a href="https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md#how-to-cite-this-report"><img src="https://img.shields.io/badge/cite-State_of_MCP_Security_2026_v1.0-informational.svg" alt="Cite the State of MCP Security 2026 report, version 1.0"></a>
  <!-- fp-badge --><a href="benchmarks/false_positive/RESULTS.md"><img src="https://img.shields.io/badge/benign--slice%20536%20configs-HIGH%2FCRIT%20FP%200%2F1-brightgreen.svg" alt="Benign-slice false-positive measurement: 536 configs scanned, 0 of 1 HIGH/CRITICAL findings were false positives (0.0%)"></a><!-- /fp-badge -->
</p>

<p align="center">
  <a href="https://asciinema.org/a/9X7N1ztuuIYi9T2P" target="_blank"><img src="https://asciinema.org/a/9X7N1ztuuIYi9T2P.svg" alt="AgentAuditKit demo" width="700"/></a>
</p>

Static security scanner for MCP-connected AI agent pipelines. It finds
misconfigurations, hardcoded secrets, tool poisoning, rug pulls, trust-boundary
violations and tainted data flows across **10 agent platforms** — and emits the
compliance evidence an auditor asks for afterwards.

It runs fully offline. No account, no telemetry, no model in the loop.

## Quick start

```bash
pip install agent-audit-kit
agent-audit-kit scan .
```

`aak` is installed as a shorthand for the same command.

As a pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sattyamjjain/agent-audit-kit
    rev: v0.6.3
    hooks:
      - id: agent-audit-kit
```

In CI:

```yaml
# .github/workflows/agent-security.yml
- uses: sattyamjjain/agent-audit-kit@v0.6.3
  with:
    severity: medium
    fail-on: high
    upload-sarif: true
```

The action writes SARIF; upload it with `github/codeql-action/upload-sarif`
to land findings in the GitHub Security tab. Full
[GitHub Action reference](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/github-action.md) ·
[CLI reference](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/cli.md) ·
[pre-commit hook](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/ci-cd.md).

## What it finds

<!-- rule-count:total -->348<!-- /rule-count --> rules across 14 security categories:

| Category | Rules | What it detects |
|----------|:-----:|-----------------|
| **MCP Configuration** | <!-- category-count:MCP_CONFIG -->67<!-- /category-count --> | Missing auth, wildcard CORS, `0.0.0.0` binds, SSRF, OAuth 2.1 and RFC 9728 gaps |
| **Supply Chain** | <!-- category-count:SUPPLY_CHAIN -->110<!-- /category-count --> | Unpinned packages, typosquats, install scripts, and verified CVE version pins |
| **Tool Poisoning** | <!-- category-count:TOOL_POISONING -->30<!-- /category-count --> | Invisible Unicode, prompt injection in tool and parameter descriptions, rug pulls |
| **Secret Exposure** | <!-- category-count:SECRET_EXPOSURE -->18<!-- /category-count --> | Provider keys, tokens in configs and env files, credentials in logs |
| **Agent Config** | <!-- category-count:AGENT_CONFIG -->18<!-- /category-count --> | Permission escalation, auto-approve, headless trust in CI |
| **A2A Protocol** | <!-- category-count:A2A_PROTOCOL -->13<!-- /category-count --> | Missing mutual auth, unbounded delegation, transitive trust |
| **Hook Injection** | <!-- category-count:HOOK_INJECTION -->17<!-- /category-count --> | Hook RCE, exfiltration through lifecycle hooks |
| **Taint Analysis** | <!-- category-count:TAINT_ANALYSIS -->14<!-- /category-count --> | `@tool` parameters reaching shell, SQL, filesystem and network sinks |
| **Transport Security** | <!-- category-count:TRANSPORT_SECURITY -->15<!-- /category-count --> | Cleartext transports, DNS rebinding, session and body-size limits |
| **Legal Compliance** | <!-- category-count:LEGAL_COMPLIANCE -->19<!-- /category-count --> | Copyleft licences, PII surface, and regional AI duties |
| **Trust Boundaries** | <!-- category-count:TRUST_BOUNDARY -->17<!-- /category-count --> | Project-scoped trust, untrusted workspace escalation |
| **MCP Server Card** | <!-- category-count:MCP_SERVER_CARD -->4<!-- /category-count --> | Static audit of SEP-1649 server cards |
| **Composition** | <!-- category-count:COMPOSITION -->3<!-- /category-count --> | Risk that exists only between components, not in any one of them |
| **Agentic Skills** | <!-- category-count:AGENTIC_SKILL -->3<!-- /category-count --> | OWASP Agentic Skills Top 10 surface in skill bundles |

Every finding carries severity, evidence, a file and line, and remediation.
Full detail per rule is in the [rule reference](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/rules.md).

## Why not a hosted scanner

- **Offline and deterministic.** Your code and secrets never leave the machine,
  and the same input always yields the same findings — measured at
  [20/20 identical runs, 0% variance](https://github.com/sattyamjjain/agent-audit-kit/blob/main/benchmarks/determinism/RESULTS.md).
  A scanner with an LLM in the loop cannot promise that, which is what makes CI
  diffs and audit re-runs stable here.
- **Auditor-ready evidence, not just findings.** SARIF plus PDF evidence packs
  mapped to 14 frameworks, a CycloneDX/SPDX SBOM, and an OpenVEX document that
  joins to it on purl.
- **Pin and verify.** `pin` fingerprints a tool surface at approval; `verify`
  re-checks it afterwards. That is the only thing that catches a server which
  behaves until it does not — see the
  [Deadbugz case study](https://github.com/sattyamjjain/agent-audit-kit/blob/main/examples/case-studies/deadbugz-delayed-metadata/README.md).

Precision is measured rather than asserted: a hand-adjudicated
[benign-slice false-positive rate](https://github.com/sattyamjjain/agent-audit-kit/blob/main/benchmarks/false_positive/RESULTS.md)
with a Wilson interval, and any offending rule filed as an issue.

## What we measured

From the [State of MCP Security 2026](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md)
report ([how to cite](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md#how-to-cite-this-report)):

- <!-- report:corpus -->2,303<!-- /report --> distinct public MCP configs scanned.
- <!-- report:noauth-pct -->52.1<!-- /report -->% (<!-- report:noauth-n -->1,200<!-- /report -->) declare a remote server with **no authentication**.
- <!-- report:rfc9728-n -->0<!-- /report --> serve RFC 9728 Protected-Resource-Metadata discovery.
- <!-- report:inline-auth-pct -->100<!-- /report -->% (<!-- report:inline-auth-n -->424<!-- /report -->/<!-- report:inline-auth-d -->424<!-- /report -->) of inline-auth remote configs **hardcode a static credential**.

These regenerate from `results.json` and are asserted in CI, so they cannot
drift from the report.

## Compliance evidence

PDF and text evidence packs mapped to 14 frameworks, including two already in
force that most scanners do not carry: **EU AI Act Article 50** (transparency,
since 2026-08-02) and **Colorado SB 26-189 ADMT** (effective 2027-01-01).

```bash
agent-audit-kit report . --framework eu-ai-act --format pdf
agent-audit-kit sbom . --format cyclonedx -o sbom.cdx.json
agent-audit-kit vex  . -o vex.openvex.json
```

Every control row cites a real clause, and a row the scanner cannot evidence
says so instead of printing a tick. Full list of the <!-- rule-count:total -->348<!-- /rule-count -->
rules mapped to 14 frameworks: [compliance reference](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/owasp-mapping.md).

### OWASP Agentic Top 10 coverage

<!-- owasp-coverage:start -->
| ASI | Title | # rules |
| --- | --- | --- |
| **ASI01** | Goal Hijack | 14 |
| **ASI02** | Tool Misuse | 48 |
| **ASI03** | Memory Poisoning | 73 |
| **ASI04** | Identity & Privilege Abuse | 74 |
| **ASI05** | Cascading Failures | 56 |
| **ASI06** | Unauthorized Capability Acquisition | 48 |
| **ASI07** | Plan Injection | 9 |
| **ASI08** | Agent Communication Poisoning | 5 |
| **ASI09** | Resource Abuse | 18 |
| **ASI10** | Supply-Chain | 21 |
<!-- owasp-coverage:end -->

Complete mapping for OWASP Agentic, OWASP MCP, and the NSA MCP CSI is in the
[standards crosswalk](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/crosswalk/nsa-csi-owasp-agentic.md).

## MCP Security Index

A public leaderboard of scanned public MCP servers, with per-server grade cards
and a 90-day [disclosure policy](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/disclosure-policy.md):
[sattyamjjain.github.io/agent-audit-kit](https://sattyamjjain.github.io/agent-audit-kit/).

<!-- index-cadence -->Last published snapshot: **2026-09-07** (5 snapshots in [`history.json`](https://sattyamjjain.github.io/agent-audit-kit/data/history.json)). The build fails if this date falls more than 10 days behind, so a stalled index reports itself.<!-- /index-cadence -->

## CVE response

Newly disclosed MCP CVEs are triaged and turned into rules as they land,
surfaced by an NVD watcher and logged in
[CHANGELOG.cves.md](https://github.com/sattyamjjain/agent-audit-kit/blob/main/CHANGELOG.cves.md). The measured disclosure-to-rule
latency is published in [docs/cve-latency.md](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/cve-latency.md) and
regenerated from the ledger, not asserted.

## Under the hood

<!-- scanner-count:total -->103<!-- /scanner-count --> scanner modules: AST-based taint analysis for
Python, and regex dangerous-sink scanners for TypeScript/JavaScript and Rust.
<!-- test-count:total -->2,367<!-- /test-count --> tests. 27 CLI commands. Releases are Sigstore-signed
and ship a deterministic rule bundle.

Mechanical fix recipes cover <!-- fix-recipe-coverage:count -->11<!-- /fix-recipe-coverage --> of <!-- rule-count:total -->348<!-- /rule-count --> rules
(<!-- fix-recipe-coverage:pct -->3.2<!-- /fix-recipe-coverage -->%), applied by `agent-audit-kit fix`. That is a scope
decision, not a coverage gap: a recipe ships only where the remediation is
**deterministic and one-line** — exactly one correct edit, confirmable from the
diff. Everything else stays advisory on purpose, because a fix that needs
judgement is a fix that can be wrong silently. [Why the rest stay
advisory](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/why.md).

## Documentation

[Getting started](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/getting-started.md) ·
[CLI reference](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/cli.md) ·
[Rule reference](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/rules.md) ·
[CI/CD](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/ci-cd.md) ·
[Comparison with other scanners](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/comparisons.md) ·
[All documentation](https://github.com/sattyamjjain/agent-audit-kit/tree/main/docs)

## Contributing

Issues and pull requests are welcome — see
[CONTRIBUTING.md](https://github.com/sattyamjjain/agent-audit-kit/blob/main/CONTRIBUTING.md). Adding a rule means a rule definition, a
scanner, and fixtures in both directions; `agent-audit-kit rule lint` checks the
registry invariants.

## Security

Report vulnerabilities per [SECURITY.md](https://github.com/sattyamjjain/agent-audit-kit/blob/main/SECURITY.md). AgentAuditKit
publishes no fixed CVE-response SLA; it publishes the measured latency instead.

## License

Apache-2.0. See [LICENSE](https://github.com/sattyamjjain/agent-audit-kit/blob/main/LICENSE). Apache-2.0 carries an explicit patent
grant, which the organisations that adopt a security tool tend to ask about.
