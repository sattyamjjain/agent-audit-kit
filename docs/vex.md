# VEX: exploitability beside the SBOM

`agent-audit-kit sbom` answers *what do you ship*. `agent-audit-kit vex`
answers *and are you exploitable*. The two are meant to travel together.

```bash
agent-audit-kit sbom . --format cyclonedx -o sbom.cdx.json
agent-audit-kit vex  .                    -o vex.openvex.json
```

Both documents identify products by the same [purl](https://github.com/package-url/purl-spec),
because both are built from the same package discovery pass. A consumer joins
them on string equality, with no mapping table:

```bash
jq -r '.statements[] | "\(.products[0]."@id")\t\(.vulnerability.name)\t\(.status)"' vex.openvex.json
# pkg:npm/mcp-grafana@1.0.0   CVE-2026-19516   affected
```

```bash
jq -r '.components[] | "\(.purl)\t\(.name)"' sbom.cdx.json
# pkg:npm/mcp-grafana@1.0.0   mcp-grafana
```

The output is [OpenVEX v0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
(`"@context": "https://openvex.dev/ns/v0.2.0"`). It is generated offline, from
the same scan the rest of the tool runs. No account, no network call, no
upload.

## The three statuses

OpenVEX defines four statuses. This emitter produces three.

| Status | When it is emitted |
|--------|--------------------|
| `affected` | A rule covers this package for this CVE and the pinned version falls inside the vulnerable range, or upstream ships no fix at all and installation is itself the exposure. Carries an `action_statement` with the remediation, as the spec requires. |
| `fixed` | A rule covers this package for this CVE and the pinned version is at or above the fix floor the rule knows about. |
| `under_investigation` | The package is in scope for the CVE but its version string is not one this tool can order, or a finding for the CVE landed on the config that declares this product while the rule set carries no version range for it. |

## Why `not_affected` is refused

The fourth status is `not_affected`, and this tool never emits it. That is a
deliberate refusal, not a gap waiting to be filled.

The spec requires a `not_affected` statement to carry a `justification` from a
closed enum — `component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary`,
`inline_mitigations_already_exist` — or a free-text `impact_statement`.

Every one of those is a claim about runtime reachability or deployed
mitigation. AgentAuditKit reads dependency manifests and MCP configuration
files. It does not execute the project, does not trace call paths into
vendored code, and does not observe the deployed environment. It establishes
none of those justifications, so it asserts none of them.

The failure mode this avoids is specific and expensive: a downstream consumer
filters a genuine exposure out of their triage queue because an upstream tool
claimed safety it never actually established. A wrong `not_affected` is worse
than no statement.

So where a human analyst would write "not affected", this emitter writes
nothing. VEX has no completeness requirement. An absent statement asserts
nothing, which is the honest position when nothing has been established.
Under-claiming is the intended bias.

## What is not covered

- Products come from MCP server packages declared with an explicit version in
  MCP configuration files. A server launched unpinned (`npx @scope/server`
  with no `@version`) produces no SBOM component, so it produces no VEX
  statement either. Pin it and both documents pick it up.
- Version-range knowledge comes from the rule set's pin tables. A CVE the rule
  set carries without a package-and-floor pairing can reach
  `under_investigation` but never `affected` or `fixed`.

## Determinism

The document `@id` is a SHA-256 over the sorted (product purl, CVE, status)
triples, so the same tree and the same scan produce a byte-identical document.
Re-running in CI does not churn the artifact. The `timestamp` field moves, and
is injectable by callers that need it pinned.

Document ids are minted under `https://sattyamjjain.github.io/agent-audit-kit/vex/`
rather than under `openvex.dev`. The spec requires a unique IRI and does not
require it to resolve, but a namespace the emitter's author does not control
cannot actually guarantee uniqueness.

## Why now

The EU Cyber Resilience Act's reporting obligations are **already live**. Since
**11 September 2026**, Article 14 of Regulation (EU) 2024/2847 requires a
manufacturer to report an actively exploited vulnerability in a product with
digital elements to ENISA and the coordinating CSIRT on a staged clock: an early
warning within **24 hours** of becoming aware, a technical notification within
**72 hours**, and a final report within **14 days**. It applies to products
already on the EU market, not only to ones placed on it after that date. The
Annex I obligations, including the machine-readable SBOM and CE marking, follow
at **11 December 2027**.

Those two dates are easy to collapse into one, and this page did exactly that
until 2026-09-12: it named 11 December 2027 as the date reporting begins, which
is wrong by fifteen months in the direction that lets a reader relax. The
correct pair was already recorded elsewhere in this repository before the error
was written.

What the pair means in practice is that a 24-hour clock is the binding
constraint today and an SBOM is not sufficient to answer it. An SBOM lists what
you ship. The question a regulator or a customer actually asks under that clock
is whether a listed component is exploitable in the product as shipped, and
whether you can say so quickly and in a form they can machine-read. That is the
question VEX answers, which is why the emitter exists and why it refuses to
answer it with a status the scan did not establish.
