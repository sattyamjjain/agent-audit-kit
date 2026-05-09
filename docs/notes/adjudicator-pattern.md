# The adjudicator pattern

> *"Static scanners that only fire one regex per rule miss the architectural
> shape; static scanners that adjudicate fire-and-suppress evidence per rule
> catch it."*

AAK rules are not single-shot regex matchers. Every CVE rule (DocsGPT
v0.3.14, GPT-Researcher v0.3.15, Claude Code v0.3.16, the OX MCP-STDIO
class umbrella from v0.3.6) is structured as a **multi-arm
adjudicator** — a small pipeline of evidence collectors and short-
circuit suppressors that together produce a single fire-or-pass
decision per `(rule, file, location)` triple.

The Mozilla security team's published Firefox-hardening triage flow
([Mozilla Hacks 2026-05-07](https://hacks.mozilla.org/2026/05/behind-the-scenes-hardening-firefox/))
walks through the same shape against a different problem: many
parallel detectors against a high false-positive surface, reconciled
by an adjudicator before a patch ships. AAK's adjudicator pattern is
the static-pre-deploy mirror of that runtime triage flow — same
architectural insight, opposite end of the lifecycle.

## The four pieces

Every adjudicator-tier AAK rule has at most four arms. They run in
fixed order; the first arm that produces a verdict short-circuits the
rest.

### 1. Pin arm (the broad detector)

Fires on the manifest pin alone — `package.json`, `package-lock.json`,
`yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `pyproject.toml`,
`Pipfile*`, `poetry.lock`, `uv.lock`, plus git+https / `github:`
shorthand. The pin arm is intentionally broad: any vulnerable pin
fires it. False-positive rate is tolerable because remediation is
mechanical (bump the pin).

### 2. Source / config arm (the narrower detector)

Fires on the **architectural shape** of the vulnerability — the
unsafe SQL construction, the transport-flip permit, the absent
`reject_stdio_transport` guard. Narrower than the pin arm; only
fires when the consumer actually instantiates the unsafe pattern.

### 3. Explicit-reject short-circuit (the suppressor)

A single signal that the consumer has already fixed the architectural
shape — `deny_stdio_transport: true`, `allowed_transports: ["sse"]`,
a sanitiser call inside the same function, a tagged-template SQL
helper. When this arm fires, the source/config arm is suppressed
even when the unsafe shape is structurally present.

### 4. Adjudicator log (the receipt)

Every fire emits a structured `Finding` with `rule_id`, `file_path`,
`line_number`, `evidence`, `remediation`, `cve_references`,
`incident_references`, plus the OWASP / AICM / framework refs. The
log is the public artefact that procurement reviewers and SLA
auditors read — not the rule code, not the regex, not the fire-count
total.

## Why this matters for procurement

A buyer's first question is rarely "how many rules?" — it's "does
this catch *my* shape?" The adjudicator pattern lets us say yes
even for shapes that are not yet a CVE: the pin arm catches the
known package, the source arm catches the architectural class
across packages we haven't named yet, and the explicit-reject
short-circuit lets the buyer suppress the rule once they fix the
shape rather than the package.

## Where each arm lives in the codebase

| Arm | File | Convention |
|---|---|---|
| Pin | `agent_audit_kit/scanners/supply_chain.py` | `_check_<package>_pin(project_root, scanned_files)` |
| Source / config | `agent_audit_kit/scanners/<package>_<shape>.py` | One file per `(package, shape)` pair |
| Explicit-reject | Inside the source/config arm, regex / AST guard | `_REJECTS_*_RE` short-circuit |
| Adjudicator log | `Finding(...)` constructor with full ref-set | `incident_references=["..."]` is the grep anchor |

## External precedent

- Mozilla — *Behind the Scenes: Hardening Firefox* (2026-05-07):
  parallel detectors + adjudicator review, runtime side.
  <https://hacks.mozilla.org/2026/05/behind-the-scenes-hardening-firefox/>
- arXiv 2605.03378 — Provenance-aware decision auditing for
  context-aware prompt injection (2026-05-05): runtime auditor that
  scores tool-call provenance against a context graph.
  Complements AAK's static-pre-deploy adjudicator rather than
  competing. <https://arxiv.org/abs/2605.03378>

## Rule examples in this codebase

- `AAK-DOCSGPT-MCP-STDIO-MITM-001` (v0.3.14) — pin + transport-flip arms.
- `AAK-GPTRESEARCHER-MCP-STDIO-MITM-001` (v0.3.15) — same shape,
  different package.
- `AAK-CLAUDECODE-CVE-2026-40068-PIN-001` (v0.3.16) — pin arm only.
  Claude Code is a binary product, not a code shape we statically
  scan; the source arm doesn't apply, so the adjudicator's pipeline
  collapses to its first arm.
- `AAK-MCP-STDIO-CMD-INJ-001..004` + `AAK-STDIO-001` (v0.3.6) — class
  umbrella. The single rule fires across every Python / TS / Java /
  Rust receiver shape; per-product pin rules then add the named row.
