# SARIF `properties.runtime_context` extension (proposal)

**Status:** Spec only. No code today; scoping for v0.3.11.
**Driver:** O12 — AIVSS v0.8 scoring (shipped v0.3.10) needs a
documented runtime-context plumbing path so the AARS multipliers can
reflect actual deployment shape rather than per-rule defaults.

## Problem

`agent_audit_kit.scoring.aivss.score_finding(rule_meta, runtime_ctx)`
already accepts a runtime-context dict, but AAK's static SARIF emitter
has nowhere to derive the context from. We need a SARIF property
shape that tools producing AAK SARIF (the scanner itself, the parity
decorator, `aak watch`) can populate consistently, and that downstream
scorers can consume without guessing.

## Proposal

Add `properties.runtime_context` to each SARIF `result`. Shape:

```jsonc
{
  "properties": {
    "runtime_context": {
      "has_tool_use": true,
      "internet_egress": true,
      "persistent_memory": false,
      "human_in_loop": false,

      "network_exposure": "internet",        // "internal" | "vpc" | "internet"
      "data_sensitivity": "regulated",       // "public" | "internal" | "confidential" | "regulated"
      "blast_radius": "tenant"               // "pod" | "host" | "cluster" | "tenant"
    }
  }
}
```

The first four flags map directly onto AIVSS v0.8 `AARSVector`. The
last three map onto `EnvironmentalVector`. AAK static SARIF stays
standards-clean — `runtime_context` is purely additive — and the
scorer reads through to it via `result["properties"]["runtime_context"]`.

## Producers

| Producer | How it derives the context |
|----------|----------------------------|
| `aak scan` static                  | Per-rule defaults in `aivss-v08-defaults.json`, optionally overridden via `.agent-audit-kit.yml > runtime_context:` |
| `@aak.parity.check` decorator      | `has_tool_use=True`, `human_in_loop=False`, `internet_egress` from a `dimensions=` entry if present |
| `aak watch`                        | Inherits the YAML default from the project being watched |
| User-provided in CI                | `agent-audit-kit scan --runtime-context-file ctx.yaml` (queues for v0.3.11) |

## Backwards compatibility

`runtime_context` is optional — older AAK SARIF without it falls back
to the per-rule defaults. Older readers that ignore unknown
`properties` are unaffected.

## Open questions

1. Should `runtime_context` live at the `run` level or per-`result`?
   Per-result is more flexible (a single project can have mixed
   exposures); per-run is cheaper. Default per-`result`, allow
   per-`run` as an inheritance fallback.
2. Should AAK ship a JSON Schema for the extension? Likely yes once
   AIVSS v0.9 stabilises; v0.8 is still in public review.

## Sequence

- v0.3.10 — this spec, AIVSS scorer accepts the dict shape.
- v0.3.11 — `aak scan` emits `runtime_context` from `.agent-audit-kit.yml`,
  parity decorator populates it, JSON Schema lands in `schema/`.
- v0.3.12 — `aak score` emits a per-finding rationale string explaining
  which AARS multipliers were applied.
