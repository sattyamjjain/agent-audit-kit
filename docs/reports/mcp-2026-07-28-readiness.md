# MCP 2026-07-28 auth-profile readiness: a scan of 748 public MCP configs

**Scan date:** 2026-07-18 · **Re-validated:** 2026-09-04 · **Tool:** AgentAuditKit `--profile mcp-2026-07-28` · **Corpus:** 748 public `.mcp.json` configurations (`benchmarks/data/`)

> **Still current, and now checked.** Every number below was re-derived from the
> corpus on **2026-09-04** and all nine reproduce exactly: the corpus has not
> changed since the July scan, and `AAK-OAUTH-006/007/008` are all still in the
> registry. This is no longer a claim you have to take on trust —
> `tests/test_readiness_report_is_current.py` asserts the table against a fresh
> `scripts/mcp_2026_07_28_readiness.py` run, so the day the corpus grows, this
> report fails CI instead of quietly becoming a confident wrong number.
>
> Status note: the MCP 2026-07-28 specification was a **release candidate** when
> this report was written (RC locked 2026-05-21) and was published on
> **2026-07-28**, before the re-validation above. The two requirements it
> measures against — RFC 8707 Resource Indicators and RFC 9728 Protected Resource
> Metadata — were already **MUST**s in the *ratified* MCP 2025-11-25
> authorization spec that the 07-28 profile builds on, which is why the readiness
> question was live before publication and remains live after it.

## Summary

We scanned 748 public MCP client configurations against the three
authorization-hardening checks of the 2026-07-28 auth profile (RFC 9207 `iss`
validation, RFC 8707 resource indicators, RFC 9728 Protected Resource Metadata
discovery). The single measurable, unambiguous result from a config-level corpus:

**None of the 748 configurations reference RFC 9728 Protected Resource Metadata
discovery. Of the 202 configs that connect to a remote (HTTP/SSE) MCP server, 36
carry a static, embedded credential — and all 36 (100%) do so with no
Protected-Resource-Metadata discovery path.** Under the 2026-07-28 profile these
clients would not obtain an audience-bound token through server-advertised
discovery; they present a pre-shared secret instead.

This is a config-posture finding, not a vulnerability count. It measures whether
public MCP deployments are *structured* the way the ratified auth spec expects,
not whether any specific server is exploitable.

## What the profile checks

| Rule | RFC | Requirement (ratified MCP 2025-11-25 auth spec) |
|------|-----|--------------------------------------------------|
| `AAK-OAUTH-006` | RFC 9207 | Client validates the `iss` authorization-response parameter (mix-up defense; the RC's SEP-2468 makes it explicit) |
| `AAK-OAUTH-007` | RFC 8707 | Client sends the `resource` indicator on auth + token requests so tokens are audience-bound |
| `AAK-OAUTH-008` | RFC 9728 | Server advertises its authorization server(s) via Protected Resource Metadata at `/.well-known/oauth-protected-resource`; clients discover auth from it rather than embedding a static credential |

## Findings

| Metric | Count | Of denominator |
|--------|------:|----------------|
| Public MCP configs scanned | 748 | — |
| Server entries across all configs | 1,724 | — |
| Remote (HTTP/SSE/URL) server entries | 344 | 20.0% of entries |
| Configs declaring ≥1 remote server | 202 | 27.0% of configs |
| Remote configs embedding a static credential | 36 | 17.8% of remote configs |
| Configs referencing RFC 9728 PRM discovery | **0** | **0.0% of configs** |
| `AAK-OAUTH-008` (no PRM discovery) — files flagged | **36** | 100% of remote-auth configs |
| `AAK-OAUTH-007` (no resource indicator) — files flagged | 0 | see *Limitations* |
| `AAK-OAUTH-006` (no `iss` validation) — files flagged | 0 | see *Limitations* |

The 36 flagged configs authenticate to a remote MCP server by hardcoding an
`Authorization: Bearer …` / `token …` header or an `auth` block directly in the
`.mcp.json`. That is a working pattern today, but it is orthogonal to the
discovery-based flow the 07-28 profile assumes: none advertise or consult a
Protected Resource Metadata document, so a client cannot learn which
authorization server issues audience-bound tokens for the resource — it must be
told the credential out of band.

## Limitations (read before quoting a number)

- **This corpus is client-side `.mcp.json` configs, not server source.** RFC 9207
  `iss` validation and RFC 8707 `resource` indicators are properties of OAuth
  *flow code* (the client's authorization/token exchange), which a connection
  config does not contain. Zero configs contained such flow code, so
  `AAK-OAUTH-006` and `AAK-OAUTH-007` returned 0 here — that is a property of the
  corpus, **not** evidence that public clients validate `iss` or send `resource`.
  The two rules are in the profile for scanning client/server *source trees*;
  they are inert against configuration files.
- **`AAK-OAUTH-008`'s config arm proves absence of a discovery path in the
  config, not that the target server fails to serve PRM.** A remote server may
  still expose `/.well-known/oauth-protected-resource`; what we measured is that
  the *client config* does not use it and instead embeds a credential.
  Confirming the server side would require probing each live endpoint, which this
  offline scan deliberately does not do.
- **Severity is LOW by design.** A hardcoded credential to a remote MCP server is
  a conformance/readiness gap, not an exploit. The report should be read as "how
  far is the public ecosystem from the 07-28 discovery model," not "how many
  servers are vulnerable."

## Reproduce it

```bash
# One-command profile scan (emits the 36 AAK-OAUTH-008 findings):
agent-audit-kit scan benchmarks/data --profile mcp-2026-07-28 --format json

# Full breakdown table above (deterministic — identical every run):
python scripts/mcp_2026_07_28_readiness.py --json
```

The scan is offline and deterministic: the same corpus yields the same counts on
every run, so this report can be regenerated and diffed as the corpus grows.

## What "ready" looks like

A 2026-07-28-ready remote MCP deployment:

1. **Server** serves RFC 9728 Protected Resource Metadata at
   `/.well-known/oauth-protected-resource` with an `authorization_servers` entry,
   and returns it via the `resource_metadata` field of a `401 WWW-Authenticate`
   challenge.
2. **Client** discovers the authorization server from that metadata, sends the
   RFC 8707 `resource` parameter so the issued token is audience-bound to the
   server, and validates the RFC 9207 `iss` parameter on the authorization
   response.

None of the 748 public configs are structured this way today. That promise of a
rolling re-run is now kept by CI rather than by intention: the table is asserted
against a fresh derivation on every test run, so a change in the corpus shows up
as a failure the same day it lands. As of the 2026-09-04 re-validation, nothing
has changed — publication of the spec on 2026-07-28 did not move the public
config posture.

---

*Method: AgentAuditKit is a deterministic, offline static scanner. Corpus and
rule set are versioned in this repository; see `benchmarks/data/`,
`agent_audit_kit/presets/mcp-2026-07-28.yaml`, and
`scripts/mcp_2026_07_28_readiness.py`.*
