# The State of MCP Security, 2026

**Scan date:** 2026-07-26 · **Corpus:** 2,303 distinct public MCP server configs · **Tool:** AgentAuditKit (offline, deterministic)

We statically scanned **2,303 distinct public Model Context Protocol server
configurations** — the largest snapshot we know of — and measured what fraction
fail each security rule family. The headline: **more than half of public MCP
servers declare a remote endpoint with no authentication.** Every number below
carries its numerator, denominator, and — where a metric is not computable for
the whole corpus — its coverage.

## Headline findings

| Finding | Rule | Share of corpus |
|---------|------|----------------:|
| Remote MCP server with **no authentication** | `AAK-MCP-001` (critical) | **52.3%** — 1205 of 2,303 |
| Carries at least one **critical** finding | — | 52.8% (1,217) |
| Fetches & executes remote packages via `npx`/`uvx` (supply-chain surface) | `AAK-MCP-005` (medium) | 19.5% (450) |
| OAuth surface with **no RFC 9728** Protected-Resource-Metadata discovery | `AAK-OAUTH-008` (low) | 18.3% (421) |
| Command uses a **relative path** (PATH-hijack surface) | `AAK-MCP-006` (medium) | 7.8% (179) |
| **Secret in the env block** (hardcoded credential) | `AAK-MCP-003` / `AAK-SECRET-007` | 3.0% (70) |
| **stdio launcher injection** — shell interpreter with exec flag / interpolated args | `AAK-MCP-STDIO-LAUNCHER-INJECT-001` (high) | 2.1% (49) |
| URL points to **localhost / internal** network (SSRF surface) | `AAK-MCP-009` (high) | 1.9% (44) |
| Deprecated **SSE** transport (2026-07-28 stateless break) | `AAK-TRANSPORT-003` | 1.6% (36) |

Auth posture, the 2026-07-28 profile:

- **No authentication:** 1205 of 2,303 (**52.3%**).
- **RFC 9728 PRM discovery:** 0 of 2,303 (**0.0%**) — not a single public server
  serves the discovery document the ratified auth spec expects.
- **Remote configs:** 1,648 of 2,303 (71.6%). Of the 421 that embed an inline
  credential, **421 of 421 (100%)** hardcode a static secret rather than
  reference an env var or use OAuth.

## Method

### Corpus construction

Two provenance-tracked sources, deduplicated by configuration content (SHA-256
of the normalised JSON):

| Source | Candidates | In corpus |
|--------|-----------:|----------:|
| GitHub-crawled `.mcp.json` files (`benchmarks/data/`) | 748 | 664 |
| Official MCP Registry, latest-version servers (`registry.modelcontextprotocol.io`) | 1,641 | 1,639 |
| **Combined** | **2,389** | **2,303** |

85 byte-duplicate configs and 1 unparseable file were removed. Registry servers
were fetched on **2026-07-26** via cursor pagination (40-page crawl), filtered to
`isLatest = true` / `status = active`, and each converted to a scannable
`.mcp.json`-shaped config. The registry has grown fast — this snapshot is
**1,641 distinct latest-version registry servers**, up from 710 on 2026-07-19
(2.3×). Provenance for every registry server — name, version, transport, auth
mode, source URL, fetch date — is recorded in `corpus/registry-manifest.json`,
so each number here is reproducible from the committed manifest without
re-fetching.

### Scanning

Each config is scanned in isolation with AgentAuditKit's engine and scored with
the same penalty-based A–F grade the `aak score` command and the MCP Security
Index use. The scan is **offline** (zero network calls) and **deterministic**:
the same corpus yields a byte-identical `results.json` on every run, across
Python hash seeds — the property that makes a published number auditable.

Note on what is and isn't config-detectable: rule families that live in a
client `.mcp.json` — no-auth, launcher injection, relative-path commands, env
secrets, `npx`/`uvx` fetch-execute, transport — fire here. Families that require
**server source** (tool-poisoning `AAK-POISON-*`, taint `AAK-TAINT-*`, the
`AAK-MCP-STDIO-CMD-INJ-*` source detectors) do not fire on a config-only corpus
and are reported as ~0% by construction, not by absence of risk. The MCP CVE
version-pins (`agent_audit_kit/scanners/mcp_cve_pins_2026_07.py`) fire only when
a config pins a specific vulnerable version; registry configs overwhelmingly use
unpinned `npx -y <pkg>` (counted under `AAK-MCP-005`), so pinned-CVE hits are
rare on this corpus.

### Reproduce

```bash
make report          # refreshes results.json from the committed manifest, offline + deterministic
# or, explicitly:
python research/state-of-mcp-2026/run_report.py \
    --corpus benchmarks/data \
    --registry-manifest research/state-of-mcp-2026/corpus/registry-manifest.json \
    --out research/state-of-mcp-2026/results.json
```

Refreshing the corpus itself (the one network step) is separate:
`python research/state-of-mcp-2026/fetch_registry.py --target 5000`.

## Grade distribution (score calibration)

| Grade | Configs | Share |
|:-----:|--------:|------:|
| A | 632 | 27.4% |
| B | 1,426 | 61.9% |
| C | 111 | 4.8% |
| D | 49 | 2.1% |
| F | 85 | 3.7% |

n = 2,303. The median config scores **B**. **1,217 (52.8%)** carry at least one
critical-severity finding — driven almost entirely by the no-auth remote server
class. Most public configs are not catastrophic, but the single most common
public posture is *a remote server anyone can call*.

## Why this matters now — and the two wedges

The market backdrop is a supply-chain and trust crisis, not a scanner gap:

- **Shai-Hulud 2.0** — the self-propagating npm worm that republishes legitimate
  packages with a malicious `preinstall` script and uses GitHub infrastructure as
  C2 — compromised **25,000+ repositories across ~350 maintainers** (Zapier,
  PostHog, Postman), with a *Mini Shai-Hulud* resurgence in May 2026 hitting 170+
  npm packages ([Microsoft Security](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)).
  Our finding that **19.5% of public MCP servers `npx`/`uvx`-fetch-and-execute
  unpinned remote packages** is that same blast radius, one `.mcp.json` away.
- **NSA MCP hardening guidance** — the NSA AISC *MCP Security Design
  Considerations* CSI (U/OO/6030316-26, 2026-05-20) put MCP posture on
  government letterhead. It is prose, not a checklist — so the gap is *evidence*,
  not awareness.

Against that backdrop, two things a free hosted scanner structurally can't match:

1. **Offline + deterministic scanning.** Zero network calls in the default scan
   path; the same input always yields the same finding (no model in the loop), so
   CI diffs, audit re-runs, and regression baselines stay byte-stable. This report
   is itself the proof: every number regenerates identically from the committed
   manifest.
2. **A compliance-evidence crosswalk.** Every rule is mapped — rule by rule — to
   the **NSA MCP Security CSI** control it evidences and its **OWASP Agentic
   Top-10 (2026)** slot (also OWASP MCP Top-10 and EU AI Act), emitted as
   machine-readable evidence: `agent-audit-kit --emit-coverage --format json`
   (see [`docs/coverage.json`](../../docs/coverage.json) and
   [`docs/crosswalk/nsa-csi-owasp-agentic.md`](../../docs/crosswalk/nsa-csi-owasp-agentic.md)).
   That turns a finding into audit evidence an assessor can cite.

We are **not** claiming to be first — public MCP-security surveys and vendor
disclosures predate this. What is offline, deterministic, and standards-mapped is
the combination.

## 2026-07-28 stateless-transport exposure

The ratified 2026-07-28 spec removes the `initialize` handshake and the
`Mcp-Session-Id` header (stateless core). The measurable proxy in a client config
is deprecated **SSE** transport: **36 configs (1.6%)** still declare it and will
break when the session model goes. streamable-HTTP dominates the fresh corpus
(1,726 server entries) over stdio (1,347) and SSE (62).

## Responsible-disclosure posture

Findings here are aggregate and de-identified; no server is named as vulnerable.
The corpus is public registry metadata and public GitHub `.mcp.json` files. AAK's
90-day [disclosure policy](../../docs/disclosure-policy.md) governs any per-server
notification.

## Limitations

- **Config-only for source-based families.** Tool-poisoning and taint need server
  source; their ~0% here is a coverage boundary, not an all-clear (stated above).
- **Registry snapshot is a 40-page crawl** (1,641 distinct latest); the registry
  is larger and still growing, so the true corpus is a floor.
- **Auth posture is inferred from declared config**, not a live probe — a server
  could enforce auth the config doesn't declare (and vice-versa).
- **"Benign" is not claimed.** This measures declared posture, not exploitability;
  see the [benign-slice false-positive rate](../../benchmarks/false_positive/RESULTS.md)
  for how precise the high-severity findings are.
