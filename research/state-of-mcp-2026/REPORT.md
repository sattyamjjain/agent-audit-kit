# The State of MCP Server Authentication, 2026

**Scan date:** 2026-07-19 · **Corpus:** 1,374 distinct public MCP server configs · **Tool:** AgentAuditKit (offline, deterministic)

A static scan of 1,374 distinct public Model Context Protocol server
configurations, measuring authentication posture and exposure to the two
scheduled MCP protocol changes (2026-07-28 stateless transport, 2027-07-28
feature removals). Every number below carries its numerator, denominator, and —
where a metric is not computable for the whole corpus — its coverage.

## Method

### Corpus construction

The corpus is two provenance-tracked sources, deduplicated by configuration
content (SHA-256 of the normalised JSON):

| Source | Candidates | Distinct after dedup |
|--------|-----------:|---------------------:|
| GitHub-crawled `.mcp.json` files (`benchmarks/data/`) | 748 | 664 |
| Official MCP Registry, latest-version servers (`registry.modelcontextprotocol.io`) | 710 | 710 |
| **Combined** | **1,458** | **1,374** |

83 byte-duplicate configs and 1 unparseable file were removed. Registry servers
were fetched on 2026-07-19 via cursor pagination, filtered to
`isLatest = true` / `status = active`, and each converted to a scannable
`.mcp.json`-shaped config. Provenance for every registry server — name, version,
transport, auth mode, source URL, fetch date — is recorded in
`corpus/registry-manifest.json`, so each number here is reproducible from the
committed manifest without re-fetching.

### Scanning

Each config is scanned in isolation with AgentAuditKit's engine and scored with
the same penalty-based A–F grade the `aak score` command and the MCP Security
Index use. The scan is offline (no network) and deterministic: the same corpus
yields a byte-identical `results.json` on every run, across Python hash seeds.

### Reproduce

```bash
make report          # refreshes results.json from the committed manifest, offline
# or, explicitly:
python research/state-of-mcp-2026/run_report.py \
    --corpus benchmarks/data \
    --registry-manifest research/state-of-mcp-2026/corpus/registry-manifest.json \
    --out research/state-of-mcp-2026/results.json
```

Refreshing the corpus itself (the one network step) is separate:
`python research/state-of-mcp-2026/fetch_registry.py --target 700`.

## Findings

### Grade distribution (score calibration)

| Grade | Configs | Share | Cumulative |
|:-----:|--------:|------:|-----------:|
| A | 500 | 36.4% | 36.4% |
| B | 643 | 46.8% | 83.2% |
| C | 97 | 7.1% | 90.3% |
| D | 49 | 3.6% | 93.9% |
| F | 85 | 6.2% | 100% |

n = 1,374. The median config scores **B**; the top 36.4% score **A**. **494
configs (36.0%)** carry at least one critical-severity finding and **164 (11.9%)**
at least one high. Operationally: most public configs are not catastrophic, but a
third contain something that, in a scanned deployment, would be a critical
finding.

### No authentication at all

**482 of 1,374 configs (35.1%)** declare a remote MCP server reachable with no
authentication (`AAK-MCP-001`). Of the 801 configs (58.3%) that declare any
remote server, that is the single most common finding. Operationally: a client
using one of these configs connects to a network-reachable MCP server that
performs no access control at the transport layer.

### RFC 9728 Protected Resource Metadata discovery

**0 of 1,374 configs (0.0%)** reference RFC 9728 Protected Resource Metadata
discovery (`/.well-known/oauth-protected-resource`, `authorization_servers`, or
`resource_metadata`). This holds across the whole corpus, not only the 748-config
baseline. Operationally: no public config in this sample uses the
server-advertised discovery mechanism the ratified 2025-11-25 auth spec defines;
authentication, where present, is arranged out of band.

### Remote auth that hardcodes a static credential

Of the configs that authenticate to a remote server by embedding a credential
inline, **318 of 318 (100%)** do so with a static credential and no PRM discovery
path (`AAK-OAUTH-008`). This matches the 36-of-36 baseline exactly at ~9× the
scale. Operationally: every remote-auth config in the sample presents a
pre-shared bearer/token header rather than obtaining an audience-bound token
through discovery.

### Transport distribution

Across all declared server entries (a config may declare several):

| Transport | Server entries |
|-----------|---------------:|
| stdio | 1,265 |
| streamable-http | 900 |
| sse | 41 |
| unknown | 7 |

stdio (local subprocess) remains the most common transport; streamable-HTTP is
the dominant remote transport; deprecated SSE is a small residual.

### Rule-family and OWASP-MCP distribution

Configs with ≥1 finding, by AAK rule family and by OWASP MCP Top 10 slot:

| AAK family | Configs | Share | | OWASP MCP | Configs | Share |
|---|--:|--:|---|---|--:|--:|
| `AAK-MCP-*` | 1,370 | 99.7% | | MCP07:2025 (authorization) | 1,370 | 99.7% |
| `AAK-OAUTH-*` | 318 | 23.1% | | MCP01:2025 (token/secret) | 385 | 28.0% |
| `AAK-SECRET-*` | 70 | 5.1% | | MCP03:2025 (tool/launch integrity) | 377 | 27.4% |
| `AAK-TRANSPORT-*` | 26 | 1.9% | | MCP10:2025 (supply chain) | 377 | 27.4% |
| | | | | MCP04:2025 (command injection) | 205 | 14.9% |
| | | | | MCP09:2025 (transport) | 44 | 3.2% |

### Top findings (advisory-posture rules excluded)

| # | Rule | Severity | Configs | Share |
|--:|---|:---:|--:|--:|
| 1 | `AAK-MCP-001` — remote server without authentication | **CRITICAL** | 482 | 35.1% |
| 2 | `AAK-MCP-005` — `npx`/`uvx` fetch-and-execute remote packages | MEDIUM | 377 | 27.4% |
| 3 | `AAK-OAUTH-008` — no RFC 9728 PRM discovery | LOW | 318 | 23.1% |
| 4 | `AAK-MCP-006` — command uses a relative path | MEDIUM | 175 | 12.7% |
| 5 | `AAK-SECRET-007` — secret in server env block | MEDIUM | 70 | 5.1% |
| 6 | `AAK-MCP-003` — env exposes secrets to the tool process | HIGH | 70 | 5.1% |
| 7 | `AAK-MCP-STDIO-LAUNCHER-INJECT-001` — stdio server launches a shell interpreter | HIGH | 49 | 3.6% |
| 8 | `AAK-MCP-009` — server URL points at localhost / internal network | HIGH | 44 | 3.2% |
| 9 | `AAK-TRANSPORT-003` — deprecated SSE transport | MEDIUM | 21 | 1.5% |
| 10 | `AAK-MCP-004` — excessive number of servers declared | HIGH | 12 | 0.9% |

## Migration exposure

### 2026-07-28 stateless transport revision

The 2026-07-28 revision makes the protocol stateless: SEP-2575 makes the
`initialize`/`initialized` handshake optional and SEP-2567 removes the
`Mcp-Session-Id` header and the SSE session model.

**Config-measurable proxy: 26 of 1,374 configs (1.9%)** declare a deprecated-SSE
transport (`AAK-TRANSPORT-003`, or a `type: sse` entry), which is the surface
being removed. **Coverage note:** the `initialize`-handshake and
`Mcp-Session-Id` dependencies are runtime/server-code behaviours that a client
`.mcp.json` config does not express — they are **not** computable from this
corpus. The SSE-transport share is the only config-visible signal; the true
protocol-level exposure requires scanning server source, which this report does
not do.

### 2027-07-28 feature-removal clock (Roots / Sampling / Logging / Dynamic Client Registration)

**Config-measurable: 0 of 1,374 configs (0.0%).** These are runtime capabilities
negotiated at connection time (or server-side auth features), not fields declared
in a client `.mcp.json` config. **Coverage note:** this metric is therefore not
measurable from the config corpus at all — a `0` here means "no config expresses
it," not "no server uses it." Measuring real Roots/Sampling/Logging/DCR usage
requires scanning server implementations; AAK ships the rules
(`AAK-MCP-DEPRECATED-001..003`, `AAK-MCP-STATELESS-001..004`) for that, but the
population on the 2027-07-28 removal clock cannot be quantified from
configurations.

## Responsible-disclosure posture

This report publishes only aggregate statistics. No individual server is named,
graded, or linked. Where AAK's public MCP Security Index does surface per-server
findings, it follows a coordinated 90-day
[disclosure policy](../../docs/disclosure-policy.md): affected maintainers are
notified privately before anything is visible, with the rule ID, file/line
pointer, remediation, and severity.

## Limitations

- **Sample bias.** The corpus is public registry servers plus GitHub-crawled
  configs. That is not the whole MCP population: private/internal servers,
  unpublished configs, and enterprise deployments are absent, and registry
  servers skew toward projects deliberately published for discovery. Percentages
  describe *this sample*, not "all MCP servers."
- **Config-level, not runtime.** The scan reads static configurations, not live
  servers. It cannot confirm that a no-auth config points at a truly open server
  (the operator may enforce auth elsewhere), nor measure runtime-negotiated
  capabilities — hence the explicit coverage notes on the two migration metrics.
- **Conversion fidelity.** Registry servers are converted to `.mcp.json` shape
  from their `remotes`/`packages` metadata; a converted config reflects the
  registry's declared transport and auth, which may differ from a server's actual
  deployment.
- **Point in time.** Numbers are as of the 2026-07-19 fetch. The registry holds
  ~17k latest-version servers; this sample is 710 of them plus the 664 crawled
  configs. Re-running `make report` on a refreshed manifest will move the numbers.

---

*Raw aggregate: [`results.json`](results.json). Prior 664-config run:
[`PREVALENCE.md`](PREVALENCE.md) (superseded by this expanded corpus).*
