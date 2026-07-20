# Benign-slice HIGH/CRITICAL false-positive rate — AgentAuditKit

> Generated from `benchmarks/false_positive/run.py` over a benign slice derived
> by `corpus.py`. Run date **2026-07-20**. Offline, deterministic, no LLM.
> Reproduce: `python benchmarks/false_positive/run.py`.

## Headline

On a **368-config benign slice** of public MCP servers, AgentAuditKit produced
**4 HIGH/CRITICAL findings** (1.1% of the slice, Wilson 95% CI [0.4%, 2.8%]).
Hand-adjudicated: **2 false positives, 1 true positive, 1 ambiguous**.

**Benign-slice HIGH/CRITICAL false-positive rate = 2 / 4 = 50.0%** (Wilson 95%
CI **[15.0%, 85.0%]**).

This number is deliberately labelled *benign-slice HIGH/CRITICAL false-positive
rate* — not "false-positive rate" unqualified. It says: of the small number of
high-severity findings AAK raises on servers that look benign, half were wrong.
Both false positives are a single, fixable root cause (below), and the interval
is wide because n is small — both stated plainly rather than smoothed over.

## Method

### Reuse, not reimplementation

The benchmark runs the shipped engine; it contains no scanner or scorer of its
own. It reuses:

- `agent_audit_kit.engine.run_scan` — the scan entrypoint the `scan` CLI drives.
- `agent_audit_kit.rules.builtin.RULES` — rule titles, severities, families.
- the committed corpus manifest
  `research/state-of-mcp-2026/corpus/registry-manifest.json` (1,374 configs).

### Pre-registered benign predicate

A server is in the benign slice iff ALL hold (see `corpus.py`; also pre-registered
in the repo README):

1. It is an **official MCP Registry** latest-version server.
2. Its registry status is **active**.
3. It **declares an auth mode** — `static-credential`, `header-nonsecret`, or
   `local-stdio` (i.e. not `none`/`unknown`).
4. It is **not in any CVE/advisory feed AAK ships** (`data/vuln_db.json` package
   names + the CVE version-pin package names).

"Benign" is a property of the server's own published metadata. It is **not**
defined as "AAK found nothing" — that would make the measurement circular.

**Resulting n = 368** (291 static-credential, 76 local-stdio, 1 header-nonsecret;
26 declared-auth servers were excluded for appearing in a shipped CVE feed).

**Stars substitution (honesty).** The commonly-suggested "repo ≥ N stars"
conjunct is *not* used: neither the MCP Registry API nor the cached raw data
exposes GitHub stars or a repository URL, and fetching stars for hundreds of
repos would require a networked GitHub-API pass — this benchmark is offline by
construction. Predicate (1)+(2) is the offline curation proxy that stands in for
the stars signal.

## Findings profile (n = 368)

793 findings total (2.15 per config), almost all low-severity / advisory:

| Severity | Findings |
|----------|---------:|
| critical | 4 |
| high | 0 |
| medium | 441 |
| low | 348 |

### Noisiest rules overall (all severities)

| Rule | Severity | Findings | Note |
|------|:--------:|---------:|------|
| `AAK-MCP-ATTEST-001` | MEDIUM | 368 | Advisory-posture rule — fires on every config (no attestation); excluded from the report headline as advisory. |
| `AAK-OAUTH-008` | LOW | 275 | Expected on static-credential servers (no RFC 9728 discovery). |
| `AAK-MCP-005` | MEDIUM | 73 | `npx`/`uvx` fetch-and-execute — a real supply-chain pattern, MEDIUM. |
| `AAK-MCP-007` | LOW | 73 | Advisory-posture. |
| `AAK-MCP-001` | **CRITICAL** | 4 | The only HIGH/CRITICAL rule that fired — adjudicated below. |

The MEDIUM count is inflated by one advisory rule (`AAK-MCP-ATTEST-001`) that
fires on 100% of configs by design; it is not an exploitable misconfiguration.
Only `AAK-MCP-001` produced HIGH/CRITICAL findings, so it is the whole of the FP
surface here.

## Adjudication (single rater, 2026-07-20)

Full table in [`triage.md`](triage.md). Summary:

| # | Rule | Config | Verdict | Reason |
|--:|------|--------|:------:|--------|
| 1 | `AAK-MCP-001` | `ai.nefesh/human-state` | **FP** | `X-Nefesh-Key` API-key header = auth; rule only sees `Authorization`/`Bearer`. |
| 2 | `AAK-MCP-001` | `ai.satoshidata/wallet-intelligence` | **FP** | `X-WR-API-Key` API-key header = auth; same gap. |
| 3 | `AAK-MCP-001` | `ai.lattiq/x402-trading-signals` | ambiguous | `X-PAYMENT` (x402 pay-to-access) gates access but isn't identity auth. |
| 4 | `AAK-MCP-001` | `ai.spala/public-mcp` | TP | only header is `Accept`; genuinely no auth (server named `public-mcp`). |

### Root cause + fix filed

Both false positives are the same gap: **`AAK-MCP-001` treats a remote server as
unauthenticated unless it sees an `Authorization`/`Bearer` header, missing custom
API-key credential headers** (`X-*-Key`, `X-API-Key`, `Api-Key`). Filed as
[#475](https://github.com/sattyamjjain/agent-audit-kit/issues/475). Publishing the
bad number and the fix is the point of this benchmark.

## Limitations (stated plainly)

- **"Benign" is a proxy.** A declared-auth, active, non-CVE registry server is a
  reasonable stand-in for "correctly configured," but it is not ground truth —
  some of these servers may be misconfigured in ways not visible in their
  registry metadata, and some flagged issues may be real.
- **Single rater, no inter-rater agreement.** All verdicts are the maintainer's.
  There is no second independent adjudicator, so no agreement statistic is
  reported. A different rater might move the ambiguous case.
- **Small n → wide interval.** Only 4 HIGH/CRITICAL findings arose, so the
  Wilson 95% CI on the FP rate spans [15%, 85%]. The point estimate (50%) should
  not be read as precise; the interval is the honest summary.
- **Config-level + conversion fidelity.** Registry servers are converted to
  `.mcp.json` shape from their `remotes`/`packages` metadata (first remote only),
  so a multi-remote server's auth may be under-represented in the scanned config.
- **Scope is HIGH/CRITICAL.** MEDIUM/LOW findings (the bulk of the volume) are not
  adjudicated here; this measures the false-positive rate of the severities that
  drive operational action.
