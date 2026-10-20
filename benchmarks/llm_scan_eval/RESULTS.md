# `--llm-scan` per-model eval: results

> Run on **2026-10-20** against AgentAuditKit **0.6.23** (commit `be0a3720`) with the
> product's own request: system prompt SHA-256 `1920e49dfc87665f18b341e703ba1b73adc997a192ae9552a53c4f51e21565be`,
> `effort: low`, `max_tokens: 4096`, structured-output verdict schema, no server-side
> fallback (the Batch API rejects it, so a refusal is measured as a refusal). The method
> is in [README.md](README.md); every number below is recomputed by `score.py` from the
> text-free receipts in `receipts/<model>/`.

## The set

MCPTox, parsed by `benchmarks/mcptox/corpus.py` from the pinned release and written
as the eval's JSONL by `benchmarks/mcptox/build.py --jsonl` (file SHA-256
`385df742114441cc3e9ef65f75db17dff67c4aaa5e3c053a6954c64e42bf0375`): **1,701 tools on
45 servers, 1,348 poisoned and 353 clean**. The poisoned descriptions fall into the
dataset's three templates (211, 519 and 618 cases) and eleven risk categories. The
dataset carries no license, so neither the cases nor any reply text is committed.

Each model got the same 5,103 requests in one batch: all 1,701 cases, three runs each
(`c<case>-r<run>`). No input was truncated, every request succeeded (0 errored, 0
expired), and every reply came from the model requested.

## Headline, per model and run

Recall is poisoned tools the model **flagged** over all 1,348. A refusal is not a
catch: the CLI reports it as not analyzed (AAK-LLM-002) and the scan INCOMPLETE. It
is listed beside recall because a human does see it. FPR is clean tools flagged over
353. Intervals are Wilson 95%.

| Model | Run | Flagged | Recall | 95% CI | Declined (refusal) | Judged clean | Clean tools flagged | FPR | 95% CI |
|---|---|---:|---:|---|---:|---:|---:|---:|---|
| claude-haiku-5-5 | 1 | 1,332 | 98.8% | [98.1%, 99.3%] | 0 | 16 | 1 | 0.3% | [0.1%, 1.6%] |
| claude-haiku-5-5 | 2 | 1,332 | 98.8% | [98.1%, 99.3%] | 0 | 16 | 1 | 0.3% | [0.1%, 1.6%] |
| claude-haiku-5-5 | 3 | 1,334 | 99.0% | [98.3%, 99.4%] | 0 | 14 | 1 | 0.3% | [0.1%, 1.6%] |
| claude-sonnet-5-5 | 1 | 1,275 | 94.6% | [93.2%, 95.7%] | 60 | 13 | 0 | 0.0% | [0.0%, 1.1%] |
| claude-sonnet-5-5 | 2 | 1,272 | 94.4% | [93.0%, 95.5%] | 63 | 13 | 0 | 0.0% | [0.0%, 1.1%] |
| claude-sonnet-5-5 | 3 | 1,277 | 94.7% | [93.4%, 95.8%] | 58 | 13 | 0 | 0.0% | [0.0%, 1.1%] |
| claude-opus-5-5 | 1 | 744 | 55.2% | [52.5%, 57.8%] | 594 | 10 | 0 | 0.0% | [0.0%, 1.1%] |
| claude-opus-5-5 | 2 | 746 | 55.3% | [52.7%, 58.0%] | 591 | 11 | 0 | 0.0% | [0.0%, 1.1%] |
| claude-opus-5-5 | 3 | 721 | 53.5% | [50.8%, 56.1%] | 615 | 12 | 0 | 0.0% | [0.0%, 1.1%] |

Three things to read off the table:

- **The models almost never call a poisoned tool clean.** Across the three runs, 14
  to 16 of 1,348 slip past Haiku 5.5, 13 past Sonnet 5.5 and 10 to 12 past Opus 5.5.
  What separates the models is whether they answer or decline: flagged *or* declined
  is 98.8% to 99.0% on Haiku 5.5, 99.0% on every Sonnet 5.5 run and 99.1% to 99.3% on
  every Opus 5.5 run.
- **Every refusal is `stop_reason: refusal` with category `cyber`, and every one is
  on a poisoned tool.** Sonnet 5.5 declined 181 of its 4,044 poisoned requests (4.5%),
  Opus 5.5 1,800 (44.5%). No clean tool was ever declined. On the current Opus the
  refusal classifier declines the most explicit poisoned descriptions instead of
  judging them, which `--llm-scan` reports as not analyzed and never as clean.
- **One clean tool is flagged, by Haiku 5.5 only, the same case in all three runs**
  (case index 1492 in the JSONL). Sonnet 5.5 and Opus 5.5 flagged no clean tool in
  any run.

Stability across the three runs (a case whose state differs between runs of the same
model): Haiku 5.5 12 of 1,701 (0.7%), Sonnet 5.5 32 (1.9%), Opus 5.5 118 (6.9%).
Every flip is on a poisoned tool. Haiku 5.5's 12 are clean-or-flagged; Sonnet 5.5's
32 and 116 of Opus 5.5's 118 are declined-or-flagged, the other 2 clean-or-flagged.

## By template (three runs pooled)

`n` counts case-runs (three per case). Recall counts flagged only; declined is listed
beside it.

| Template | n | Haiku 5.5 recall | declined | Sonnet 5.5 recall | declined | Opus 5.5 recall | declined |
|---|---:|---:|---:|---:|---:|---:|---:|
| Template-1 | 633 | 98.3% | 0 | 93.0% | 32 | 45.8% | 334 |
| Template-2 | 1,557 | 98.2% | 0 | 92.1% | 96 | 45.3% | 827 |
| Template-3 | 1,854 | 99.6% | 0 | 97.1% | 53 | 65.5% | 639 |

## By risk category (three runs pooled)

| Risk category (the dataset's label) | n | Haiku 5.5 | Sonnet 5.5 (declined) | Opus 5.5 (declined) |
|---|---:|---:|---:|---:|
| Code Injection | 189 | 100.0% | 55.6% (81) | 11.1% (165) |
| Credential Leakage | 345 | 100.0% | 95.1% (17) | 5.8% (325) |
| Data Tampering | 360 | 98.9% | 97.2% (10) | 50.3% (179) |
| Financial Loss | 165 | 100.0% | 98.2% (3) | 57.6% (70) |
| Information Manipulation | 843 | 99.4% | 98.6% (9) | 81.1% (159) |
| Infrastructure Damage | 372 | 100.0% | 89.0% (41) | 33.9% (246) |
| Instruction Tampering | 171 | 100.0% | 98.8% (2) | 66.7% (57) |
| Message Hijacking | 132 | 100.0% | 97.7% (3) | 38.6% (81) |
| Other | 12 | 100.0% | 100.0% (0) | 41.7% (7) |
| Privacy Leakage | 828 | 97.1% | 96.4% (12) | 51.9% (383) |
| Service Disruption | 627 | 97.9% | 97.1% (3) | 77.2% (128) |

The refusals cluster where the description asks for code execution or credentials:
Opus 5.5 declines 87% of the code-injection and 94% of the credential-leakage
case-runs, and Sonnet 5.5 43% of the code-injection ones.

## Cost and receipts

Batch prices are half of list (Haiku 5.5 $0.10 / $0.50, Sonnet 5.5 $2 / $10, Opus 5.5
$4 / $20 per million input / output tokens, as read on 2026-10-10). No prompt cache
was used.

| Model | Batch | Requests | Input tokens | Output tokens | Cost | Submitted (UTC) | Ended (UTC) | Wall |
|---|---|---:|---:|---:|---:|---|---|---|
| claude-haiku-5-5 | `msgbatch_01LSqavG1SDByyqi9e4CoXuk` | 5,103 | 5,589,774 | 527,933 | $0.41 | 12:59:30 | 13:06:46 | 7 min 16 s |
| claude-sonnet-5-5 | `msgbatch_01TJKHTCYUZvu2z9mKChbA2g` | 5,103 | 5,589,774 | 503,614 | $8.11 | 12:59:36 | 13:06:45 | 7 min 9 s |
| claude-opus-5-5 | `msgbatch_014Qn7CcvK6Rm6pDP2pdCBpi` | 5,103 | 5,589,774 | 302,710 | $14.21 | 12:59:42 | 15:43:13 | 2 h 43 min |

Total for the eval: **$22.73**. A request is about 1,095 input tokens (prompt, schema
and one tool) and, on average, 103 output tokens on Haiku 5.5, 99 on Sonnet 5.5 and
59 on Opus 5.5 (a refusal carries almost none).

`receipts/<model>/` holds, per batch: `batch-<id>.json` (the submission record without
its requests: model, effort, prompt hash, cases hash, case indices, AAK commit),
`results-<id>.jsonl.gz` (every result row with the text removed: the state the CLI's
parser assigns, refusal category, served model, message id, stop reason, token usage
and the SHA-256 of the raw row) and `cost-<id>.json`. The raw receipts, which quote
the dataset, stay outside the repository. To recompute this page:

```bash
python benchmarks/mcptox/build.py --jsonl /tmp/cases.jsonl          # outside the repo
python benchmarks/llm_scan_eval/score.py --cases /tmp/cases.jsonl --group paradigm \
    benchmarks/llm_scan_eval/receipts/claude-haiku-5-5 \
    benchmarks/llm_scan_eval/receipts/claude-sonnet-5-5 \
    benchmarks/llm_scan_eval/receipts/claude-opus-5-5
```

## The canary, same day

`scripts/llm_canary.py` ran by hand against 0.6.23 at 12:56 to 12:58 UTC on
2026-10-20 (30 live Messages API requests, $0.0858 at list price), over its ten
synthetic tools (five poisoned, five benign). Every reply came from the model
requested and no benign tool was flagged.

| Model | Analyzed | Poisoned flagged | Declined | Input / output tokens | Cost (list) | Canary |
|---|---:|---:|---:|---:|---:|---|
| claude-haiku-5-5 | 10 / 10 | 5 / 5 | 0 | 10,872 / 913 | $0.0015 | ok |
| claude-sonnet-5-5 | 9 / 10 | 4 / 5 | 1 (`cyber`) | 10,872 / 845 | $0.0302 | fail: a tool went unanalyzed |
| claude-opus-5-5 | 7 / 10 | 2 / 5 | 3 (`cyber`) | 10,872 / 531 | $0.0541 | fail: 2 of 5 caught, bar is 4 |

The canary fails on a refusal by design: a tool the model would not read is not a
clean tool. It is a smoke alarm, not a measurement; the measurement is the table above.

## Caveats

- **Contamination.** MCPTox was published before the models' knowledge cutoff, so they
  may have seen it. A private holdout gives the cleaner number.
- **One prompt, one effort.** These numbers measure this system prompt at `effort:
  low`. A different prompt or effort is a different measurement.
- **Refusals move.** The share of poisoned tools a model declines depends on its
  safety classifier, which changes between model versions without a change in AAK.
  A re-run is a replication, not a reproduction: hosted inference is not
  deterministic and the current models accept no temperature.
- **Not a security boundary.** Adaptive attacks have bypassed published defenses
  against prompt injection most of the time ([Nasr et al., 2025](https://arxiv.org/abs/2510.09023)).
  `--llm-scan` raises recall at the cost of a model's judgement and its refusals; it
  does not make a tool safe, and the deterministic rules stay the default path.
