# `--llm-scan` per-model eval

How well does `scan --llm-scan` catch poisoned tool descriptions, per Claude
model, and how often does it flag benign ones? The results are in
[RESULTS.md](RESULTS.md). This page is the method.

## What is measured

The product's own request, nothing else. `run_eval.py` builds each request with
`llm_scan.anthropic_request` over `llm_scan.render_tool_text`: the same system
prompt, `<tool_metadata>` fence, verdict schema, `effort` and `max_tokens` a
user's `--llm claude-*` run sends. `score.py` parses every reply with
`llm_scan.parse_anthropic_message`, the CLI's own parser, so each reply lands
in a CLI state:

| State | Counts as |
|---|---|
| `flagged` | caught (malicious) or a false positive (benign) |
| `clean` | missed (malicious) or correct (benign) |
| `declined` (refusal), `cut_off`, `unparsed`, `errored` | not analyzed: the CLI's AAK-LLM-002 |

Recall is flagged malicious cases over **all** malicious cases. A refusal on a
poisoned description is not a catch, because the CLI never reports one as a
catch; refusals are reported beside recall, because the CLI does surface them
as "not analyzed". Intervals are Wilson 95%.

## How it runs

- **Message Batches API**: half price, results kept 29 days. Batches reject
  the server-side fallback parameter, so a refusal is measured as a refusal and
  no other model answers in its place.
- **Three runs per model.** The current models accept no temperature, so
  verdicts vary between runs; the flip rate (a case whose state differs
  between runs) is reported.
- **Receipts.** `runs/<name>/batch-<id>.json` holds every request exactly as
  submitted, with the prompt hash, the cases file's SHA-256, the AAK commit and
  the case indices. `runs/<name>/results-<id>.jsonl` holds every raw result
  exactly as returned, message ids and token usage included. Every number in
  RESULTS.md is recomputed offline from those files by `score.py`. A fresh API
  run is a replication, not a reproduction.
- **Committed receipts.** The raw files quote the dataset, so the repository
  holds `redact`'s output under `receipts/<model>/`: the batch record without
  its requests, every result row with the text removed (state, refusal
  category, served model, message id, token usage, SHA-256 of the raw row),
  gzipped, and the cost file. `score.py` reads either form and scores both
  identically.

```bash
pip install anthropic                      # the eval only; AAK itself has no SDK dependency
export ANTHROPIC_API_KEY=...
python run_eval.py submit  --cases cases.jsonl --model claude-haiku-5-5 --runs 3 --out runs/haiku-5-5
python run_eval.py collect --out runs/haiku-5-5
python score.py --cases cases.jsonl --group <paradigm field> runs/* --json results.json
```

## Caveats

- **Contamination.** MCPTox was published before the models' June 2026
  knowledge cutoff, so they may have seen it. A fresh or private holdout gives
  the cleaner number.
- **One prompt.** The numbers measure this system prompt at this effort. A
  different prompt is a different measurement.
- **Not a security boundary.** Adaptive attacks have bypassed 12 published
  defenses against jailbreaks and prompt injection, most of them more than
  90% of the time ([Nasr et al., 2025](https://arxiv.org/abs/2510.09023)).
  This layer raises recall at its own false-positive cost; it does not make a
  tool safe.
