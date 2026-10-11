# CVE pre-screen

A first read of every `cve-response` issue, drafted before the maintainer opens
it. The CVE watcher (`.github/workflows/cve-watcher.yml`) files one
release-gating issue per matching NVD record, a mean of four a day in bursts
of up to thirteen, and part of every burst is keyword noise: Apache Storm
advisories that matched "Claude agents" in an acknowledgement line, a kernel
driver for the MCP2221 USB chip. The pre-screen turns each record into a
candidate disposition with the affected packages already copied out, so
triage starts from a draft instead of a blank issue.

**It produces a candidate, nothing more.** Nothing in this package closes,
labels or comments on an issue. The maintainer decides.

How well it does is measured in [RESULTS.md](RESULTS.md), a backtest against
what the maintainer actually decided, generated from `results.json`.

## What it does

1. **Retrieval, deterministic, no model** (`retrieval.py`). For a CVE id, or a
   `cve-response` issue number resolved to its CVE through the issue title:
   - the NVD API 2.0 record, without an API key, never more than 5 requests in
     any 30 seconds (NVD's public limit), with backoff on 403/429/5xx;
   - the GitHub advisory through `gh api '/advisories?cve_id=...'`, plus the
     repository advisory (`/repos/O/R/security-advisories/GHSA-...`) when NVD
     cites one the global database does not carry yet. REST only;
   - OSV (`api.osv.dev/v1/vulns/<id>`) for the CVE and every GHSA or PYSEC id
     the other sources name, which is where the structured ranges live.

   Raw responses are cached under `$AAK_CVE_PRESCREEN_CACHE`, else
   `$XDG_CACHE_HOME/agent-audit-kit/cve-prescreen`, else
   `~/.cache/agent-audit-kit/cve-prescreen`: outside the repository, so no
   scan and no `git add` sees them. A 404 is cached too.
2. **A compact context** (`context.py`): description, CWEs, CVSS, NVD's CNA
   `affected` block, CPE bounds, the GHSA packages with their ranges and fixed
   versions, OSV's affected ranges, references. Free text is truncated and
   reporter identities are dropped.
3. **Two model calls** (`prompts.py`, `runner.py`, `screen.py`):
   - a noise filter on Haiku: is this record about AI-agent, MCP or LLM
     tooling at all?
   - the classification on Sonnet: `version-pin`, `new-detection`,
     `out-of-scope` or `needs-human`; the affected packages, ecosystems, ranges
     and fixed versions, each value carrying the path of the context field it
     was copied from; and a one-line rationale.
4. **Verification** (`verify.py`): every extracted value is checked against
   the field it cites, so a package or version the model made up is reported
   as invented rather than passed along.

The candidate: if the noise filter says the record is not agent tooling, the
candidate is `out-of-scope` with `is_noise` set; otherwise it is the
classification. Both answers are kept.

## Commands

From the repository root:

```bash
python -m benchmarks.cve_prescreen context CVE-2026-55253   # the context only, no model
python -m benchmarks.cve_prescreen context '#926'           # an issue number works too
python -m benchmarks.cve_prescreen screen '#926'            # candidate disposition (subscription)

python -m benchmarks.cve_prescreen ground-truth             # rebuild ground_truth.json (gh REST)
python -m benchmarks.cve_prescreen retrieve                 # warm the cache for every record
python -m benchmarks.cve_prescreen backtest                 # screen every record (resumable)
python -m benchmarks.cve_prescreen report --write           # results.json + RESULTS.md
python -m benchmarks.cve_prescreen report --check           # offline drift guard
```

`backtest` writes one JSON file per record under
`<cache>/runs/<prompt version>/records/` and skips records already there, so
an interrupted run resumes. It refuses to start unless `claude auth status`
reports the `claude.ai` login, and refuses to continue a run directory whose
prompts have changed.

## How each model call is isolated

Every call is one `claude -p` process (`runner.py`), checked on Claude Code
2.1.296:

- a fresh, empty temporary working directory, so no project `CLAUDE.md`,
  settings or MCP configuration is in reach;
- `--safe-mode`, because an empty directory is not enough on its own: the
  user-level `~/.claude/CLAUDE.md` still loads from one. A probe asking the
  model to quote any such text returned the user's global instructions without
  `--safe-mode` (8,429 cache-creation tokens) and `NONE` with it (2,652);
- `--strict-mcp-config --mcp-config '{"mcpServers":{}}' --tools ""`, so no MCP
  server and no tool: an advisory carrying a prompt injection can at worst
  steer a label, which the maintainer reviews;
- `--system-prompt` with the classifier's own prompt, `--json-schema` for the
  answer, `--output-format json`, `--no-session-persistence`;
- environment: `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1`,
  `ENABLE_CLAUDEAI_MCP_SERVERS=false`, and `ANTHROPIC_API_KEY` and
  `ANTHROPIC_AUTH_TOKEN` removed (the shell equivalent is
  `env -u ANTHROPIC_API_KEY`), so the call runs on the subscription. Every
  other `CLAUDE*` variable is removed too, since a parent Claude Code session
  exports its own session id and messaging socket;
- the prompt goes on stdin: `--mcp-config` and `--tools` take several values,
  so a trailing positional prompt would be read as a tool name.

The model that answered is read from the result's `modelUsage`, never assumed
from `--model`. A call answered by another model family, refused, or returned
outside the schema is not scored. `total_cost_usd` is a list-price figure
(`costBasis: "list"`); on the subscription it is not a charge.

## A nightly job, on the subscription

Not created. Arming any scheduled job is the maintainer's call. This is how it
would run.

**What one run does.** List the open `cve-response` issues without
`cve-deferred` that carry no pre-screen yet, run `screen` on each, and write
one digest: a table of issue, candidate disposition, `is_noise`, the packages
and ranges with their citations, the rationale, and every extraction verdict
that is not exact. A burst of thirteen needs about a minute of NVD time at the
public rate limit (five requests, a 30-second window, five more, another
window, three more), plus two model calls per record (see RESULTS.md for the
measured time per call).

**Use `gh api` REST everywhere.** `gh issue list` and `gh issue view` go
through GraphQL, which a Claude Code routine's GitHub proxy blocks. List the
queue with
`gh api '/repos/sattyamjjain/agent-audit-kit/issues?labels=cve-response&state=open&per_page=100'`
and drop any issue whose labels include `cve-deferred`. Everything in this
package already uses REST.

**Option 1: a local scheduled `claude -p`.** A cron or launchd entry on the
maintainer's machine, logged in to the subscription with `claude auth login`:

```bash
cd /path/to/agent-audit-kit && env -u ANTHROPIC_API_KEY \
  python -m benchmarks.cve_prescreen screen '#NNN' >> ~/cve-prescreen-digest.jsonl
```

once per open issue, looped over the REST listing above. Nothing leaves the
machine except the NVD, GitHub and OSV reads and the model calls.

**Option 2: a Claude Code routine.** The routine checks out the repository and
runs the same `screen` command per issue. Two cautions. The GitHub proxy blocks
GraphQL, hence REST only. And the numbers in RESULTS.md describe the isolated
`claude -p` path: if a routine cannot run a nested `claude -p` and instead
applies the prompt in its own session, the routine's context is no longer
isolated from the record, and the backtest no longer describes it.

**Delivery.** The digest goes to a file or the routine's output. Posting
candidates as issue comments is a separate decision; if the maintainer opts
in, each comment should say it is a machine candidate, not a disposition, and
the `## Disposition:` convention stays the maintainer's. A candidate comment
must never open with that heading: `tests/test_cve_watcher_backpressure.py`
accepts any comment that starts with it as the disposition a `cve-deferred`
label requires, so a machine comment could satisfy a check meant for a human.

## Ground truth

`ground_truth.json` is built by `ground_truth.py` from two sources the
maintainer wrote at triage time, for records dated 2026-08-11 or later:

- `CHANGELOG.cves.md` table rows, in both table shapes the ledger used in that
  window. The newest row for a CVE wins, since dispositions are sometimes
  revised (heym went from out of scope to a new pin on the day an image-tag
  reader landed).
- closed `cve-response` issues, read through `gh` REST: the last disposition
  statement in the comments, then the close reason. This covers records the
  ledger mentions only in prose.

The classes come from rules over the disposition text. Four records the rules
could not read are settled in `OVERRIDES`, each citing where the decision is
recorded. `is_noise` is not parsed at all: it is the `NOISE` table, six
records whose product the maintainer's own close reason says is not agent
tooling. A product with a real MCP surface whose bug sits elsewhere, or that
AAK cannot see, is out of scope but not noise.

## Files

| File | What it is |
|---|---|
| `retrieval.py` | NVD / GHSA / OSV fetch, rate limit, disk cache |
| `context.py` | The compact context and the citation-path resolver |
| `prompts.py` | Both prompts, both JSON schemas, `PROMPT_VERSION` |
| `runner.py` | One isolated `claude -p` call; result parsing |
| `screen.py` | Noise filter, classification, verification, candidate |
| `verify.py` | Extraction checks against the cited fields |
| `ground_truth.py` | Ledger and issue parsing; `NOISE` and `OVERRIDES` |
| `metrics.py` | Accuracy, confusion matrix, precision and recall |
| `backtest.py` | Running, scoring and rendering the backtest |
| `ground_truth.json` | The labelled records the backtest scores against |
| `results.json`, `RESULTS.md` | The backtest result and its rendered page |

Offline tests: `tests/test_cve_prescreen.py`, with hand-written NVD, GHSA and
OSV fixtures under `tests/fixtures/cve_prescreen/`.
