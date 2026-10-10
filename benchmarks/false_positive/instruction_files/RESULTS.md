# Instruction-file benign slice — AgentAuditKit

> Generated from `run.py` over the benign slice derived by `corpus.py`, from a
> corpus pinned on **2026-10-10**. Offline after one fetch, deterministic, no LLM.
> Reproduce: `make fp-instruction-fetch` (network, once), then `make fp-instruction`.
> Which repositories, commits and files were measured is committed in
> [`slice.json`](slice.json) and [`manifest.json`](manifest.json); file contents
> are not, so the fetch is needed to re-run the scan.

## Status: pending adjudication

Every HIGH/CRITICAL finding below is listed in [`adjudication.json`](adjudication.json)
with a null verdict. No script sets a verdict, and until each one is set by hand
there is **no false-positive rate for instruction files** and this page states
none. `make fp-instruction-check` fails if it does.

This slice exists because the MCP benchmark one directory up covers MCP server
configs only, and its own Limitations say so: the rules that read `CLAUDE.md`,
`AGENTS.md` and the like had no measured false-positive rate.

## What the run measured

On a **892-repository benign slice** (1,422 instruction files), the shipped
engine raises **29 HIGH/CRITICAL** findings, on 15 repositories (1.7% of the
slice). Every one of them is up for adjudication, not a sample.

| Rule | Severity | Findings | Repositories |
|------|:--------:|---------:|-------------:|
| `AAK-AGENT-001` | CRITICAL | 12 | 6 |
| `AAK-AGENT-003` | HIGH | 10 | 3 |
| `AAK-IPI-WILD-CORPUS-001` | HIGH | 5 | 5 |
| `AAK-AGENT-006` | HIGH | 2 | 2 |

By split, the main manifest (570 repositories in the slice) carries 27 of them
and the held-out manifest (322) carries 2.

`AAK-IPI-WILD-CORPUS-001` is not an instruction-file rule by design: it reads
every `.md`, `.txt`, `.yml`, `.yaml`, `.json` and `.py` file, so it reads
instruction files too. The run uses the whole engine, not only the
`AAK-AGENT-*` scanners, for exactly this reason: the question is what fires on
these files when a build scans them.

All severities, 1,368 findings in total (1.53 per repository):

| Severity | Findings |
|----------|---------:|
| critical | 12 |
| high | 17 |
| medium | 446 |
| low | 893 |

The low count is almost entirely `AAK-AGENT-002` (a plain link in an instruction
file, reported as inventory since v0.6.8), and no scanner failed on any file.

## Method

### Corpus

The bench manifests the [#771](https://github.com/sattyamjjain/agent-audit-kit/issues/771)
reporter published with their report: `GarvitAgrawal04/SENTINEL`
`bench/results/manifest_main.json` (590 repositories) and `manifest_heldout.json`
(340), Apache-2.0, pinned at SENTINEL commit `2b70c363512d`. They list popular
public repositories that ship instruction files, which the reporter described as
"presumed benign, not audited one by one". Nobody selected them for what AAK
says about them, which is what makes them a fair benign proxy.

`manifest.json` pins every listed instruction file by repository, the head
commit of its recorded branch on the pin date, path and SHA-256. Only the paths
an instruction-file rule reads are kept: `AGENTS.md`, `CLAUDE.md`,
`.github/copilot-instructions.md`, `.cursorrules` and `GEMINI.md` here. The other
paths in the SENTINEL listings (`.claude/settings.json`, `.mcp.json`, hook
scripts) are not instruction files.

### Pre-registered benign predicate

A repository is in the slice iff ALL hold (pre-registered in `corpus.py`, whose
`PREDICATE` was committed on its own, before the corpus was pinned or scanned;
the pull request that added this slice shows that commit first):

1. It is listed in the SENTINEL bench manifests at the pinned commit.
2. GitHub reports it **public, not archived and not a fork** at pin time.
3. Its SENTINEL-recorded star count is at least 1,000. Every listed repository
   clears this today; it is the source's popularity premise written down, read
   from the frozen manifest so the slice does not move when stars do.
4. It is **not in any CVE/advisory feed AAK ships**, the same exclusion set the
   MCP slice uses.
5. At least one instruction file was fetched at the pinned commit.

**Resulting n = 892**: 930 listed → 2 not found on GitHub → 1 archived → 12 in a
shipped CVE feed → 23 with no instruction file fetched (17 list none, 6 list
files that return 404 at the pinned commit) → **892**.

"Benign" is a property of how the repositories were selected and of their own
GitHub metadata. It is not "AAK found nothing", which would be circular.

### Tuned, and said so

Both manifests were scanned while the `AAK-AGENT-*` matchers were reworked:
for #771 on 2026-10-02 and for #869 on 2026-10-04. Neither split is unseen data
for those rules, so the rate this slice yields will be a tuned measurement, and
`adjudication.json` records `"tuned": true`. The held-out split is kept to report
a different star band (1,242 to 2,999, against main's 6,929 and up), not as a
test set.

## Adjudicating

Set each `verdict` in `adjudication.json` to `true_positive` (the file really
contains what the rule says), `false_positive` (AAK is wrong) or `ambiguous`
(defensible either way; denominator only), the verdict rule the MCP slice uses
in [`../triage.md`](../triage.md). Fill in `rater` and `run_date`, then replace
the status section above with the rate and its Wilson 95% CI. While any
verdict is null `make fp-instruction-check` requires this page to say it is
pending and to state no rate; once all are set it checks the stated rate, the
interval and the counts against the verdicts.

`python benchmarks/false_positive/instruction_files/run.py --sheet <path>` writes
every finding with its matched line and context from the local cache, for
reading. It contains third-party text, so keep it out of the repository.

## Limitations

- **"Benign" is a proxy.** Popular, public, maintained repositories are a
  reasonable stand-in for instruction files written in good faith, but some may
  contain real problems, and those are true positives, not noise.
- **Tuned, not held out.** See above.
- **One snapshot.** Each file is pinned at its repository's branch head on
  2026-10-10, and a repository that changes its instruction files later is
  measured as it was then.
- **Only the files SENTINEL listed.** `.claude/CLAUDE.md`, `.windsurfrules`,
  `.roo/rules` and `.kiro/rules` are read by the rules but appear in no listing,
  so they are not measured here.
- **The CVE-feed exclusion matches by name, and coarsely.** `supabase/mcp` is
  excluded because its repository name equals the `mcp` package, and
  `ruvnet/ruflo`, one of the three `AAK-AGENT-006` hits read in #771, is
  excluded because `ruflo` is a CVE-pinned package. The predicate was not
  adjusted after seeing that, which is the point of pre-registering it.
- **Scope is HIGH/CRITICAL.** MEDIUM and LOW findings are not adjudicated; this
  measures the severities that fail a build.
- **No third-party text is committed.** `results.json` and `adjudication.json`
  key each finding by repository, path, line and rule, with a SHA-256 of its
  evidence, so the scan cannot be re-run from the repository alone.

## History

| Run | Slice | HIGH/CRIT | FP / adjudicated | Rate | Note |
|-----|------:|----------:|-----------------:|-----:|------|
| 2026-10-10 | 892 | 29 | pending | — | First run. Corpus pinned the same day from SENTINEL `2b70c36`. |
