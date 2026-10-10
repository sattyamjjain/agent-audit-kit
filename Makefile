# AgentAuditKit task runner.
#
# The State of MCP report is a build artifact: `make report` regenerates
# results.json from the local benchmarks/data crawl (gitignored) and the
# committed registry manifest, deterministically and offline, so the numbers in
# research/state-of-mcp-2026/REPORT.md cannot drift from the code. `make corpus`
# is the report's one network step (refreshes the manifest from the MCP
# Registry); it is intentionally separate from `report`.

RESEARCH := research/state-of-mcp-2026
CORPUS   := benchmarks/data
MANIFEST := $(RESEARCH)/corpus/registry-manifest.json
RESULTS  := $(RESEARCH)/results.json

.PHONY: report corpus report-check report-pdf report-pdf-check report-figures-check count-check test lint typecheck repo-description \
        cve-latency cve-latency-check cve-latency-queue-check cve-latency-refresh \
        remediation-corpus remediation-corpus-check \
        fp fp-check \
        fp-instruction fp-instruction-check fp-instruction-pin fp-instruction-fetch \
        registry-parity cve-deferral-check

## report: regenerate results.json from the corpus + manifest (offline, deterministic)
## Also re-renders the human PDF, because the docs site serves it at a stable URL
## and a PDF left behind by a results.json bump is a published wrong number.
report:
	python $(RESEARCH)/run_report.py \
	  --corpus $(CORPUS) \
	  --registry-manifest $(MANIFEST) \
	  --out $(RESULTS)
	python scripts/render_report_pdf.py

## report-pdf: re-render just the human PDF from the committed results.json
report-pdf:
	python scripts/render_report_pdf.py

## report-pdf-check: fail if the PDF was built from a different results.json.
## Not a byte-diff: reportlab stamps a /CreationDate, so two renders of the same
## input differ. The stamp beside the PDF records its source hash instead.
report-pdf-check:
	@python scripts/render_report_pdf.py --check

## corpus: refresh the MCP Registry corpus manifest (the one network step)
corpus:
	python $(RESEARCH)/fetch_registry.py --target 5000

## report-figures-check: fail if a governed report figure is stated outside a
## `report:` marker. report-check guards results.json against the corpus; this
## guards the published prose against results.json, which is the gap that let
## `100% (421/421)` sit in the README while the data said 424 -- unmarked, so the
## marker test could not see it.
report-figures-check:
	@PYTHONPATH=. python scripts/check_report_figures.py

## report-check: fail if results.json is not byte-identical to a fresh run (drift guard)
report-check:
	@python $(RESEARCH)/run_report.py --corpus $(CORPUS) --registry-manifest $(MANIFEST) --out /tmp/aak-report-check.json >/dev/null
	@diff -q $(RESULTS) /tmp/aak-report-check.json >/dev/null && echo "report is up to date" \
	  || (echo "results.json is stale — run 'make report' and commit" && exit 1)

## fp: re-measure the benign-slice false-positive benchmark and refresh every artifact
## it feeds (slice manifest, results.json, README badge). Offline, deterministic, ~5s.
## The adjudication in adjudication.json is a HUMAN judgement and is never regenerated —
## re-running this after a rule change requires re-adjudicating the findings by hand.
fp:
	python benchmarks/false_positive/corpus.py --write
	python benchmarks/false_positive/run.py --write
	python scripts/sync_fp_badge.py

## fp-check: fail if any false-positive artifact is stale vs a fresh derivation (drift guard).
## This is the guard that was missing: the corpus manifest grew 1,374 -> 1,641 servers, the
## benign slice 368 -> 536, and the published rate went on describing a slice that no longer
## existed because nothing checked. The last line checks the hand-written RESULTS.md: its
## Limitations kept the 2026-08-24 run's numbers under a headline reporting 2026-09-03's.
fp-check:
	@python benchmarks/false_positive/corpus.py --check
	@python benchmarks/false_positive/run.py --out /tmp/aak-fp-check.json >/dev/null
	@diff -q benchmarks/false_positive/results.json /tmp/aak-fp-check.json >/dev/null && echo "fp results are up to date" \
	  || (echo "results.json is stale - run 'make fp', re-adjudicate by hand, and commit" && exit 1)
	@python scripts/sync_fp_badge.py --check
	@python scripts/check_fp_results_page.py
	@$(MAKE) --no-print-directory fp-instruction-check

## fp-instruction: re-derive the instruction-file slice (slice.json) and re-scan it
## (results.json) from the committed manifest and the local cache. Offline once
## `fp-instruction-fetch` has filled the cache. Like `fp`, it never touches
## adjudication.json: a run that moves the findings needs a fresh adjudication
## (`run.py --init-adjudication`, which refuses to overwrite a set verdict).
fp-instruction:
	python benchmarks/false_positive/instruction_files/corpus.py --write
	python benchmarks/false_positive/instruction_files/run.py --write

## fp-instruction-check: the instruction slice's drift guard. The manifest validates and
## matches the scanners' instruction paths, slice.json matches a fresh derivation, the
## scan matches results.json (only when the cache is filled; otherwise it says NOT
## CHECKED, which is a skip and not a pass), and RESULTS.md states no rate while the
## adjudication is pending, then exactly the adjudicated one.
fp-instruction-check:
	@python benchmarks/false_positive/instruction_files/corpus.py --check
	@python benchmarks/false_positive/instruction_files/run.py --check
	@python scripts/check_fp_instruction_page.py

## fp-instruction-pin: (network, one-time) re-pin the instruction-file corpus from the
## SENTINEL bench manifests: repository metadata and head commits through `gh api graphql`,
## every instruction file by SHA-256. A re-pin is a corpus refresh and moves the slice.
fp-instruction-pin:
	python benchmarks/false_positive/instruction_files/fetch.py pin

## fp-instruction-fetch: (network) fill the cache from manifest.json, verifying every SHA-256.
## Third-party file contents live only there, never in a commit: the cache is a user cache
## directory outside the repo ($XDG_CACHE_HOME/agent-audit-kit/fp-instruction-files, or
## AAK_FP_INSTRUCTION_CACHE), so no scan of the repo reads it.
fp-instruction-fetch:
	python benchmarks/false_positive/instruction_files/fetch.py fetch

## count-check: fail if ANY rendered count is stale. Two guards, because they cover
## different halves and each one alone gives a false all-clear:
##   check_counts.py     - unmarked prose ("N rules across M categories") in tracked *.md
##   sync_rule_count.py  - generated surfaces: the shields badge + alt text, action.yml,
##                         __init__.py, docs/rules.md, and every <!-- rule-count --> anchor
## The badge sat outside check_counts.py's phrase list, so `make count-check` reported
## clean with a stale badge until v0.3.88. Both now run under the one target.
## Last, the live github.com description against the rendered one (gh repo view; fails
## on a mismatch, skipped with a message when gh is missing or not authenticated).
count-check:
	@PYTHONPATH=. python scripts/check_counts.py
	@PYTHONPATH=. python scripts/sync_rule_count.py --check
	@PYTHONPATH=. python scripts/sync_rule_doc_pages.py --check
	@PYTHONPATH=. python scripts/render_repo_metadata.py --check-live sattyamjjain/agent-audit-kit

## cve-latency: regenerate docs/cve-latency.md from the ledger. Not offline: the
## open-queue row reads the live cve-response tracker via gh (read=no without
## it); run the script with --issues-json FILE to render a fixed queue.
cve-latency:
	python scripts/cve_latency.py

## cve-latency-check: fail if docs/cve-latency.md is stale vs the ledger (drift guard,
## offline: pytest runs it every time and release.yml on every tag)
cve-latency-check:
	@python scripts/cve_latency.py --check

## cve-latency-queue-check: fail if the published open-queue row disagrees with
## the tracker (network). Deliberately NOT part of cve-latency-check: that one
## runs in pytest and on every tag, and a published number must not gate a
## release. Runs on the daily CVE cron beside the ageing gate.
cve-latency-queue-check:
	@python scripts/cve_latency.py --check-queue

## cve-latency-refresh: top up docs/data/cve-published.json from NVD (network)
cve-latency-refresh:
	python scripts/cve_latency.py --refresh

## remediation-corpus: regenerate remediation-key-corpus.json from benchmarks/data (offline, deterministic)
remediation-corpus:
	python scripts/gen_remediation_key_corpus.py

## remediation-corpus-check: fail if remediation-key-corpus.json is stale vs benchmarks/data.
## Also asserted by tests/test_remediation_keys_are_real.py, so CI covers it via pytest;
## this target is for regenerating locally without running the suite.
remediation-corpus-check:
	@python scripts/gen_remediation_key_corpus.py --check

## registry-parity: does the version we declare actually exist on PyPI? (network)
## The only check here that looks OUTSIDE the repo. Every other version guard
## compares one in-repo surface to another, and all of them passed on 2026-08-31
## while 0.3.91 was declared and PyPI served 0.3.90. Also runs daily in CI --
## the failure is time-based, so a push-only gate cannot see it.
registry-parity:
	@python scripts/check_registry_parity.py

## cve-deferral-check: every `cve-deferred` issue must name a target date (network, needs gh)
## `cve-deferred` is the one label that switches the release gate off, and until
## 2026-09-04 its only obligation was a prose comment nothing read -- so a deferral
## and a silent drop were the same gesture. Runs inside the release gate; this target
## is for checking the queue before you get there.
cve-deferral-check:
	@python scripts/check_cve_deferrals.py

## test: run the test suite
test:
	python -m pytest -q

## lint: ruff
lint:
	ruff check .

## typecheck: mypy the package
typecheck:
	mypy agent_audit_kit

## repo-description: print the GitHub "About" description, rendered from RULE_COUNT.
## Paste the output into repo Settings > About when RULE_COUNT changes — GitHub's
## description field is not writable from a CI token (see docs/RELEASING.md).
repo-description:
	@PYTHONPATH=. python scripts/render_repo_metadata.py
