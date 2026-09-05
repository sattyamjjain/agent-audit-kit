# AgentAuditKit task runner.
#
# The State of MCP report is a build artifact: `make report` regenerates
# results.json from the committed corpus manifest, deterministically and
# offline, so the numbers in research/state-of-mcp-2026/REPORT.md cannot drift
# from the code. `make corpus` is the single network step (refreshes the
# manifest from the MCP Registry); it is intentionally separate from `report`.

RESEARCH := research/state-of-mcp-2026
CORPUS   := benchmarks/data
MANIFEST := $(RESEARCH)/corpus/registry-manifest.json
RESULTS  := $(RESEARCH)/results.json

.PHONY: report corpus report-check count-check test lint typecheck repo-description \
        cve-latency cve-latency-check cve-latency-refresh \
        remediation-corpus remediation-corpus-check \
        fp fp-check \
        registry-parity cve-deferral-check

## report: regenerate results.json from the corpus + manifest (offline, deterministic)
report:
	python $(RESEARCH)/run_report.py \
	  --corpus $(CORPUS) \
	  --registry-manifest $(MANIFEST) \
	  --out $(RESULTS)

## corpus: refresh the MCP Registry corpus manifest (the one network step)
corpus:
	python $(RESEARCH)/fetch_registry.py --target 5000

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
## existed because nothing checked.
fp-check:
	@python benchmarks/false_positive/corpus.py --check
	@python benchmarks/false_positive/run.py --out /tmp/aak-fp-check.json >/dev/null
	@diff -q benchmarks/false_positive/results.json /tmp/aak-fp-check.json >/dev/null && echo "fp results are up to date" \
	  || (echo "results.json is stale - run 'make fp', re-adjudicate by hand, and commit" && exit 1)
	@python scripts/sync_fp_badge.py --check

## count-check: fail if ANY rendered count is stale. Two guards, because they cover
## different halves and each one alone gives a false all-clear:
##   check_counts.py     - unmarked prose ("N rules across M categories") in tracked *.md
##   sync_rule_count.py  - generated surfaces: the shields badge + alt text, action.yml,
##                         __init__.py, docs/rules.md, and every <!-- rule-count --> anchor
## The badge sat outside check_counts.py's phrase list, so `make count-check` reported
## clean with a stale badge until v0.3.88. Both now run under the one target.
count-check:
	@PYTHONPATH=. python scripts/check_counts.py
	@PYTHONPATH=. python scripts/sync_rule_count.py --check
	@PYTHONPATH=. python scripts/sync_rule_doc_pages.py --check

## cve-latency: regenerate docs/cve-latency.md from the ledger (offline, deterministic)
cve-latency:
	python scripts/cve_latency.py

## cve-latency-check: fail if docs/cve-latency.md is stale vs the ledger (drift guard, runs on tag)
cve-latency-check:
	@python scripts/cve_latency.py --check

## cve-latency-refresh: top up docs/data/cve-published.json from NVD (the one network step)
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
