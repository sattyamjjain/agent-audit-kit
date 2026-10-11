"""Run the pre-screen over the ground truth and score it.

Three steps, each re-runnable on its own:

1. `run_backtest` screens every ground-truth record and writes one JSON file
   per record into a run directory outside the repository (raw model output
   stays out of git). It is resumable: a record already on disk is skipped.
   At most two `claude -p` processes run at once, whatever is asked for.
2. `build_results` joins the run directory with the ground truth into the
   committed `results.json`: every record's prediction and verdicts, plus the
   metrics in `metrics.py`.
3. `render_markdown` turns `results.json` into `RESULTS.md`. It reads nothing
   else, so `tests/test_cve_prescreen.py` re-renders the committed results and
   fails if the page drifted from them.

The "post-cutoff" population is the records NVD published on or after
`POST_CUTOFF` (2026-07-01). Every ledger row is dated 2026-08-11 or later, but
a backlog row can carry a CVE published long before, which a model could have
seen in training, so the headline figures are reported on both populations.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from benchmarks.cve_prescreen import DISPOSITIONS, metrics, prompts
from benchmarks.cve_prescreen.context import context_digest, structured_packages
from benchmarks.cve_prescreen.ground_truth import Truth
from benchmarks.cve_prescreen.retrieval import Retriever
from benchmarks.cve_prescreen.runner import CallResult, run_claude
from benchmarks.cve_prescreen.screen import (
    DEFAULT_CLASSIFY_MODEL,
    DEFAULT_NOISE_MODEL,
    screen,
)
from benchmarks.cve_prescreen.verify import verify_affected

HERE = Path(__file__).resolve().parent
GROUND_TRUTH = HERE / "ground_truth.json"
RESULTS_JSON = HERE / "results.json"
RESULTS_MD = HERE / "RESULTS.md"
MAX_CONCURRENCY = 2
POST_CUTOFF = "2026-07-01"
#: GHSA and OSV spellings of the two registries AAK's pin tables read.
REGISTRY_ECOSYSTEMS = frozenset({"pip", "PyPI", "npm"})

#: Printed at the foot of RESULTS.md. Each one bounds what a figure above means.
LIMITATIONS: list[str] = [
    "One run, one sample per record, at the CLI's default effort. Run-to-run variance was "
    "not measured, so a difference of a few records between two prompt versions is noise.",
    "The ground truth is the maintainer's dispositions read by rules (`ground_truth.py`). Four "
    "records the rules could not read (`OVERRIDES`) and the six noise records (`NOISE`) were "
    "settled by the agent that built this benchmark, from the maintainer's own notes. The "
    "maintainer has not reviewed these labels.",
    "The prompt was written by someone who had read the ledger, then frozen before any "
    "backtest call. It is an informed prompt, not a blind one, and it was not changed after "
    "the run.",
    "The verifier was corrected after the run, from the run's own mismatches: CNA placeholder "
    "products such as `n/a` stopped counting as expected packages, and a value that differs "
    "from its field only in whitespace (a no-break space typed as a space) is reported as "
    "`whitespace` instead of `invented`. Model outputs were not touched; extraction was "
    "re-scored from them.",
    "AAK's read surface changed inside the window: container image tags became readable on "
    "2026-10-03, and the Go arm of the STDIO command-injection family landed on 2026-09-15. "
    "The prompt describes today's surface, so a record closed as out of scope before a reader "
    "existed can disagree for that reason alone. SiYuan, MaxKB, Coroot and Lightdash were "
    "closed for having no PyPI or npm artifact before image tags were readable; whether the "
    "maintainer would pin their images today is not known.",
    "The commonest model error is asserting that a product is published on PyPI, npm or a "
    "container registry when no structured field shows it (\"likely an npm package\", a Docker "
    "image name the record never mentions). The post-hoc split under the confusion matrix "
    "shows what that does to version-pin precision. The structured data can be wrong as "
    "well: GHSA names pip `onyx` for the Onyx AI platform, which the ledger records as an "
    "unrelated PyPI project, so even a copied package needs its registry identity checked.",
    "version-pin against new-detection is partly maintainer judgment the prompt does not "
    "encode: the ledger says a class rule was chosen over a one-package pin for a recurring "
    "shape (argocd-mcp, @ooples/token-optimizer-mcp), and a general LLM-app bug with no MCP "
    "surface was closed as out of scope although the package is on PyPI "
    "(langchain-chatchat).",
    "The maintainer's own labels shifted over the window: a source-only MCP server whose shape "
    "a detection rule covers was closed as out of scope in August (mcp-dominican-layer, "
    "mcp-rdf-explorer) and recorded against the rule in September (MCP Documentation "
    "Server). The ground truth keeps each record's label as decided.",
    "Noise has six positives, so its recall interval is wide; its precision is measured on "
    "every other record in the window.",
    "NVD, GHSA and OSV were read on 2026-10-12, after the dispositions. A record revised "
    "since triage shows the model today's text, not what the maintainer read.",
    "Cost is the CLI's list-price `total_cost_usd`, not a charge on the subscription. Wall "
    "time includes CLI start-up; one Haiku call hung until the 300 s timeout and is counted "
    "in the noise stage's mean, so read its median.",
    "`needs-human` never appears in the final ground truth, because every deferral in the "
    "window was resolved, so a `needs-human` answer can only count as an abstention.",
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_backtest(
    truths: list[Truth],
    retriever: Retriever,
    run_dir: Path,
    *,
    concurrency: int = MAX_CONCURRENCY,
    call: Callable[..., CallResult] = run_claude,
    noise_model: str = DEFAULT_NOISE_MODEL,
    classify_model: str = DEFAULT_CLASSIFY_MODEL,
    force: bool = False,
    log: Callable[[str], None] = print,
) -> dict[str, int]:
    """Screen every record not already in `run_dir/records`. Returns counts."""
    workers = max(1, min(int(concurrency), MAX_CONCURRENCY))
    records_dir = run_dir / "records"
    records_dir.mkdir(parents=True, exist_ok=True)

    todo: list[tuple[Truth, dict[str, Any]]] = []
    skipped = no_context = 0
    for truth in truths:
        path = records_dir / f"{truth.cve}.json"
        if path.is_file() and not force:
            skipped += 1
            continue
        bundle = retriever.bundle(truth.cve)
        context = bundle.context()
        if context["nvd"] is None and not context["ghsa"] and not context["osv"]:
            no_context += 1
            _write(path, {"cve": truth.cve, "status": "no-context", "sources": bundle.status})
            continue
        todo.append((truth, context))

    def work(item: tuple[Truth, dict[str, Any]]) -> str:
        truth, context = item
        started = time.monotonic()
        result = screen(context, call=call, noise_model=noise_model, classify_model=classify_model)
        result["status"] = "screened"
        result["published"] = (context.get("nvd") or {}).get("published")
        result["sources"] = context.get("sources")
        result["screened_at"] = _now()
        result["record_seconds"] = round(time.monotonic() - started, 3)
        _write(records_dir / f"{truth.cve}.json", result)
        cand = result["candidate"]
        return f"{truth.cve}: {cand['disposition']} (truth {truth.disposition}) noise={cand['is_noise']}"

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for line in pool.map(work, todo):
            done += 1
            log(f"[{done}/{len(todo)}] {line}")
    return {"screened": done, "skipped": skipped, "no_context": no_context}


def _write(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=1, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Joining a run with the ground truth
# ---------------------------------------------------------------------------

_LEDGER_NAME_RE = re.compile(r"`([^`]+)`")


def ledger_package_names(cell: str) -> list[str]:
    """Registry names the ledger gives for a record, if it gives any.

    The newer table spells them in backticks (`` `mcp-atlassian` ``); the older
    one yields a bare name from its floor clause (`qwed-mcp`). A product phrase
    with spaces ("Microsoft UFO (source checkout)") names no registry package.
    """
    ticked = [n for n in _LEDGER_NAME_RE.findall(cell or "") if " " not in n]
    if ticked:
        return ticked
    bare = (cell or "").strip()
    return [bare] if bare and " " not in bare and "`" not in bare else []


def _stage_view(stage: dict[str, Any] | None) -> dict[str, Any] | None:
    if not stage:
        return None
    keep = (
        "ok", "scorable", "models_used", "model_mismatch", "refusal",
        "cost_usd", "cost_basis", "duration_api_ms", "wall_seconds",
    )
    view = {k: stage.get(k) for k in keep}
    # Failure detail only where there is a failure, so the common row stays short.
    for extra in ("error", "refusal_signal", "schema_errors", "stop_reason"):
        if stage.get(extra) and not stage.get("scorable"):
            view[extra] = stage.get(extra)
    return view


def record_row(truth: Truth, record: dict[str, Any]) -> dict[str, Any]:
    """One committed result row: truth, both predictions, verdicts, spend."""
    noise = record.get("noise") or {}
    clf = record.get("classification") or {}
    noise_out = noise.get("structured") or {}
    clf_out = clf.get("structured") or {}
    extraction = record.get("extraction")
    published = record.get("published") or ""
    listed = (extraction or {}).get("packages_listed") or []
    ledger_names = ledger_package_names(truth.package)
    row: dict[str, Any] = {
        "cve": truth.cve,
        "issue": truth.issue,
        "published": published[:10] if published else None,
        "post_cutoff": bool(published) and published[:10] >= POST_CUTOFF,
        "status": record.get("status"),
        "truth": truth.disposition,
        "acceptable": list(truth.acceptable),
        "truth_detail": truth.detail,
        "truth_noise": truth.is_noise,
        "truth_source": truth.source,
        "haiku_noise": noise_out.get("is_noise") if noise.get("scorable") else None,
        "haiku_rationale": noise_out.get("rationale") if noise.get("scorable") else None,
        "sonnet_pred": clf_out.get("disposition") if clf.get("scorable") else None,
        "sonnet_noise": clf_out.get("is_noise") if clf.get("scorable") else None,
        "sonnet_rationale": clf_out.get("rationale") if clf.get("scorable") else None,
        "pipeline_pred": (record.get("candidate") or {}).get("disposition"),
        "pipeline_decided_by": (record.get("candidate") or {}).get("decided_by"),
        "context_digest": record.get("context_digest"),
        "noise_call": _stage_view(noise),
        "classify_call": _stage_view(clf),
    }
    if extraction is not None:
        row["extraction"] = {k: v for k, v in extraction.items() if k != "checks"}
        row["extraction_failures"] = [
            {k: c.get(k) for k in ("kind", "value", "source", "verdict")}
            for c in extraction.get("checks", []) if c.get("verdict") != "exact"
        ]
    if ledger_names:
        lowered = {n.lower() for n in listed}
        row["ledger_package_named"] = any(n.lower() in lowered for n in ledger_names)
    if "registry_evidence" in record:
        row["registry_evidence"] = record["registry_evidence"]
    return row


def pin_precision_by_evidence(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Post-hoc: version-pin precision split by whether GHSA/OSV name a PyPI or npm package.

    Defined after reading the run, so it is reported as a reading aid for the
    candidate, not as a pre-registered figure.
    """
    rows = [r for r in rows if r.get("sonnet_pred") == "version-pin" and "registry_evidence" in r]
    if not rows:
        return None
    with_ev = [r for r in rows if r["registry_evidence"]]
    without = [r for r in rows if not r["registry_evidence"]]
    return {
        "with_evidence": metrics.ratio(sum(1 for r in with_ev if "version-pin" in r["acceptable"]), len(with_ev)),
        "without_evidence": metrics.ratio(sum(1 for r in without if "version-pin" in r["acceptable"]), len(without)),
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""


def build_results(
    truths: list[Truth],
    run_dir: Path,
    meta: dict[str, Any],
    ground_truth_path: Path = GROUND_TRUTH,
    context_for: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Join a run with the ground truth.

    With `context_for`, extraction is re-verified here from the stored model
    output, against the context rebuilt from the cache, so a fix to the
    verifier re-scores a run without re-asking the model. The rebuilt context
    must hash to the digest the record was screened against; a record whose
    context changed keeps its run-time verdicts and is listed in the meta.
    """
    rows = []
    missing = []
    rescored = 0
    changed: list[str] = []
    for truth in truths:
        path = run_dir / "records" / f"{truth.cve}.json"
        if not path.is_file():
            missing.append(truth.cve)
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        structured = (record.get("classification") or {}).get("structured")
        if context_for is not None and record.get("status") == "screened" and structured is not None:
            ctx = context_for(truth.cve)
            if context_digest(ctx) == record.get("context_digest"):
                record["extraction"] = verify_affected(ctx, structured.get("affected"))
                record["registry_evidence"] = sorted(
                    {eco for eco, _ in structured_packages(ctx)} & REGISTRY_ECOSYSTEMS
                )
                rescored += 1
            else:
                changed.append(truth.cve)
        rows.append(record_row(truth, record))
    if context_for is not None:
        meta = dict(meta, extraction_rescored=rescored, context_digest_changed=changed)
    screened = [r for r in rows if r["status"] == "screened"]
    post = [r for r in screened if r["post_cutoff"]]
    noise_calls = [r["noise_call"] for r in screened if r.get("noise_call")]
    clf_calls = [r["classify_call"] for r in screened if r.get("classify_call")]
    ledger_rows = [r for r in screened if "ledger_package_named" in r and r.get("sonnet_pred")]
    summary = {
        "population": {
            "ground_truth_records": len(truths),
            "screened": len(screened),
            "no_context": sum(1 for r in rows if r["status"] == "no-context"),
            "not_run": len(missing),
            "post_cutoff": len(post),
            "by_class": {c: sum(1 for r in screened if r["truth"] == c) for c in DISPOSITIONS},
            "noise": sum(1 for r in screened if r["truth_noise"]),
            "multi_label": sum(1 for r in screened if len(r["acceptable"]) > 1),
        },
        "sonnet": metrics.classification(screened, "sonnet_pred"),
        "sonnet_post_cutoff": metrics.classification(post, "sonnet_pred"),
        "pipeline": metrics.classification(screened, "pipeline_pred"),
        "noise_haiku": metrics.binary(screened, "truth_noise", "haiku_noise"),
        "noise_sonnet": metrics.binary(screened, "truth_noise", "sonnet_noise"),
        "extraction": metrics.extraction(screened),
        "ledger_package_named": {
            "k": sum(1 for r in ledger_rows if r["ledger_package_named"]),
            "n": len(ledger_rows),
        },
        "calls_haiku": metrics.calls(noise_calls),
        "calls_sonnet": metrics.calls(clf_calls),
        "pin_precision_by_evidence": pin_precision_by_evidence(screened),
    }
    return {
        "schema": "aak-cve-prescreen-results/1",
        "meta": dict(meta, ground_truth_sha256=_sha256(ground_truth_path), not_run=missing),
        "summary": summary,
        "records": rows,
    }


# ---------------------------------------------------------------------------
# RESULTS.md, rendered from results.json alone
# ---------------------------------------------------------------------------


def _pct(ratio: dict[str, Any]) -> str:
    if not ratio or not ratio.get("n"):
        return "n/a"
    low, high = ratio["ci95"]
    return f"{ratio['k']}/{ratio['n']} = {100 * ratio['rate']:.1f}% [{100 * low:.1f}%, {100 * high:.1f}%]"


def _money(dist: dict[str, Any], key: str) -> str:
    return f"${dist[key]:.4f}" if dist.get("n") else "n/a"


def _secs(dist: dict[str, Any], key: str) -> str:
    return f"{dist[key]:.1f}s" if dist.get("n") else "n/a"


def _confusion_table(conf: dict[str, dict[str, int]]) -> list[str]:
    head = "| truth \\ predicted | " + " | ".join(DISPOSITIONS) + " |"
    lines = [head, "|---|" + "---|" * len(DISPOSITIONS)]
    for truth in DISPOSITIONS:
        cells = " | ".join(str(conf[truth][p]) for p in DISPOSITIONS)
        lines.append(f"| {truth} | {cells} |")
    return lines


def render_markdown(results: dict[str, Any]) -> str:
    meta = results["meta"]
    s = results["summary"]
    pop = s["population"]
    lines: list[str] = []
    add = lines.append
    add("# CVE pre-screen backtest")
    add("")
    add(
        "Generated by `python -m benchmarks.cve_prescreen report` from `results.json`; "
        "`tests/test_cve_prescreen.py` fails if this page and that file disagree, so do "
        "not edit it by hand. What the pre-screen is, and why its output is only a "
        "candidate, is in `README.md`."
    )
    add("")
    add("## Run")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Prompt version | `{meta.get('prompt_version')}` |")
    add(f"| Claude Code | {meta.get('cli_version')} |")
    add(f"| Auth | `{meta.get('auth_method')}` ({meta.get('subscription_type')} subscription); `ANTHROPIC_API_KEY` removed |")
    add(f"| Models requested | noise `{meta.get('noise_model')}`, classification `{meta.get('classify_model')}` |")
    add(f"| Models that answered | noise {', '.join(s['calls_haiku']['models_used']) or 'none'}; classification {', '.join(s['calls_sonnet']['models_used']) or 'none'} |")
    add(f"| Concurrency | {meta.get('concurrency')} |")
    add(f"| Screened | {meta.get('run_started')} to {meta.get('run_finished')} |")
    add(f"| Ground truth | `ground_truth.json`, sha256 `{str(meta.get('ground_truth_sha256'))[:16]}...` |")
    if "extraction_rescored" in meta:
        changed = ", ".join(meta.get("context_digest_changed") or []) or "none"
        add(f"| Extraction verdicts | re-verified at report time for {meta['extraction_rescored']} records "
            f"against the cached context; contexts changed since screening: {changed} |")
    add("")
    add("## Population")
    add("")
    add(
        f"{pop['screened']} records screened of {pop['ground_truth_records']} in the ground truth "
        f"({pop['no_context']} had no record at any source, {pop['not_run']} were not run). "
        f"{pop['post_cutoff']} were published by NVD on or after {POST_CUTOFF}. "
        f"{pop['noise']} are keyword noise and {pop['multi_label']} accept two classes."
    )
    add("")
    add("| Ground-truth class | Records |")
    add("|---|---|")
    for cls in DISPOSITIONS:
        add(f"| {cls} | {pop['by_class'][cls]} |")
    add("")
    add("## Disposition accuracy")
    add("")
    add("95% Wilson intervals. `needs-human` counts as not correct in accuracy; coverage and "
        "selective accuracy report it separately.")
    add("")
    add("| Predictor | Scored | Accuracy | Coverage | Selective accuracy |")
    add("|---|---|---|---|---|")
    for label, key in (
        ("Sonnet, all records", "sonnet"),
        (f"Sonnet, published on or after {POST_CUTOFF}", "sonnet_post_cutoff"),
        ("Pipeline (Haiku noise gate, then Sonnet)", "pipeline"),
    ):
        m = s[key]
        add(f"| {label} | {m['scored']}/{m['records']} | {_pct(m['accuracy'])} | "
            f"{_pct(m['coverage'])} | {_pct(m['selective_accuracy'])} |")
    add("")
    add("### Confusion matrix (Sonnet, all records)")
    add("")
    add("A prediction matching any acceptable class is counted on the diagonal.")
    add("")
    lines.extend(_confusion_table(s["sonnet"]["confusion"]))
    add("")
    add("| Class | Precision | Recall |")
    add("|---|---|---|")
    for cls in DISPOSITIONS:
        pc = s["sonnet"]["per_class"][cls]
        add(f"| {cls} | {_pct(pc['precision'])} | {_pct(pc['recall'])} |")
    add("")
    split = s.get("pin_precision_by_evidence")
    if split:
        add("### When to trust a version-pin candidate (post hoc)")
        add("")
        add("Defined after reading the run, so it is a reading aid, not a pre-registered figure. "
            "Evidence means GHSA or OSV names a PyPI or npm package; container images never "
            "appear in those sources, so an image pin always lands in the second row.")
        add("")
        add("| version-pin candidates | Precision |")
        add("|---|---|")
        add(f"| GHSA or OSV names a PyPI or npm package | {_pct(split['with_evidence'])} |")
        add(f"| No PyPI or npm package in GHSA or OSV | {_pct(split['without_evidence'])} |")
        add("")
    add("## Noise filter")
    add("")
    add("A false positive here is a real agent or MCP record flagged as noise, the costly error "
        "for a filter that runs first, so the rate over every non-noise record is shown too.")
    add("")
    add("| Model | Precision | Recall | Non-noise records flagged | False positives | False negatives |")
    add("|---|---|---|---|---|---|")
    for label, key in (("Haiku (noise prompt)", "noise_haiku"), ("Sonnet (is_noise field)", "noise_sonnet")):
        m = s[key]
        fps = ", ".join(m["false_positive_ids"]) or "none"
        fns = ", ".join(m["false_negative_ids"]) or "none"
        add(f"| {label} | {_pct(m['precision'])} | {_pct(m['recall'])} | "
            f"{_pct(m['false_positive_rate'])} | {fps} | {fns} |")
    add("")
    add("## Extraction against the structured data")
    add("")
    e = s["extraction"]
    add("Every extracted value names the context field it was copied from; a value is exact "
        "when that field exists, is a structured field, and holds the same string.")
    add("")
    add("| Measure | Result |")
    add("|---|---|")
    add(f"| Values exact | {_pct(e['values'])} |")
    add(f"| Records whose every value is exact | {_pct(e['records_all_exact'])} |")
    add(f"| Records with an invented value | {e['records_with_invented_value']} |")
    add(f"| Package set equals the structured set | {_pct(e['package_set_exact'])} |")
    add(f"| Empty list when no structured field names a package | {_pct(e['empty_when_nothing_structured'])} |")
    lp = s["ledger_package_named"]
    add(f"| Names the package the ledger names (where it spells one) | {lp['k']}/{lp['n']} |")
    add("")
    verdicts = ", ".join(f"{k} {v}" for k, v in e["verdicts"].items()) or "none"
    add(f"Verdicts over all values: {verdicts}.")
    add("")
    add("## Calls, refusals and spend")
    add("")
    add("Cost is the CLI's `total_cost_usd`, a list-price figure (`costBasis` "
        f"{', '.join(s['calls_sonnet']['cost_basis']) or 'n/a'}); on a subscription it is not a charge.")
    add("")
    add("| Stage | Calls | OK | Refusals | Model mismatch | Cost mean | Cost median | Cost total | Wall mean | Wall median | Wall p90 |")
    add("|---|---|---|---|---|---|---|---|---|---|---|")
    for label, key in (("Noise (Haiku)", "calls_haiku"), ("Classification (Sonnet)", "calls_sonnet")):
        c = s[key]
        add(f"| {label} | {c['calls']} | {c['ok']} | {c['refusals']} | {c['model_mismatch']} | "
            f"{_money(c['cost_usd'], 'mean')} | {_money(c['cost_usd'], 'median')} | "
            f"{_money(c['cost_usd'], 'total')} | {_secs(c['wall_seconds'], 'mean')} | "
            f"{_secs(c['wall_seconds'], 'median')} | {_secs(c['wall_seconds'], 'p90')} |")
    add("")
    misses = [r for r in results["records"] if r.get("sonnet_pred") and r["sonnet_pred"] not in r["acceptable"]]
    add("## Every disagreement (Sonnet)")
    add("")
    if not misses:
        add("None.")
    else:
        add("| CVE | Truth | Predicted | Truth detail | Model rationale |")
        add("|---|---|---|---|---|")
        for r in sorted(misses, key=lambda r: (r["truth"], r["cve"])):
            why = (r.get("sonnet_rationale") or "").replace("|", "/").replace("\n", " ")
            add(f"| {r['cve']} | {r['truth']} | {r['sonnet_pred']} | {r['truth_detail']} | {why} |")
    add("")
    add("## Limitations")
    add("")
    for item in meta.get("limitations", []):
        add(f"- {item}")
    add("")
    return "\n".join(lines)


def load_results(path: Path = RESULTS_JSON) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def write_results(results: dict[str, Any], json_path: Path = RESULTS_JSON, md_path: Path = RESULTS_MD) -> None:
    json_path.write_text(json.dumps(results, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(results), encoding="utf-8")


def prompt_fingerprint() -> str:
    """SHA-256 over both prompts and schemas: what PROMPT_VERSION stands for."""
    blob = "\n".join([
        prompts.NOISE_SYSTEM, prompts.schema_json(prompts.NOISE_SCHEMA),
        prompts.CLASSIFY_SYSTEM, prompts.schema_json(prompts.CLASSIFY_SCHEMA),
    ])
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
