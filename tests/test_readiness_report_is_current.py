"""The standing readiness report must still be true, or say that it is not.

``docs/reports/mcp-2026-07-28-readiness.md`` is written as a live artifact: it
carries no "historical snapshot" banner, it is linked as a current finding, and
it ends by promising a re-run "on ratification day (2026-07-28) and on a rolling
basis". It was generated once, in July, and then nothing ever checked it again.

Its numbers happen to have held -- ``scripts/mcp_2026_07_28_readiness.py``
reproduces all nine of them exactly, on 2026-09-04, because the corpus has not
moved. That is luck, not a guarantee, and luck is what this test replaces. The
corpus is a directory of files that any PR may add to; the day one lands, the
report becomes a confident wrong number with a citation, which is a worse
artifact than no report.

So the table is asserted against a fresh run, and the file must carry a
re-validation date. A report that reads as current is a claim, and a claim in
this repo gets a guard.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT = REPO_ROOT / "docs" / "reports" / "mcp-2026-07-28-readiness.md"
CORPUS = REPO_ROOT / "benchmarks" / "data"


def _load_readiness():
    script = REPO_ROOT / "scripts" / "mcp_2026_07_28_readiness.py"
    assert script.is_file(), "scripts/mcp_2026_07_28_readiness.py missing"
    spec = importlib.util.spec_from_file_location("mcp_readiness", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["mcp_readiness"] = module
    spec.loader.exec_module(module)
    return module


def _report_text() -> str:
    assert REPORT.is_file(), f"{REPORT.relative_to(REPO_ROOT)} missing"
    return REPORT.read_text(encoding="utf-8")


def _table_number(text: str, *needles: str) -> int:
    """Pull the count out of the ``| Metric | Count |`` row matching every needle.

    Reads the rendered table rather than a sidecar JSON on purpose: the rendered
    table is what a reader believes, so it is the thing worth checking. Handles
    the thousands separator and the bolding the report uses for its headline rows.

    Takes several needles because the report names each rule in two tables -- the
    "What the profile checks" table, whose second column is an RFC number, and
    the findings table. Matching on the rule id alone reads RFC **9207** as a hit
    count, which is how this helper was first written and what its first run
    caught.
    """
    label = needles[0]
    for line in text.splitlines():
        if not line.startswith("|") or not all(n in line for n in needles):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        for cell in cells[1:]:
            match = re.search(r"(\d[\d,]*)", cell)
            if match:
                return int(match.group(1).replace(",", ""))
    raise AssertionError(f"no table row for {label!r} in {REPORT.name}")


def test_every_number_in_the_report_reproduces() -> None:
    """Nine published counts, each re-derived from the corpus this run.

    ``benchmarks/data/`` is gitignored, so a bare CI checkout has no corpus and
    ``compute()`` would return zeros -- which is not the report being wrong, it is
    the report being unmeasurable. Skipping there matches what every other
    corpus-backed test in this suite does (``test_remediation_keys_are_real``,
    ``test_composition``, ``test_transport_flip_remediation``).

    Which does mean this guard bites where the corpus lives -- a maintainer
    checkout, and any job that fetches it -- and not on a bare CI run. That is
    worth stating plainly rather than letting the report imply a stronger promise
    than it has: it is the difference between "nobody re-derives this" and "the
    person holding the corpus cannot change it without being told".
    """
    if not CORPUS.is_dir() or not any(CORPUS.glob("*.json")):
        pytest.skip("benchmarks/data not present in this checkout")
    live = asdict(_load_readiness().compute())
    text = _report_text()

    for label, key in [
        ("Public MCP configs scanned", "corpus_configs"),
        ("Server entries across all configs", "server_entries"),
        ("Remote (HTTP/SSE/URL) server entries", "remote_entries"),
        ("Configs declaring", "configs_with_remote_server"),
        ("Remote configs embedding a static credential", "remote_configs_with_inline_credential"),
        ("Configs referencing RFC 9728 PRM discovery", "configs_referencing_rfc9728_prm"),
    ]:
        assert _table_number(text, label) == live[key], (
            f"{label!r} in {REPORT.name} disagrees with a fresh run "
            f"(report says {_table_number(text, label)}, corpus says {live[key]}). "
            f"Regenerate with `python scripts/mcp_2026_07_28_readiness.py`."
        )

    for rule in ("AAK-OAUTH-006", "AAK-OAUTH-007", "AAK-OAUTH-008"):
        assert _table_number(text, f"`{rule}`", "files flagged") == live["hits"][rule], (
            f"{rule} hit count in {REPORT.name} disagrees with a fresh run."
        )


def test_the_three_profile_rules_still_exist() -> None:
    """A report citing a rule id that no longer exists is unfalsifiable prose.

    Rules get renamed and merged here routinely; this is the cheap check that the
    report's whole premise is still in the registry.
    """
    from agent_audit_kit.rules.builtin import RULES

    for rule in ("AAK-OAUTH-006", "AAK-OAUTH-007", "AAK-OAUTH-008"):
        assert rule in RULES, f"{rule} is cited by {REPORT.name} but is not a rule"


def test_report_carries_a_revalidation_date() -> None:
    """The date is the honest half of "this is still current".

    Without it the reader has only the July scan date and a promise of rolling
    re-runs, and no way to tell whether either still describes the world.
    """
    text = _report_text()
    assert re.search(r"Re-validated:\*{0,2}\s*20\d\d-\d\d-\d\d", text), (
        "the report must state the date its numbers were last re-derived"
    )


def test_report_does_not_describe_the_spec_as_forthcoming() -> None:
    """The credibility bug this file exists to stop.

    The report was written while 2026-07-28 was a future publication date and
    said so in the present tense. Read after that date, a live-looking artifact
    describing a shipped spec as "scheduled" is wrong about the calendar, which
    invites the reader to discount the parts that are right.
    """
    text = _report_text()
    assert "final publication scheduled" not in text.lower(), (
        "the 2026-07-28 publication date has passed; the report must not still "
        "describe it as scheduled"
    )
