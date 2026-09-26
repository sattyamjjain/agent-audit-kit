"""`scripts/render_report_pdf.py` — the stamp must describe the PDF on disk.

The docs site serves the report PDF at a stable URL, and the stamp beside it
(`.pdf.source.sha256`) is the only record of which `results.json` it was built
from: `make report-pdf-check` and the committed-PDF test below both read it. A
stamp naming numbers the PDF does not show is worse than no stamp, because it
turns the check into a certificate for a stale artifact.

These tests used to live in `test_docs_research_publishing.py`, which skips as a
whole module when MkDocs is missing. CI installs `.[dev]`, which has no MkDocs,
so the committed-PDF guard never ran there. Nothing here needs MkDocs.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_STALE_DIGEST = "0" * 64


def _module():
    spec = importlib.util.spec_from_file_location(
        "render_report_pdf", REPO_ROOT / "scripts" / "render_report_pdf.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["render_report_pdf"] = module
    spec.loader.exec_module(module)
    return module


render = _module()


def test_report_pdf_is_built_from_the_committed_results() -> None:
    """The site serves this PDF at a stable URL, so a stale one is a wrong number.

    It had been stale for roughly two months: the PDF was last written
    2026-07-26 while results.json moved three times after it, because nothing
    regenerated it and nothing compared them.
    """
    stamped = render.stamped_digest()
    assert stamped is not None, (
        "the report PDF carries no source stamp, so nothing records which "
        "numbers it shows. Run `make report-pdf` and commit both files."
    )
    assert stamped == render.results_digest(), (
        "the report PDF was rendered from a different results.json. "
        "Run `make report-pdf` and commit."
    )


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A real results.json, an old PDF and a stale stamp, with the script aimed at them."""
    results = tmp_path / "results.json"
    results.write_bytes((REPO_ROOT / "research/state-of-mcp-2026/results.json").read_bytes())
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"%PDF rendered from an older results.json")
    stamp = pdf.with_suffix(".pdf.source.sha256")
    stamp.write_text(f"{_STALE_DIGEST}  results.json\n", encoding="utf-8")
    monkeypatch.setattr(render, "RESULTS", results)
    monkeypatch.setattr(render, "PDF", pdf)
    monkeypatch.setattr(render, "STAMP", stamp)
    return tmp_path


def _without_reportlab(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every `import reportlab...` fail, as it does where it is not installed.

    A None entry in sys.modules halts an import. Cached submodules are masked
    too: `from reportlab.lib.pagesizes import ...` is answered from the cache
    without consulting the parent, so masking only `reportlab` lets a machine
    that has it installed render anyway once anything imported it.
    """
    for name in [n for n in sys.modules if n.startswith("reportlab.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "reportlab", None)


@pytest.mark.usefixtures("workspace")
def test_a_render_without_reportlab_leaves_the_stale_pdf_failing_the_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stamp was written whether or not the PDF was.

    Without reportlab, `emit_report_pdf` writes a text fallback and reports
    failure, and `render()` stamped the old PDF with the live digest anyway. So
    after a failed `make report`, `--check` and the committed-PDF test both
    passed while the site served numbers from an older results.json.
    """
    _without_reportlab(monkeypatch)

    assert render.main([]) == 1
    assert render.stamped_digest() == _STALE_DIGEST
    assert render.main(["--check"]) == 1


@pytest.mark.usefixtures("workspace")
def test_a_successful_render_stamps_the_results_it_was_built_from(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other side of the same line: a render that happened is stamped.

    The renderer is replaced because CI has no reportlab; what is under test is
    the script's bookkeeping around it, not reportlab's drawing.
    """

    def rendered(_results: dict, output_path: Path) -> tuple[bool, str]:
        output_path.write_bytes(b"%PDF rendered from the live results.json")
        return True, f"wrote {output_path}"

    monkeypatch.setattr("agent_audit_kit.output.pdf_report.emit_report_pdf", rendered)

    assert render.main([]) == 0
    assert render.stamped_digest() == render.results_digest()
    assert render.main(["--check"]) == 0
