"""CVE-2026-41481 — langchain-text-splitters SSRF redirect bypass."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.scanners.ssrf_redirect import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-41481"


def test_vulnerable_redirect_pattern_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-redirect")
    assert any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_patched_no_redirect_pattern_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-no-redirect")
    assert not any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_vulnerable_pin_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-pin")
    assert any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_patched_pin_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-pin")
    assert not any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_ts_fetch_without_redirect_off_fires(tmp_path: Path) -> None:
    (tmp_path / "tool.ts").write_text(
        """
async function fetchDoc(url: string) {
  if (!validateSafeUrl(url)) throw new Error("unsafe");
  const r = await fetch(url);
  return r.text();
}
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_ts_fetch_redirect_manual_passes(tmp_path: Path) -> None:
    (tmp_path / "tool.ts").write_text(
        """
async function fetchDoc(url: string) {
  if (!validateSafeUrl(url)) throw new Error("unsafe");
  const r = await fetch(url, { redirect: 'manual' });
  return r.text();
}
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_unrelated_get_without_validator_passes(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(
        "import requests\nrequests.get('https://example.com')\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


# The pin took the first number after the name, so `langchain-text-splitters<1.1.2`,
# which admits only affected releases, read as the fix and was silent, and the
# extras in `langchain-text-splitters[html]==1.1.2` read as a name with no version
# and fired. Manifests are now read as the CVE pin table reads them.


@pytest.mark.parametrize(("manifest", "text", "fires"), [
    ("requirements.txt", "langchain-text-splitters<1.1.2\n", True),
    ("requirements.txt", "langchain-text-splitters<2.0.0,>=1.0.0\n", True),
    ("requirements.txt", "langchain-text-splitters[html]==1.1.2\n", False),
    ("requirements.txt", "langchain-text-splitters[html]==1.1.1\n", True),
    ("requirements.txt", "langchain-text-splitters\n", True),   # no version stated, reported as before
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["langchain-text-splitters<1.1.2"]\n', True),
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["langchain-text-splitters"]\n', True),
    ("pyproject.toml", '[tool.poetry.dependencies]\nlangchain-text-splitters = "^1.1.2"\n', False),
])
def test_pin_reads_ranges_extras_and_pyproject(tmp_path: Path, manifest: str, text: str, fires: bool) -> None:
    (tmp_path / manifest).write_text(text, encoding="utf-8")
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings) is fires


# Lockfiles are read with the CVE pin table's lockfile reader. The old pattern
# wanted TOML `name =` and `version =` lines, one after the other, so Pipfile.lock's
# JSON never matched, and neither did a uv.lock entry under a PEP 503 spelling.
_PIPFILE_LOCK = '{"_meta": {}, "default": {"langchain-text-splitters": {"hashes": [], "version": "==%s"}}}'


@pytest.mark.parametrize(("lockfile", "text", "fires"), [
    ("Pipfile.lock", _PIPFILE_LOCK % "1.1.1", True),
    ("Pipfile.lock", _PIPFILE_LOCK % "1.1.2", False),
    ("uv.lock", '[[package]]\nname = "langchain_text_splitters"\nversion = "1.1.1"\n', True),
    ("uv.lock", '[[package]]\nname = "langchain-text-splitters"\nversion = "1.1.2"\n', False),
    ("poetry.lock", '[[package]]\nname = "langchain-text-splitters"\nversion = "1.1.1"\ndescription = "x"\n', True),
    ("poetry.lock", '[[package]]\nname = "langchain-text-splitters"\nversion = "1.1.2"\n', False),
])
def test_pin_reads_lockfiles_as_the_pin_table_does(tmp_path: Path, lockfile: str, text: str, fires: bool) -> None:
    (tmp_path / lockfile).write_text(text, encoding="utf-8")
    findings, _ = scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001"]
    assert bool(hits) is fires
    if fires:
        assert [(f.file_path, f.evidence.split(" — ")[0]) for f in hits] == [(lockfile, "langchain-text-splitters pinned at '1.1.1'")]
