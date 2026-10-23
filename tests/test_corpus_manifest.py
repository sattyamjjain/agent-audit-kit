"""`aak corpus update` writes `<data dir>/<target_filename>` with the name the manifest
gives; the loader refuses a name that is not a bare file name (#1060, row 6)."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.corpus import manifest
from agent_audit_kit.corpus.manifest import (
    CorpusManifestWarning,
    is_bare_file_name,
    load_manifest,
)

_URL = "https://example.invalid/corpora/manifest.json"


def _entry(cid: str, target_filename: str | None) -> dict:
    raw = {
        "id": cid,
        "body_url": f"https://example.invalid/corpora/{cid}.json",
        "sha256": "0" * 64,
    }
    if target_filename is not None:
        raw["target_filename"] = target_filename
    return raw


def _serve(monkeypatch: pytest.MonkeyPatch, entries: list[dict]) -> list[str]:
    """Answer every fetch with the manifest, and record what was asked for."""
    asked: list[str] = []

    def fake_get(url: str, timeout: int = 30) -> bytes:
        asked.append(url)
        return json.dumps({"corpora": entries}).encode("utf-8")

    monkeypatch.setattr(manifest, "_http_get", fake_get)
    return asked


@pytest.mark.parametrize("name", [
    "placeholder", "placeholder.json", "ipi_wild_payloads_2026_04.json", ".placeholder", "a..b",
])
def test_a_bare_file_name_is_accepted(name: str) -> None:
    assert is_bare_file_name(name)


@pytest.mark.parametrize("name", [
    "../placeholder", "..", ".", "", "sub/placeholder", "/placeholder", "/tmp/placeholder",
    "placeholder/", "..\\placeholder", "sub\\placeholder", "placeholder\0",
])
def test_a_path_is_not_a_bare_file_name(name: str) -> None:
    assert not is_bare_file_name(name)


def test_a_manifest_naming_a_bare_file_loads_into_the_data_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, [_entry("placeholder", "placeholder.json")])
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        entries = load_manifest(_URL)
    assert [e.id for e in entries] == ["placeholder"]
    assert entries[0].target_path == manifest._DATA_DIR / "placeholder.json"
    assert entries[0].target_path.parent == manifest._DATA_DIR


@pytest.mark.parametrize("name", ["../placeholder", "/tmp/placeholder", "sub/placeholder", ".."])
def test_a_manifest_naming_a_path_is_skipped_with_a_warning(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """The entry naming `../placeholder` (or any other path) is dropped and said so; the
    bare-named entry beside it still loads. Before, `target_path` was `<data dir>/../placeholder`
    and `write_corpus` wrote there."""
    _serve(monkeypatch, [_entry("escape", name), _entry("placeholder", "placeholder.json")])
    with pytest.warns(CorpusManifestWarning, match="skipped 'escape'") as caught:
        entries = load_manifest(_URL)
    assert [e.id for e in entries] == ["placeholder"]
    assert all(e.target_path.parent == manifest._DATA_DIR for e in entries)
    assert len(caught) == 1
    assert repr(name) in str(caught[0].message)


def test_an_id_used_as_the_default_name_is_checked_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no `target_filename` the id is the name, so a path-shaped id is refused the same way."""
    _serve(monkeypatch, [_entry("../placeholder", None)])
    with pytest.warns(CorpusManifestWarning, match="not a bare file name"):
        assert load_manifest(_URL) == []


def test_a_non_string_target_filename_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, [_entry("placeholder", ["placeholder.json"])])  # type: ignore[list-item]
    with pytest.warns(CorpusManifestWarning, match="not a bare file name"):
        assert load_manifest(_URL) == []


def test_corpus_update_prints_the_skip_and_fetches_nothing_for_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The command says which entry it skipped and why, on stderr, and never fetches
    its body. The surviving entry is fetched; its digest does not match the
    placeholder body, so the run fails on that and writes nothing."""
    asked = _serve(monkeypatch, [
        _entry("ipi_wild_2026_04", "../placeholder"),
        _entry("fhi_universal_suffixes", "fhi_universal_suffixes.txt"),
    ])
    monkeypatch.setattr(manifest, "_DATA_DIR", tmp_path)
    result = CliRunner().invoke(cli, ["corpus", "update", "--all", "--manifest", _URL])
    assert "Warning: corpus manifest: skipped 'ipi_wild_2026_04': target_filename '../placeholder'" in result.output
    assert "VERIFY FAILED" in result.output  # the bare-named entry was fetched and checked
    assert "ipi_wild_2026_04.json" not in " ".join(asked[1:])
    assert asked[1:] == ["https://example.invalid/corpora/fhi_universal_suffixes.json"]
    assert not (tmp_path.parent / "placeholder").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == []
