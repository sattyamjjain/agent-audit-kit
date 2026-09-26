"""scripts/release_sbom.py: the SBOM a release attaches describes the release.

From v0.3.0 to v0.6.9 the release job ran `agent-audit-kit sbom .` on this
repository. That command inventories the MCP servers a scanned project declares,
and this repository declares none, so every signed SBOM attached to a release
listed zero components.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from importlib import metadata
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "release_sbom.py"
# The interpreter's own answer, not `__version__`: a stale egg-info ahead on
# sys.path changes both alike, and the SBOM describes what metadata resolves.
ROOT_PURL = f"pkg:pypi/agent-audit-kit@{metadata.version('agent-audit-kit')}"


def _load():
    spec = importlib.util.spec_from_file_location("release_sbom", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["release_sbom"] = module
    spec.loader.exec_module(module)
    return module


def _purls(components: list[dict]) -> set[str]:
    return {c["purl"].split("@")[0] for c in components}


def test_the_closure_is_the_runtime_dependencies() -> None:
    """click and pyyaml are in; the `dev` and `taint` extras are not, installed or not."""
    root, deps, _ = _load().closure("agent-audit-kit")
    names = {_load().normalize(d.metadata["Name"]) for d in deps}
    assert root.version == metadata.version("agent-audit-kit")
    assert {"click", "pyyaml"} <= names
    assert not names & {"pytest", "ruff", "mypy", "mkdocs", "tree-sitter"}


def test_the_cyclonedx_document_describes_the_package() -> None:
    doc = _load().cyclonedx(*_load().closure("agent-audit-kit"))
    assert (doc["bomFormat"], doc["specVersion"]) == ("CycloneDX", "1.5")
    assert doc["metadata"]["component"]["purl"] == ROOT_PURL
    assert {"pkg:pypi/click", "pkg:pypi/pyyaml"} <= _purls(doc["components"])
    root_deps = next(d for d in doc["dependencies"] if d["ref"] == ROOT_PURL)["dependsOn"]
    assert {"pkg:pypi/click", "pkg:pypi/pyyaml"} <= {p.split("@")[0] for p in root_deps}
    refs = {c["bom-ref"] for c in doc["components"]} | {ROOT_PURL}
    assert all(d["ref"] in refs and set(d["dependsOn"]) <= refs for d in doc["dependencies"])


def test_the_spdx_document_relates_every_package() -> None:
    doc = _load().spdx(*_load().closure("agent-audit-kit"))
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", doc["creationInfo"]["created"])
    ids = {p["SPDXID"]: p for p in doc["packages"]}
    assert all(re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", i) for i in ids)
    described = [r for r in doc["relationships"] if r["relationshipType"] == "DESCRIBES"]
    assert [ids[r["relatedSpdxElement"]]["name"] for r in described] == ["agent-audit-kit"]
    root_id = described[0]["relatedSpdxElement"]
    depends = {ids[r["relatedSpdxElement"]]["name"].lower() for r in doc["relationships"]
               if r["relationshipType"] == "DEPENDS_ON" and r["spdxElementId"] == root_id}
    assert {"click", "pyyaml"} <= depends
    purls = {ref["referenceLocator"] for p in doc["packages"] for ref in p["externalRefs"]}
    assert ROOT_PURL in purls


def test_a_package_that_is_not_installed_is_refused() -> None:
    with pytest.raises(SystemExit, match="not installed"):
        _load().closure("no-such-package-anywhere")


def test_main_writes_both_documents(tmp_path: Path) -> None:
    cdx, spdx = tmp_path / "sbom.cdx.json", tmp_path / "sbom.spdx.json"
    assert _load().main(["--cyclonedx", str(cdx), "--spdx", str(spdx)]) == 0
    assert json.loads(cdx.read_text(encoding="utf-8"))["components"]
    assert json.loads(spdx.read_text(encoding="utf-8"))["packages"]


def _release_steps(job: str) -> list[dict]:
    doc = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    return doc["jobs"][job]["steps"]


def test_the_release_job_describes_the_package_not_the_repository() -> None:
    runs = "\n".join(s.get("run", "") for s in _release_steps("bundle-and-sign"))
    assert "agent-audit-kit sbom ." not in runs
    assert "scripts/release_sbom.py" in runs


def test_the_release_notes_pull_the_tag_the_image_is_pushed_under() -> None:
    """Image tags drop the `v`; the notes said `docker pull ...:v0.6.9`, which 404s."""
    def version_step(job: str) -> str:
        return next(s["run"] for s in _release_steps(job) if s.get("id") == "version")

    assert version_step("github-release") == version_step("docker")
    body = next(s["with"]["body"] for s in _release_steps("github-release") if s.get("name") == "Create release")
    pulls = re.findall(r"docker pull ghcr\.io/sattyamjjain/agent-audit-kit:(.+?)\s*$", body, re.M)
    assert pulls == ["${{ steps.version.outputs.version }}"]
