"""The two out-of-scope dispositions of the 2026-10-13 batch, pinned as facts.

* CVE-2026-108859 (#975) - mcp-go through 1.2.1 reads a Streamable HTTP POST body
  with ``io.ReadAll`` before validating it. mcp-go is a Go library
  (``github.com/mark3labs/mcp-go``) with no image, and nothing in AAK reads a
  ``go.mod``, so no file AAK reads states the version a server embeds. v1.2.1
  (2026-10-09) is the newest release and ``server/streamable_http.go`` on ``main``
  still calls ``io.ReadAll(r.Body)``, so there is no fixed release either.
* CVE-2026-108854 (#977) - Wanwu before 0.6.3 deletes an AppKey by its numeric id
  alone. Fixed in v0.6.3 (``13d0b22``). Its compose file takes every service's
  whole image reference from ``${WANWU_BACKEND_IMAGE}``, which ``.env.image.amd64``
  and ``.env.image.arm64`` set, and the image reader opens neither file. The image
  lives on an account-scoped Aliyun registry whose tags could not be listed.

If a ``go.mod`` reader or an ``.env`` image reader is ever added, these tests fail
and both CVEs become re-triageable. That is the intent.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.scanners import container_image_pins
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _CANDIDATE_GLOBS, _CANDIDATE_NAMES

_WANWU_IMAGE = (
    "crpi-6pj79y7ddzdpexs8.cn-hangzhou.personal.cr.aliyuncs.com/wanwulite/wanwu-backend"
)


def _write(root: Path, name: str, body: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_no_pin_reads_a_go_manifest() -> None:
    readable = {n.lower() for n in _CANDIDATE_NAMES} | {g.lower() for g in _CANDIDATE_GLOBS}
    assert not any("go.mod" in n or "go.sum" in n for n in readable)


def test_an_mcp_go_server_states_no_version_aak_reads(tmp_path: Path) -> None:
    _write(tmp_path, "go.mod",
           "module example.com/server\n\ngo 1.24\n\n"
           "require github.com/mark3labs/mcp-go v1.2.1\n")
    findings = run_scan(tmp_path).findings
    assert not any("CVE-2026-108859" in f.cve_references for f in findings)


def test_the_image_reader_does_not_open_wanwus_env_file(tmp_path: Path) -> None:
    _write(tmp_path, ".env.image.amd64", f"WANWU_BACKEND_IMAGE={_WANWU_IMAGE}:v0.6.2-5fe36664\n")
    _write(tmp_path, "docker-compose.yaml",
           "services:\n  bff-service:\n    image: ${WANWU_BACKEND_IMAGE}\n")
    findings, scanned = container_image_pins.scan(tmp_path)
    assert findings == []
    assert scanned == {"docker-compose.yaml"}


def test_no_image_pin_names_wanwu() -> None:
    assert not any("wanwu" in pin.image for pin in container_image_pins._PINS)
