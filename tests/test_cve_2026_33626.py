"""AAK-LMDEPLOY-VL-SSRF-001 — vision-language image loader SSRF."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.ssrf_redirect import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-33626"


def test_vulnerable_vl_pipeline_fires(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "vulnerable", tmp_path, dirs_exist_ok=True)
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-LMDEPLOY-VL-SSRF-001" for f in findings)


def test_guarded_vl_pipeline_passes(tmp_path: Path) -> None:
    (tmp_path / "pipeline.py").write_text(
        "import lmdeploy\n"
        "from lmdeploy.serve.vl_engine import VLEngine\n"
        "from starlette.middleware.trustedhost import TrustedHostMiddleware\n"
        "ALLOWED_HOSTS = {'images.internal'}\n"
        "def f(url):\n"
        "    engine = VLEngine()\n"
        "    return engine.preprocess_image_url(url)\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-LMDEPLOY-VL-SSRF-001" for f in findings)


def test_non_lmdeploy_passes(tmp_path: Path) -> None:
    (tmp_path / "f.py").write_text(
        "def f(url):\n"
        "    return preprocess_image_url(url)\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-LMDEPLOY-VL-SSRF-001" for f in findings)
