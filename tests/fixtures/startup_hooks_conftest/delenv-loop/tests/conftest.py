"""Scanner input for AAK-STARTUP-HOOK-CONFTEST-001: aak's own tests/conftest.py loop, not reported."""
import os

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key in [k for k in os.environ if k.lower() == "npm_config_cache"]:
        monkeypatch.delenv(key)
    monkeypatch.setenv("npm_config_cache", str(tmp_path / ".npm"))
