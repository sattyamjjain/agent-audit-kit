"""Scanner input for AAK-STARTUP-HOOK-CONFTEST-001: a fixture reading one setting, not reported."""
import os

import pytest


@pytest.fixture
def database_url():
    return os.environ.get("DATABASE_URL")
