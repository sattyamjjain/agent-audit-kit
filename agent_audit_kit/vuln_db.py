from __future__ import annotations

import json
import urllib.request
from pathlib import Path

BUNDLED_DB: Path = Path(__file__).parent / "data" / "vuln_db.json"
CACHE_DIR: Path = Path.home() / ".agent-audit-kit"
CACHED_DB: Path = CACHE_DIR / "vuln_db.json"
UPDATE_URL: str = (
    "https://raw.githubusercontent.com/sattyamjjain/agent-audit-kit/main/"
    "agent_audit_kit/data/vuln_db.json"
)


def load_database() -> dict:
    """Load the vulnerability database, preferring cached over bundled.

    Attempts to load the cached database first (downloaded via
    ``update_database``), falling back to the bundled copy shipped
    with the package.

    Returns:
        A dictionary keyed by ecosystem (npm, python, rust, etc.)
        mapping package names to vulnerability details. Returns a
        default empty structure if no database can be loaded.
    """
    for path in [CACHED_DB, BUNDLED_DB]:
        if path.is_file():
            try:
                return json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
    return {"npm": {}, "python": {}, "rust": {}}


def update_database() -> int:
    """Fetch the latest vulnerability database from the remote URL.

    Downloads the JSON database and caches it locally at
    ``~/.agent-audit-kit/vuln_db.json``.

    Returns:
        The total number of vulnerability entries across all ecosystems
        on success, or -1 on failure.
    """
    try:
        req = urllib.request.Request(
            UPDATE_URL,
            headers={"User-Agent": "AgentAuditKit/0.2.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHED_DB.write_text(json.dumps(data, indent=2))
        total = sum(len(v) for v in data.values() if isinstance(v, dict))
        return total
    except Exception:  # noqa: BLE001
        return -1
