"""Back-compat shim.

`typescript_scan` was renamed to `typescript_pattern_scan` in v0.3.0
because the module is a regex pattern scanner, not a taint analyzer.
Imports from the old path keep working; please migrate.
"""

from __future__ import annotations

import warnings

from agent_audit_kit.scanners.typescript_pattern_scan import scan as _scan


def scan(*args, **kwargs):  # type: ignore[no-untyped-def]
    warnings.warn(
        "agent_audit_kit.scanners.typescript_scan is deprecated; "
        "import from agent_audit_kit.scanners.typescript_pattern_scan instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _scan(*args, **kwargs)


__all__ = ["scan"]
