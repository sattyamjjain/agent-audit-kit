"""Constants and config helpers shared by ``cli`` and the command modules.

Extracted from ``cli.py`` unchanged. They live here rather than in ``cli`` so a
command module can use them without importing ``cli``, which imports the command
modules to register them — see ``agent_audit_kit.commands.__init__``.

``cli`` re-exports all of these, so existing imports from
``agent_audit_kit.cli`` continue to resolve.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agent_audit_kit.models import Severity

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

FAIL_ON_CHOICES = ["critical", "high", "medium", "low", "none"]

# Exit codes
EXIT_PASS = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _to_list(value: str | list[str] | None) -> list[str] | None:
    """Normalise a CLI string or YAML list into a Python list.

    Args:
        value: A comma-separated string, a list of strings, or None.

    Returns:
        A list of stripped strings, or None if the input is falsy.
    """
    if not value:
        return None
    if isinstance(value, list):
        return [str(v).strip() for v in value if v]
    return [v.strip() for v in value.split(",") if v.strip()]


def _load_config(config_path: str | None, project_root: Path) -> dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Explicit path to config file, or None for auto-detect.
        project_root: Project root directory for auto-detection.

    Returns:
        Dictionary of configuration values, empty if no config found.
    """
    if config_path:
        p = Path(config_path)
    else:
        p = project_root / ".agent-audit-kit.yml"

    if not p.is_file():
        return {}

    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    return data if isinstance(data, dict) else {}


def _apply_config_defaults(
    config: dict[str, Any],
    output_format: str,
    min_severity: str,
    fail_on: str,
    output_file: str | None,
    include_user_config: bool,
    ignore_paths: str | None,
    rules: str | None,
    exclude_rules: str | None,
    verbose: bool,
    show_score: bool,
    owasp_report: bool,
    compliance: str | None,
    verify_secrets: bool,
    diff_base: str | None,
    llm_scan: bool,
) -> dict[str, Any]:
    """Merge config file defaults with CLI flags. CLI flags take priority.

    Returns:
        Merged settings dictionary.
    """
    # Config file values serve as defaults; CLI-provided values override them.
    # We detect "CLI-provided" by checking against Click's own defaults.
    return {
        "output_format": output_format if output_format != "console" else config.get("format", output_format),
        "min_severity": min_severity if min_severity != "low" else config.get("severity", min_severity),
        "fail_on": fail_on if fail_on is not None else config.get("fail-on", "none"),
        "output_file": output_file or config.get("output", None),
        "include_user_config": include_user_config or config.get("include-user-config", False),
        "ignore_paths": ignore_paths or config.get("ignore-paths", None),
        "rules": rules or config.get("rules", None),
        "exclude_rules": exclude_rules or config.get("exclude-rules", None),
        "verbose": verbose or config.get("verbose", False),
        "show_score": show_score or config.get("score", False),
        "owasp_report": owasp_report or config.get("owasp-report", False),
        "compliance": compliance or config.get("compliance", None),
        "verify_secrets": verify_secrets or config.get("verify-secrets", False),
        "diff_base": diff_base or config.get("diff", None),
        "llm_scan": llm_scan or config.get("llm-scan", False),
    }
