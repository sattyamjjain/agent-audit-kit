"""AAK-PIPELOCK-POLICY-TRANSLATOR-001 — Pipelock v2.3 → AAK config.

Pipelock (https://github.com/jwaldrep/pipelock) ships a YAML policy DSL
for AI agent pipelines. This translator converts a Pipelock v2.3.x
policy file into a `.agent-audit-kit.yml` config that AAK consumes
directly.

Mapping (best-effort; unknown fields are surfaced as comments):

    Pipelock                          AAK
    --------                          ---
    schema: pipelock/v2.3             # validated, then dropped
    name:                             # rendered as a header comment
    rules.allow / rules.deny[*].id    rules: / exclude-rules:
    rules.deny[*].severity_floor      severity:
    integrations.git.fail_on          fail-on:
    paths.ignore[]                    ignore-paths: (csv)
    integrations.user_config_scan     include-user-config: (bool)
    output.format                     format:
    output.file                       output:
    integrations.parity.dimension     parity-dimension:
    integrations.parity.metric        parity-metric:

Anything else is preserved as a YAML comment block at the top of the
output so the operator can hand-merge if needed.
"""
from __future__ import annotations

from pathlib import Path

import yaml


_SCHEMA_PREFIX = "pipelock/v2."


def _stringify_paths(values: object) -> str:
    if isinstance(values, list):
        return ",".join(str(v) for v in values if v)
    return str(values)


def translate(policy_path: Path) -> str:
    """Translate a Pipelock policy file into AAK YAML config text.

    Args:
        policy_path: Path to a Pipelock v2.3.x YAML policy file.

    Returns:
        YAML string suitable for writing to `.agent-audit-kit.yml`.
    """
    raw = policy_path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError("Pipelock policy must be a YAML mapping at root")
    schema = str(data.get("schema", ""))
    if not schema.startswith(_SCHEMA_PREFIX):
        raise ValueError(
            f"Unsupported Pipelock schema {schema!r}; expected pipelock/v2.x"
        )

    name = data.get("name", "<unnamed pipelock policy>")
    rules_block = data.get("rules", {}) or {}
    integrations = data.get("integrations", {}) or {}
    paths_block = data.get("paths", {}) or {}
    output = data.get("output", {}) or {}

    out: dict[str, object] = {}

    allow = rules_block.get("allow")
    if isinstance(allow, list) and allow:
        out["rules"] = list(allow)

    deny = rules_block.get("deny")
    severity_floor = None
    if isinstance(deny, list):
        deny_ids = [d.get("id") for d in deny if isinstance(d, dict) and d.get("id")]
        if deny_ids:
            out["exclude-rules"] = deny_ids
        for entry in deny:
            if isinstance(entry, dict) and entry.get("severity_floor"):
                severity_floor = entry["severity_floor"]
                break
    if severity_floor:
        out["severity"] = str(severity_floor).lower()

    git_block = integrations.get("git", {}) or {}
    if "fail_on" in git_block:
        out["fail-on"] = str(git_block["fail_on"]).lower()

    user_scan = integrations.get("user_config_scan")
    if isinstance(user_scan, bool):
        out["include-user-config"] = user_scan

    ignored = paths_block.get("ignore")
    if ignored:
        out["ignore-paths"] = _stringify_paths(ignored)

    if "format" in output:
        out["format"] = output["format"]
    if "file" in output:
        out["output"] = output["file"]

    parity = integrations.get("parity", {}) or {}
    if "dimension" in parity:
        out["parity-dimension"] = parity["dimension"]
    if "metric" in parity:
        out["parity-metric"] = parity["metric"]

    header = (
        f"# Translated from Pipelock policy: {name}\n"
        f"# Source schema: {schema}\n"
        "# AAK-PIPELOCK-POLICY-TRANSLATOR-001\n"
    )

    untranslated = sorted(
        k for k in data.keys()
        if k not in {"schema", "name", "rules", "integrations", "paths", "output"}
    )
    if untranslated:
        header += "# Untranslated top-level keys (review manually):\n"
        for key in untranslated:
            header += f"#   - {key}\n"

    return header + yaml.safe_dump(out, sort_keys=True, default_flow_style=False)


__all__ = ["translate"]
