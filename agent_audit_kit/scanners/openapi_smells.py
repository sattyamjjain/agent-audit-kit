"""OpenAPI smells scanner for MCP-on-REST migrations.

Anchored to Hermes (arXiv:2605.14312, EASE 2026 — large-scale eval of
2,450 smells across 600 endpoints), which identified three primary
shapes that break agent tool-selection accuracy when an OpenAPI 3.x
spec is auto-converted into MCP tools:

  - LAZY description    — operation.description missing or <40 chars.
  - BLOATED parameters  — operation.parameters length > 12, or
                          requestBody.schema.properties length > 24.
  - TANGLED methods     — same path has > 4 HTTP methods, or the
                          HTTP method contradicts the path segment
                          (POST /get/..., GET /create/...).

Auto-detection: scans for `openapi.yaml` / `openapi.yml` / `openapi.json`
/ `*.openapi.yaml` at project root or under `api/`, `openapi/`, `spec/`,
`docs/api/` subdirs. Files that don't parse as YAML/JSON with a top-
level `openapi:` or `swagger:` field are silently skipped.

Detector contract:
    scan(project_root) -> (list[Finding], set[str])
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from agent_audit_kit.models import Category, Finding, Severity


_OPENAPI_FILENAMES: frozenset[str] = frozenset({
    "openapi.yaml", "openapi.yml", "openapi.json",
    "swagger.yaml", "swagger.yml", "swagger.json",
})
_OPENAPI_SUBDIRS: frozenset[str] = frozenset({"api", "openapi", "spec", "docs/api"})
_HTTP_METHODS: frozenset[str] = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
})

_VERB_METHOD_CONFLICTS: dict[str, frozenset[str]] = {
    "get":    frozenset({"post", "put", "patch", "delete"}),
    "list":   frozenset({"post", "put", "patch", "delete"}),
    "fetch":  frozenset({"post", "put", "patch", "delete"}),
    "read":   frozenset({"post", "put", "patch", "delete"}),
    "create": frozenset({"get", "delete"}),
    "add":    frozenset({"get", "delete"}),
    "new":    frozenset({"get", "delete"}),
    "update": frozenset({"get", "delete"}),
    "edit":   frozenset({"get", "delete"}),
    "delete": frozenset({"get", "post"}),
    "remove": frozenset({"get", "post"}),
}


def _candidate_files(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for name in _OPENAPI_FILENAMES:
        p = project_root / name
        if p.is_file():
            out.append(p)
    for sub in _OPENAPI_SUBDIRS:
        sub_dir = project_root / sub
        if sub_dir.is_dir():
            for entry in sub_dir.rglob("*"):
                if not entry.is_file():
                    continue
                if entry.name.lower() in _OPENAPI_FILENAMES:
                    out.append(entry)
                elif entry.suffix.lower() in {".yaml", ".yml", ".json"} \
                        and "openapi" in entry.name.lower():
                    out.append(entry)
    for entry in project_root.glob("*.openapi.*"):
        if entry.is_file():
            out.append(entry)
    return sorted(set(out))


def _load(path: Path) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    if "openapi" not in data and "swagger" not in data:
        return None
    return data


def _check_lazy(op: dict) -> str | None:
    desc = op.get("description") or op.get("summary") or ""
    if not isinstance(desc, str) or len(desc.strip()) < 40:
        return f"description length={len(desc.strip())} (< 40)"
    return None


def _request_body_property_count(op: dict) -> int:
    rb = op.get("requestBody") or {}
    if not isinstance(rb, dict):
        return 0
    content = rb.get("content") or {}
    if not isinstance(content, dict):
        return 0
    total = 0
    for media in content.values():
        if not isinstance(media, dict):
            continue
        schema = media.get("schema") or {}
        if not isinstance(schema, dict):
            continue
        props = schema.get("properties") or {}
        if isinstance(props, dict):
            total = max(total, len(props))
    return total


def _check_bloated(op: dict) -> str | None:
    params = op.get("parameters") or []
    nparams = len(params) if isinstance(params, list) else 0
    nbody = _request_body_property_count(op)
    if nparams > 12:
        return f"parameters={nparams} (> 12)"
    if nbody > 24:
        return f"requestBody properties={nbody} (> 24)"
    return None


def _check_tangled_path(path: str, methods_on_path: list[str]) -> str | None:
    if len(methods_on_path) > 4:
        return f"path '{path}' supports {len(methods_on_path)} HTTP methods"
    segs = [s.lower() for s in re.split(r"[/{}]+", path) if s]
    for verb, bad_methods in _VERB_METHOD_CONFLICTS.items():
        if verb in segs:
            for m in methods_on_path:
                if m.lower() in bad_methods:
                    return f"path '{path}' contains '/{verb}/' but supports {m.upper()}"
    return None


def _make_finding(
    rule_id: str,
    title: str,
    rel: str,
    line: int | None,
    evidence: str,
    remediation: str,
    severity: Severity,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=title,
        severity=severity,
        category=Category.TOOL_POISONING,
        file_path=rel,
        line_number=line,
        evidence=evidence,
        remediation=remediation,
        incident_references=["ARXIV-2605.14312"],
    )


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()

    for path in _candidate_files(project_root):
        data = _load(path)
        if data is None:
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        paths_block = data.get("paths") or {}
        if not isinstance(paths_block, dict):
            continue

        for url_path, methods_block in paths_block.items():
            if not isinstance(methods_block, dict):
                continue
            methods_present = [m for m in methods_block.keys() if m.lower() in _HTTP_METHODS]

            tangled = _check_tangled_path(url_path, methods_present)
            if tangled:
                findings.append(_make_finding(
                    "AAK-MCP-OPENAPI-TANGLED-METHODS-001",
                    "OpenAPI tangled methods + paths",
                    rel, None, tangled,
                    "Split the tangled path into >=2 disjoint paths, each "
                    "owning <=4 methods with method-name and path-segment in "
                    "semantic agreement.",
                    Severity.MEDIUM,
                ))

            for method_name, op in methods_block.items():
                if method_name.lower() not in _HTTP_METHODS:
                    continue
                if not isinstance(op, dict):
                    continue
                lazy = _check_lazy(op)
                if lazy:
                    findings.append(_make_finding(
                        "AAK-MCP-OPENAPI-LAZY-DESCRIPTION-001",
                        "OpenAPI operation has missing or sub-40-char description",
                        rel, None,
                        f"{method_name.upper()} {url_path} — {lazy}",
                        "Author a >=40-character description naming the "
                        "operation's purpose, input shape, and side-effect class.",
                        Severity.MEDIUM,
                    ))
                bloated = _check_bloated(op)
                if bloated:
                    findings.append(_make_finding(
                        "AAK-MCP-OPENAPI-BLOATED-PARAMS-001",
                        "OpenAPI operation has too many parameters or properties",
                        rel, None,
                        f"{method_name.upper()} {url_path} — {bloated}",
                        "Decompose the operation into smaller MCP tools, each "
                        "owning <=12 parameters.",
                        Severity.LOW,
                    ))
    return findings, scanned


__all__ = ["scan"]
