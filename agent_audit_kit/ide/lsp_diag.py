"""LSP diagnostic adapter for AAK findings.

`diagnostics_for(path)` runs the scanner and converts each Finding into
an LSP-shape dict (per Language Server Protocol 3.17 — `Diagnostic`).

`serve_stdio(path)` runs a minimal stdio JSON-RPC LSP loop: it accepts
`initialize` + `textDocument/didOpen` + `textDocument/didChange` and
publishes `textDocument/publishDiagnostics`. The implementation is
deliberately small — enough for Zed and VS Code language clients to
attach without pulling in a third-party LSP framework.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity


_LSP_SEVERITY: dict[Severity, int] = {
    Severity.CRITICAL: 1,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _path_to_uri(path: Path) -> str:
    return path.resolve().as_uri()


def diagnostics_for(target: Path) -> list[dict[str, Any]]:
    """Run AAK against `target` (file or directory) and return
    LSP-shape diagnostics.

    For a single file, the scan runs against its parent directory and
    diagnostics are filtered to that file. For a directory, all
    findings are returned.
    """
    target = target.resolve()
    project_root = target.parent if target.is_file() else target
    result = run_scan(project_root=project_root)
    diagnostics: list[dict[str, Any]] = []
    for finding in result.findings:
        if not finding.file_path:
            continue
        finding_path = (project_root / finding.file_path).resolve()
        if target.is_file() and finding_path != target:
            continue
        line = max(0, (finding.line_number or 1) - 1)
        diagnostics.append({
            "uri": _path_to_uri(finding_path),
            "range": {
                "start": {"line": line, "character": 0},
                "end": {"line": line, "character": 200},
            },
            "severity": _LSP_SEVERITY.get(finding.severity, 2),
            "code": finding.rule_id,
            "source": "agent-audit-kit",
            "message": f"{finding.title}: {finding.evidence or ''}".strip(),
        })
    return diagnostics


def _read_message(stream) -> dict[str, Any] | None:
    """Read one LSP-framed JSON-RPC message from a binary stream."""
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        if line.strip() == b"":
            break
        if b":" not in line:
            continue
        k, _, v = line.decode("utf-8").partition(":")
        headers[k.strip().lower()] = v.strip()
    length = int(headers.get("content-length", "0"))
    if not length:
        return None
    body = stream.read(length)
    return json.loads(body.decode("utf-8"))


def _write_message(stream, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    stream.write(body)
    stream.flush()


def serve_stdio(root: Path) -> None:
    """Minimal stdio LSP server. Publishes diagnostics on did-open /
    did-change. Exits when the client closes stdin."""
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    initialized = False

    while True:
        msg = _read_message(stdin)
        if msg is None:
            return
        method = msg.get("method")
        if method == "initialize":
            initialized = True
            _write_message(stdout, {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "result": {
                    "capabilities": {
                        "textDocumentSync": 1,
                        "diagnosticProvider": {
                            "interFileDependencies": False,
                            "workspaceDiagnostics": False,
                        },
                    },
                    "serverInfo": {"name": "agent-audit-kit", "version": "0.3.9"},
                },
            })
            continue
        if method == "shutdown":
            _write_message(stdout, {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "result": None,
            })
            continue
        if method == "exit":
            return
        if not initialized:
            continue
        if method in {"textDocument/didOpen", "textDocument/didChange"}:
            params = msg.get("params", {}) or {}
            uri = (params.get("textDocument") or {}).get("uri", "")
            target_path = root
            if uri.startswith("file://"):
                target_path = Path(uri[7:])
            if not target_path.exists():
                continue
            diags = diagnostics_for(target_path)
            _write_message(stdout, {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": [
                    {k: v for k, v in d.items() if k != "uri"} for d in diags
                ]},
            })


__all__ = ["diagnostics_for", "serve_stdio"]
