"""Tests for oauth_misconfig: AAK-OAUTH-007 in data files.

The scanner read .json, .yaml, .yml and .toml files with the token-request
pattern meant for code, so a data file that mentioned OAuth and a /token
path in prose was reported for a missing RFC 8707 `resource` parameter. In a
data file the request now has to be part of the data: a flow key or a value
that is wholly a token or authorization URL.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_audit_kit.scanners.oauth_misconfig import scan


# ---------------------------------------------------------------------------
# AAK-OAUTH-007 in data files: the flow has to be part of the data.
# ---------------------------------------------------------------------------

OAUTH_007 = "AAK-OAUTH-007"


def _lines_007(tmp_path: Path, name: str, src: str) -> list[int | None]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(src, encoding="utf-8")
    findings, _ = scan(tmp_path)
    return [f.line_number for f in findings if f.rule_id == OAUTH_007]


@pytest.mark.parametrize(("name", "src"), [
    # A results file whose prose mentions OAuth and a token path.
    ("data/results.json",
     '{"cases": [{"title": "oauth server returns 401 on /oauth/token", "verdict": "out-of-scope"}]}\n'),
    # A finding's evidence quoting a command, beside remediation prose.
    ("scan-results.json", (
        "{\n"
        '  "evidence": "Server \'lab\' headersHelper: curl -s https://auth.internal/token",\n'
        '  "remediation": "Use static headers or OAuth flows instead."\n'
        "}\n"
    )),
    # A registry id that happens to contain `/token`.
    ("baseline.json", '{"servers": [{"auth_posture": "oauth", "id": "ai.tachyo/token-safety"}]}\n'),
    ("notes.yaml", "title: the oauth client calls /oauth/token twice\nlinks: [see /authorize docs]\n"),
    ("data.toml", 'summary = "oauth: retries /oauth/token on 401"\n'),
    # A list of field names is no endpoint.
    ("fields.json", '{"oauth_fields": ["authorization_endpoint", "token_endpoint"]}\n'),
])
def test_oauth_007_skips_data_that_only_mentions_a_flow(tmp_path: Path, name: str, src: str) -> None:
    """The scanner read data files as client code, so any of them with the word
    oauth and a /token or /authorize path reported a missing resource
    parameter: on main, AAK's own case-study scan results and the State of MCP
    baseline did."""
    assert _lines_007(tmp_path, name, src) == []


@pytest.mark.parametrize(("name", "src", "line"), [
    # RFC 8414 server metadata advertises the endpoints: still in scope.
    ("oauth-authorization-server.json", (
        "{\n"
        '  "issuer": "https://auth.example.com",\n'
        '  "authorization_endpoint": "https://auth.example.com/authorize",\n'
        '  "token_endpoint": "https://auth.example.com/token"\n'
        "}\n"
    ), 3),
    ("client.yaml", "oauth:\n  client_id: mcp\n  token_url: https://auth.example.com/oauth/token  # issuer\n", 3),
    ("client.toml", '[oauth]\nclient_id = "mcp"\ntoken_url = "https://auth.example.com/oauth2/token"\n', 3),
    ("client.json", '{"oauth": {"client_id": "mcp", "urls": ["https://auth.example.com/oauth/authorize?x=1"]}}\n', 1),
    ("client.yaml", "oauth:\n  endpoints:\n    - /oauth/token\n", 3),
    ("compose.yml", 'services:\n  mcp:\n    environment:\n      - "OAUTH_GRANT=x"\n      grant_type: client_credentials\n', 5),
])
def test_oauth_007_still_reads_a_flow_in_data(tmp_path: Path, name: str, src: str, line: int) -> None:
    assert _lines_007(tmp_path, name, src) == [line]


def test_oauth_007_code_files_are_read_as_before(tmp_path: Path) -> None:
    """Only data files changed: a prose path in code still counts."""
    src = "# the oauth server returns 401 on /oauth/token\n"
    assert _lines_007(tmp_path, "client.py", src) == [1]


_CRAFTED_DATA = {
    "colon-slash": ":/" * 250_000,
    "path-run": '"x": "' + "/a" * 249_000 + '"',
    "url-run": ': "https://' + "a" * 499_000,
    "dash-lines": "- /" * 160_000,
}


@pytest.mark.parametrize("shape", sorted(_CRAFTED_DATA))
def test_oauth_007_crafted_data_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    src = "oauth\n" + _CRAFTED_DATA[shape]
    assert len(src) < 512_000
    for name in ("data.json", "data.yaml"):
        (tmp_path / name).write_text(src, encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 10.0
