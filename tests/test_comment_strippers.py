"""The comment strippers read a crafted file in linear time and strip what they did.

Fifteen scanners blank comments with a lazy `/\\*.*?\\*/` (or `<!--[\\s\\S]*?-->`)
before they look for anything. Block comments do not nest, so an opener after
the last closer can never close, but the lazy pattern still read from each such
opener to the end of the file: 80,000 characters of `/* a` took 3.3 seconds, and
the time grew with the square of the file. `_helpers.sub_up_to_last`,
`finditer_up_to_last` and `sub_comments` read only up to the last closer.
"""

from __future__ import annotations

import importlib
import time
from pathlib import Path

import pytest

from agent_audit_kit.scanners import _helpers, argv_toctou, dns_rebind, skill_poisoning, transport_limits

_SHAPES = [
    "",
    "a /* b */ c",
    "/* a */ /* b",
    "/* a /* b */ c */ d",
    "/*/ x */",
    "x // a /* b\n*/ c",
    "# a /* b\n*/ c /* d // e */",
    "a */ b /* c",
    "/* a\n b */ // c\n /* d",
    "<!-- a --> b <!-- c",
    "<!-- a <!-- b --> c -->",
]


@pytest.mark.parametrize("text", _SHAPES)
def test_the_helpers_strip_what_the_patterns_did(text: str) -> None:
    block = argv_toctou._TS_BLOCK_COMMENT_RE
    assert _helpers.sub_up_to_last(block, " ", text, "*/") == block.sub(" ", text)
    html = skill_poisoning._HTML_COMMENT_RE
    assert [m.span() for m in _helpers.finditer_up_to_last(html, text, "-->")] == [m.span() for m in html.finditer(text)]
    for mod in (dns_rebind, transport_limits):
        assert mod._strip_comments(text) == mod._LINE_COMMENT_RE.sub("", text)


_STRIPPERS = [
    ("argv_toctou", "_strip_ts_comments"),
    ("llm_sql_rce", "_strip_ts_comments"),
    ("mcp_auth_pathtraversal", "_strip_comments"),
    ("mcp_ssrf_toolarg", "_strip_comments"),
    ("mcp_http_noauth_server", "_strip_ts_comments"),
    ("mcp_env_placeholder_exfil", "_strip_ts_comments"),
    ("mcp_transport_session_unauth", "_strip_ts_comments"),
    ("mcp_toolgate_asymmetry", "_strip_ts_comments"),
    ("ssrf_bracketed_host", "_strip_comments"),
    ("dns_rebind", "_strip_comments"),
    ("transport_limits", "_strip_comments"),
]


_UNCLOSED = {
    "openers": "/* a" * 250_000,
    # The last `*/` sits inside a line comment, which is read whole.
    "closer-in-a-line-comment": "// a */ b\n" + "/* a" * 250_000,
}


@pytest.mark.parametrize(("module", "function"), _STRIPPERS)
@pytest.mark.parametrize("shape", sorted(_UNCLOSED))
def test_a_file_of_unclosed_comments_strips_in_linear_time(module: str, function: str, shape: str) -> None:
    """1 MB of an unclosed opener repeated. The bound is loose for slow CI
    runners; each takes a fraction of a second."""
    strip = getattr(importlib.import_module(f"agent_audit_kit.scanners.{module}"), function)
    text = _UNCLOSED[shape]
    started = time.perf_counter()
    strip(text)
    assert time.perf_counter() - started < 5.0


@pytest.mark.parametrize("call", [
    lambda text: importlib.import_module("agent_audit_kit.scanners.approval_parser_desync")._strip_comments(text, Path("x.ts")),
    lambda text: importlib.import_module("agent_audit_kit.scanners.mcp_tools_list_unbounded")._strip_comments(text, False),
    lambda text: importlib.import_module("agent_audit_kit.scanners.policy_truncation")._strip_prose(text, False),
    lambda text: importlib.import_module("agent_audit_kit.scanners._ssrf_reach").strip_comments(text, False),
    lambda text: skill_poisoning._hidden_instruction_hits(text.replace("/*", "<!--")),
])
def test_the_other_strippers_read_unclosed_comments_in_linear_time(call: object) -> None:
    text = "/* a" * 250_000
    started = time.perf_counter()
    call(text)  # type: ignore[operator]
    assert time.perf_counter() - started < 5.0


def test_an_instruction_file_of_unclosed_html_comments_scans_in_linear_time(tmp_path: Path) -> None:
    """agent_config reads every HTML comment in an instruction file."""
    from agent_audit_kit.scanners.agent_config import scan

    (tmp_path / "CLAUDE.md").write_text("<!-- a" * 160_000, encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 5.0
