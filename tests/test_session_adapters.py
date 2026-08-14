"""Tests for the session-transcript adapters (agent_audit_kit/sessions/adapters.py).

AAK-AGENT-COMPOSE-002 shipped in 0.3.74 reading only `*.session.json` and JSON
under `.aak/sessions/` — the file a user writes by hand, not what any framework
emits. These cover the adapters that normalise real transcripts into the same
ordered call list, so the rule fires on real data with no rule change.

One fixture and one splice test per supported format.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.sessions.adapters import (
    SUPPORTED_FORMATS,
    detect_format,
    from_jsonl,
    from_langgraph,
    from_openai_agents,
    load_transcripts,
    normalize,
    normalize_path,
    scan_sessions,
)

RULE = "AAK-AGENT-COMPOSE-002"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sessions"

OPENAI = FIXTURES / "openai-agents-trace.json"
LANGGRAPH = FIXTURES / "langgraph-checkpoint.json"
JSONL = FIXTURES / "raw-calls.jsonl"


def _rule_ids(target: Path) -> set[str]:
    return {f.rule_id for f in scan_sessions(target)}


# --- format detection -------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        (OPENAI, "openai-agents"),
        (LANGGRAPH, "langgraph"),
        (JSONL, "jsonl"),
    ],
)
def test_detects_each_format(fixture: Path, expected: str) -> None:
    assert detect_format(fixture) == expected
    assert expected in SUPPORTED_FORMATS


def test_every_fixture_format_is_covered() -> None:
    """Each non-canonical supported format has a fixture behind it."""
    found = {fmt for _p, fmt, _c in load_transcripts(FIXTURES)}
    assert found == {"openai-agents", "langgraph", "jsonl"}


# --- the splice fires, per format -------------------------------------------


def test_openai_agents_trace_splice_is_detected() -> None:
    """Four consecutive read_file spans reassembling to /home/dev/.ssh/id_rsa."""
    assert RULE in _rule_ids(OPENAI)


def test_langgraph_checkpoint_splice_is_detected() -> None:
    """Four consecutive web_fetch tool calls reassembling to a non-allowlisted host."""
    assert RULE in _rule_ids(LANGGRAPH)


def test_jsonl_splice_is_detected() -> None:
    """Three consecutive read_file lines reassembling to /srv/app/.env."""
    assert RULE in _rule_ids(JSONL)


def test_directory_ingest_finds_all_three() -> None:
    findings = scan_sessions(FIXTURES)
    assert len(findings) == 3
    assert {f.rule_id for f in findings} == {RULE}


# --- findings cite the real transcript, not the staging copy ----------------


def test_finding_paths_point_at_the_source_transcript() -> None:
    paths = {f.file_path for f in scan_sessions(FIXTURES)}
    assert paths == {
        "openai-agents-trace.json",
        "langgraph-checkpoint.json",
        "raw-calls.jsonl",
    }


def test_single_file_target_reports_its_own_path() -> None:
    finding = scan_sessions(JSONL)[0]
    assert finding.file_path.endswith("raw-calls.jsonl")
    assert "aak-sessions-" not in finding.file_path
    assert "aak-sessions-" not in finding.evidence


def test_related_locations_are_remapped_too() -> None:
    finding = scan_sessions(JSONL)[0]
    assert finding.related_locations
    for related in finding.related_locations:
        assert "aak-sessions-" not in related["file_path"]


# --- adapter unit behaviour -------------------------------------------------


def test_openai_orders_spans_by_started_at() -> None:
    """Order is the whole premise of the rule, so out-of-order spans must sort."""
    trace = {
        "spans": [
            {"started_at": "2026-08-13T09:00:03Z",
             "span_data": {"type": "function", "name": "read_file",
                           "input": '{"path": "rsa"}'}},
            {"started_at": "2026-08-13T09:00:01Z",
             "span_data": {"type": "function", "name": "read_file",
                           "input": '{"path": "/home/dev/.ssh/"}'}},
            {"started_at": "2026-08-13T09:00:02Z",
             "span_data": {"type": "function", "name": "read_file",
                           "input": '{"path": "id_"}'}},
        ]
    }
    calls = from_openai_agents(trace)
    assert calls is not None
    assert [c["arguments"]["path"] for c in calls] == ["/home/dev/.ssh/", "id_", "rsa"]


def test_openai_ignores_non_function_spans() -> None:
    trace = {
        "spans": [
            {"span_data": {"type": "agent", "name": "triage"}},
            {"span_data": {"type": "generation", "name": "llm"}},
            {"span_data": {"type": "function", "name": "read_file", "input": '{"path": "a"}'}},
        ]
    }
    calls = from_openai_agents(trace)
    assert calls == [{"tool": "read_file", "arguments": {"path": "a"}}]


def test_openai_non_json_input_is_preserved_as_arg() -> None:
    trace = {"spans": [{"span_data": {"type": "function", "name": "fetch", "input": "not-json"}}]}
    calls = from_openai_agents(trace)
    assert calls == [{"tool": "fetch", "arguments": {"arg": "not-json"}}]


def test_langgraph_reads_thread_state_values_shape() -> None:
    """GET /threads/{id}/state nests messages under `values`, not `channel_values`."""
    state = {
        "values": {
            "messages": [
                {"type": "ai", "tool_calls": [{"name": "read_file", "args": {"path": "x"}}]},
            ]
        }
    }
    assert from_langgraph(state) == [{"tool": "read_file", "arguments": {"path": "x"}}]


def test_langgraph_reads_legacy_openai_function_shape() -> None:
    state = {
        "channel_values": {
            "messages": [
                {"type": "ai", "additional_kwargs": {"tool_calls": [
                    {"function": {"name": "web_fetch", "arguments": '{"url": "https://a.example"}'}}
                ]}},
            ]
        }
    }
    assert from_langgraph(state) == [
        {"tool": "web_fetch", "arguments": {"url": "https://a.example"}}
    ]


def test_jsonl_skips_blank_and_unparseable_lines() -> None:
    text = (
        '{"tool": "read_file", "args": {"path": "a"}}\n'
        "\n"
        "not json at all\n"
        '{"tool": "read_file", "args": {"path": "b"}}\n'
    )
    assert from_jsonl(text) == [
        {"tool": "read_file", "arguments": {"path": "a"}},
        {"tool": "read_file", "arguments": {"path": "b"}},
    ]


def test_jsonl_preserves_file_order_when_ts_is_missing() -> None:
    text = (
        '{"tool": "t", "args": {"path": "1"}}\n'
        '{"tool": "t", "args": {"path": "2"}}\n'
        '{"tool": "t", "args": {"path": "3"}}\n'
    )
    calls = from_jsonl(text)
    assert calls is not None
    assert [c["arguments"]["path"] for c in calls] == ["1", "2", "3"]


def test_canonical_aak_shape_still_reads() -> None:
    """--sessions must also accept the hand-written shape the rule already knows."""
    raw = {"calls": [{"tool": "read_file", "arguments": {"path": "a"}}]}
    result = normalize(raw)
    assert result == ("aak", [{"tool": "read_file", "arguments": {"path": "a"}}])


# --- robustness -------------------------------------------------------------


def test_unrecognised_json_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "unrelated.json").write_text(json.dumps({"hello": "world"}))
    assert load_transcripts(tmp_path) == []
    assert scan_sessions(tmp_path) == []


def test_malformed_json_does_not_raise(tmp_path: Path) -> None:
    (tmp_path / "broken.json").write_text("{not json")
    assert load_transcripts(tmp_path) == []


def test_missing_target_is_empty(tmp_path: Path) -> None:
    assert load_transcripts(tmp_path / "nope") == []
    assert scan_sessions(tmp_path / "nope") == []


def test_normalize_path_on_unknown_suffix_returns_none(tmp_path: Path) -> None:
    other = tmp_path / "trace.txt"
    other.write_text('{"calls": [{"tool": "read_file", "arguments": {"path": "a"}}]}')
    assert normalize_path(other) is None


def test_clean_transcript_produces_no_finding(tmp_path: Path) -> None:
    """Consecutive calls that reassemble to nothing sensitive must stay quiet."""
    rows = [
        {"tool": "read_file", "args": {"path": "docs/"}},
        {"tool": "read_file", "args": {"path": "readme"}},
        {"tool": "read_file", "args": {"path": ".md"}},
    ]
    (tmp_path / "clean.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    assert scan_sessions(tmp_path) == []


# --- CLI wiring: `aak scan --sessions <path>` -------------------------------


def test_cli_sessions_flag_surfaces_the_splice(tmp_path: Path) -> None:
    """The flag must make the existing rule fire on real transcripts."""
    from click.testing import CliRunner

    from agent_audit_kit.cli import cli

    result = CliRunner().invoke(
        cli,
        ["scan", str(tmp_path), "--sessions", str(FIXTURES), "--format", "json"],
    )
    payload = json.loads(result.output)
    hits = [f for f in payload["findings"] if f["ruleId"] == RULE]
    assert len(hits) == 3
    assert {f["filePath"] for f in hits} == {
        "openai-agents-trace.json",
        "langgraph-checkpoint.json",
        "raw-calls.jsonl",
    }


def test_cli_without_sessions_flag_finds_nothing_in_an_empty_project(tmp_path: Path) -> None:
    """No --sessions means no session findings — the flag is what enables ingest."""
    from click.testing import CliRunner

    from agent_audit_kit.cli import cli

    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--format", "json"])
    payload = json.loads(result.output)
    assert [f for f in payload["findings"] if f["ruleId"] == RULE] == []


def test_cli_warns_when_no_transcript_is_readable(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from agent_audit_kit.cli import cli

    empty = tmp_path / "transcripts"
    empty.mkdir()
    (empty / "notes.json").write_text('{"unrelated": true}')

    result = CliRunner().invoke(
        cli, ["scan", str(tmp_path), "--sessions", str(empty), "--format", "json"]
    )
    assert "no readable session transcript" in result.output
