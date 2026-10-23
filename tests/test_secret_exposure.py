from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import secret_exposure
from agent_audit_kit.scanners._helpers import find_line_number
from agent_audit_kit.scanners.secret_exposure import (
    GITHUB_TOKEN,
    OPENAI_KEY,
    _secret_assignments,
    _shannon_entropy,
    scan,
)


def test_vulnerable_env_triggers_secret_rules(project_with_secrets: Path) -> None:
    findings, _ = scan(project_with_secrets)
    rule_ids = {f.rule_id for f in findings}

    assert "AAK-SECRET-001" in rule_ids, "Should detect Anthropic API key"
    assert "AAK-SECRET-002" in rule_ids, "Should detect OpenAI API key"
    assert "AAK-SECRET-003" in rule_ids, "Should detect AWS credentials"
    assert "AAK-SECRET-006" in rule_ids, "Should detect .env not in .gitignore"


def test_clean_project_no_secrets(tmp_path: Path) -> None:
    """A project with no secret files should produce zero findings."""
    (tmp_path / "README.md").write_text("# My Project\n")
    (tmp_path / ".gitignore").write_text(".env\n.env.*\n")
    findings, _ = scan(tmp_path)
    assert len(findings) == 0, f"Clean project should have no findings, got: {[f.rule_id for f in findings]}"


def test_env_in_gitignore_not_flagged(tmp_path: Path) -> None:
    """If .env is in .gitignore, AAK-SECRET-006 should not fire."""
    (tmp_path / ".env").write_text("SAFE_VAR=hello\n")
    (tmp_path / ".gitignore").write_text(".env\nnode_modules/\n")
    findings, _ = scan(tmp_path)
    env_findings = [f for f in findings if f.rule_id == "AAK-SECRET-006"]
    assert len(env_findings) == 0


def test_shannon_entropy_calculation() -> None:
    """Test the Shannon entropy implementation."""
    # Empty string
    assert _shannon_entropy("") == 0.0
    # Single repeated char (0 entropy)
    assert _shannon_entropy("aaaa") == 0.0
    # Binary string (1 bit)
    entropy = _shannon_entropy("ab")
    assert abs(entropy - 1.0) < 0.01
    # High entropy (random-looking)
    high_entropy = _shannon_entropy("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5jK7")
    assert high_entropy > 4.5, f"High entropy string should have entropy > 4.5, got {high_entropy}"


def test_generic_high_entropy_secret_detected(tmp_path: Path) -> None:
    """AAK-SECRET-004 should trigger on high-entropy values."""
    content = 'SECRET_KEY="aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5jK7"\n'
    (tmp_path / "config.json").write_text(content)
    findings, _ = scan(tmp_path)
    entropy_findings = [f for f in findings if f.rule_id == "AAK-SECRET-004"]
    assert len(entropy_findings) > 0, "High-entropy secret should be detected"


def test_private_key_file_detected(tmp_path: Path) -> None:
    """AAK-SECRET-005 should detect private key files."""
    (tmp_path / "server.key").write_text("-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----\n")
    findings, _ = scan(tmp_path)
    key_findings = [f for f in findings if f.rule_id == "AAK-SECRET-005"]
    assert len(key_findings) > 0, "Private key file should be detected"


def test_mcp_env_secret_in_settings(tmp_path: Path) -> None:
    """AAK-SECRET-007 should detect secrets in MCP env blocks outside .mcp.json."""
    config = {
        "mcpServers": {
            "test-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "API_KEY": "hardcoded-secret-value-1234567890"
                }
            }
        }
    }
    (tmp_path / "custom-mcp-config.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    mcp_secret_findings = [f for f in findings if f.rule_id == "AAK-SECRET-007"]
    assert len(mcp_secret_findings) > 0, "MCP env secrets should be detected"


def test_empty_dir(tmp_path: Path) -> None:
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# #951: the key formats the providers issue today
#
# AAK-SECRET-002 read only ``sk-`` followed by alphanumerics, so an OpenAI
# project, service-account or admin key, whose body carries ``-`` and ``_``,
# never matched. AAK-SECRET-008 read only ``ghp_``, so a fine-grained token
# (``github_pat_``) never matched either. Nothing was reported in ANY file type,
# not just in ``.env``, because the patterns run over every file the scanner
# reads; the tests below show the fix holds in each shape of file.
#
# Every token is assembled at run time, so no literal secret sits in the source,
# and every body is a repeated character, so none has entropy to flag.
# ---------------------------------------------------------------------------

_OPENAI_FAMILIES = ("proj", "svcacct", "admin")


def _openai_key(family: str, tag: str = "A") -> str:
    """A fake key of one OpenAI family: the prefix, then a URL-safe body that
    carries ``-`` and ``_`` and the ``T3BlbkFJ`` marker real keys contain."""
    return (
        "sk-" + family + "-" + tag * 12 + "_" + tag.lower() * 10 + "-"
        + "T3Blbk" + "FJ" + tag * 24
    )


def _github_fine_grained(tag: str = "A") -> str:
    """A fake fine-grained token: ``github_pat_``, 22 characters, ``_``, 59 more."""
    return "github_pat_" + tag * 22 + "_" + tag.lower() * 59


# (file name, content with ``{key}`` where the secret goes): one per way the scanner
# reaches a file, so the fix is shown wherever it reads and not only in ``.env``.
_SCANNED_FILES = [
    (".env", "SERVICE_KEY={key}\n"),
    (".mcp.json", '{"mcpServers": {"s": {"command": "npx", "env": {"SERVICE_KEY": "{key}"}}}}\n'),
    ("settings.json", '{"credential": "{key}"}\n'),
    ("agent.py", 'client = Client(credential="{key}")\n'),
    ("server.ts", 'const credential = "{key}";\n'),
    ("config.yml", "service:\n  credential: {key}\n"),
    ("config.toml", 'credential = "{key}"\n'),
    ("deploy.sh", "export SERVICE_CREDENTIAL={key}\n"),
    ("Dockerfile", "FROM python:3.12\nENV SERVICE_CREDENTIAL={key}\n"),
    ("main.tf", 'variable "credential" { default = "{key}" }\n'),
]
_SCANNED_IDS = [name for name, _ in _SCANNED_FILES]


def _hits(findings: list, rule_id: str) -> list:
    return [f for f in findings if f.rule_id == rule_id]


@pytest.mark.parametrize("family", _OPENAI_FAMILIES)
@pytest.mark.parametrize(("name", "template"), _SCANNED_FILES, ids=_SCANNED_IDS)
def test_openai_project_service_account_and_admin_keys_are_found_in_every_scanned_file(
    tmp_path: Path, family: str, name: str, template: str
) -> None:
    key = _openai_key(family)
    (tmp_path / name).write_text(template.replace("{key}", key), encoding="utf-8")

    findings, _ = scan(tmp_path)

    (hit,) = _hits(findings, "AAK-SECRET-002")
    assert hit.file_path == name
    assert hit.line_number is not None
    assert key not in hit.evidence  # a prefix only, as for every other secret


@pytest.mark.parametrize(("name", "template"), _SCANNED_FILES, ids=_SCANNED_IDS)
def test_github_fine_grained_tokens_are_found_in_every_scanned_file(
    tmp_path: Path, name: str, template: str
) -> None:
    token = _github_fine_grained()
    (tmp_path / name).write_text(template.replace("{key}", token), encoding="utf-8")

    findings, _ = scan(tmp_path)

    (hit,) = _hits(findings, "AAK-SECRET-008")
    assert hit.file_path == name
    assert hit.evidence.startswith("Found GitHub token: github_pat_")
    assert token not in hit.evidence


@pytest.mark.parametrize("family", _OPENAI_FAMILIES)
def test_the_openai_pattern_takes_the_whole_prefixed_key(family: str) -> None:
    key = _openai_key(family)
    assert OPENAI_KEY.search(f'api_key = "{key}"  # rotate').group() == key


def test_the_github_pattern_takes_the_whole_fine_grained_token() -> None:
    token = _github_fine_grained()
    assert GITHUB_TOKEN.search(f"token: {token}\n").group() == token


def test_the_legacy_openai_and_classic_github_formats_are_still_found(tmp_path: Path) -> None:
    legacy = "sk-" + "Q" * 24 + "1234"
    classic = "ghp_" + "T" * 36
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={legacy}\nGITHUB_TOKEN={classic}\n", encoding="utf-8")

    findings, _ = scan(tmp_path)

    assert len(_hits(findings, "AAK-SECRET-002")) == 1
    assert len(_hits(findings, "AAK-SECRET-008")) == 1


@pytest.mark.parametrize(
    "text",
    [
        "task-admin-dashboard-configuration-for-everyone",  # a word ending in "sk" is not a prefix
        "risk-proj-assessment-framework-version-two-draft",
        "disk-svcacct-mount-configuration-parameters-here",
        "sk-proj-" + "a" * 19,  # one character short of a key
        "sk-svcacct-" + "a" * 19,
        "sk-admin-" + "a" * 19,
        "sk-proj-<your-key-here>",  # a placeholder, not a key
        "sk-proj-",  # a bare prefix
        "sk-admin_" + "a" * 40,  # the family is followed by a hyphen, not an underscore
    ],
    ids=lambda text: text[:24],
)
def test_text_that_is_not_an_openai_key_is_not_reported(tmp_path: Path, text: str) -> None:
    (tmp_path / "notes.json").write_text(json.dumps({"note": text}), encoding="utf-8")

    findings, _ = scan(tmp_path)

    assert _hits(findings, "AAK-SECRET-002") == []


@pytest.mark.parametrize("family", _OPENAI_FAMILIES)
@pytest.mark.parametrize(("length", "reported"), [(19, 0), (20, 1)])
def test_a_prefixed_openai_key_body_needs_twenty_characters(
    tmp_path: Path, family: str, length: int, reported: int
) -> None:
    (tmp_path / "keys.json").write_text(json.dumps({"k": "sk-" + family + "-" + "a" * length}), encoding="utf-8")

    findings, _ = scan(tmp_path)

    assert len(_hits(findings, "AAK-SECRET-002")) == reported


@pytest.mark.parametrize("lead", ["sk-ant-api03-", "sk-ant-admin01-"])
def test_an_anthropic_key_is_not_reported_as_an_openai_key(tmp_path: Path, lead: str) -> None:
    (tmp_path / ".env").write_text("SERVICE_KEY=" + lead + "A" * 40 + "\n", encoding="utf-8")

    findings, _ = scan(tmp_path)

    assert len(_hits(findings, "AAK-SECRET-001")) == 1
    assert _hits(findings, "AAK-SECRET-002") == []


@pytest.mark.parametrize(
    "text",
    [
        "github_pat_" + "A" * 21 + "_" + "b" * 59,  # first part one short
        "github_pat_" + "A" * 22 + "_" + "b" * 58,  # second part one short
        "github_pat_" + "A" * 22 + "-" + "b" * 59,  # the separator is an underscore
        "github_pat_" + "A" * 82,  # one run, no separator
        "github_pat_YOUR_TOKEN_HERE",  # a placeholder, not a token
        "github_pat_",  # a bare prefix
    ],
    ids=lambda text: text[:30],
)
def test_text_that_is_not_a_fine_grained_token_is_not_reported(tmp_path: Path, text: str) -> None:
    (tmp_path / "notes.json").write_text(json.dumps({"note": text}), encoding="utf-8")

    findings, _ = scan(tmp_path)

    assert _hits(findings, "AAK-SECRET-008") == []


# ---------------------------------------------------------------------------
# #951, second half: a finding reports the line its own match sits on
#
# Every finding used to take the first line containing the first 8 to 12
# characters of its match. All Anthropic keys start ``sk-ant-api03``, so a file
# with several reported them on one line, and GitHub code scanning folds
# findings that share a rule and a line into one alert. ``agent_config`` moved
# to match offsets for the same reason in #792.
# ---------------------------------------------------------------------------


def test_each_key_of_one_family_reports_the_line_it_sits_on(tmp_path: Path) -> None:
    first = _openai_key("proj", "A")
    second = first[:-1] + "Z"  # shares the first 12 characters, all the old lookup read
    (tmp_path / "keys.cfg").write_text(f"# keys\nPRIMARY={first}\n\nFALLBACK={second}\n", encoding="utf-8")

    findings, _ = scan(tmp_path)

    assert sorted(f.line_number for f in _hits(findings, "AAK-SECRET-002")) == [2, 4]


def test_every_regex_rule_reports_the_line_of_its_own_match(tmp_path: Path) -> None:
    anthropic = "sk-ant-" + "api03-" + "A" * 40
    classic = "ghp_" + "T" * 36
    access = "AKIA" + "TESTONLY" * 2
    assignment = "aws_secret_access_key = " + "S" * 40
    lines = [
        "A1=" + anthropic,
        "A2=" + anthropic,
        "G1=" + classic,
        "G2=" + classic,
        "W1=" + access,
        "W2=" + access,
        assignment,
        assignment,
    ]
    (tmp_path / "keys.cfg").write_text("\n".join(lines) + "\n", encoding="utf-8")

    findings, _ = scan(tmp_path)

    def at(rule_id: str) -> list[int]:
        return sorted(f.line_number or 0 for f in _hits(findings, rule_id))

    assert at("AAK-SECRET-001") == [1, 2]
    assert at("AAK-SECRET-008") == [3, 4]
    assert at("AAK-SECRET-003") == [5, 6, 7, 8]


def test_two_keys_on_one_line_share_that_line(tmp_path: Path) -> None:
    first, second = _openai_key("svcacct", "A"), _openai_key("svcacct", "B")
    (tmp_path / "keys.cfg").write_text(f"x\nPAIR={first},{second}\n", encoding="utf-8")

    findings, _ = scan(tmp_path)

    assert [f.line_number for f in _hits(findings, "AAK-SECRET-002")] == [2, 2]


@pytest.mark.parametrize(
    "separator",
    ["\n", "\r\n", "\r", "\x0b", "\x0c", "\x1c", "\x85", chr(0x2028), chr(0x2029)],
    ids=["LF", "CRLF", "CR", "VT", "FF", "FS", "NEL", "LS", "PS"],
)
def test_a_line_number_counts_breaks_as_the_other_findings_do(tmp_path: Path, separator: str) -> None:
    """``AAK-SECRET-004`` and ``find_line_number`` split a file as ``str.splitlines``
    does, so a key must land on the same line whichever break precedes it."""
    key = _openai_key("proj")
    text = separator.join(["first", "second", "KEY=" + key, "fourth"]) + separator
    (tmp_path / "keys.cfg").write_bytes(text.encode("utf-8"))

    findings, _ = scan(tmp_path)

    (hit,) = _hits(findings, "AAK-SECRET-002")
    assert hit.line_number == 3
    assert find_line_number("\n".join(["first", "second", "KEY=" + key]), key[:12]) == 3


@pytest.mark.parametrize("unit", ["sk-proj-", "sk-svcacct-", "sk-admin-", "github_pat_", "ghp_", "xsk-proj-"])
def test_the_key_patterns_scan_a_crafted_file_in_linear_time(unit: str) -> None:
    """Each pattern is a literal and bounded or single trailing classes, so even a
    file of nothing but prefixes costs one pass. 600 KB is under the 1 MB limit
    above which the scanner skips a file."""
    blob = unit * (600_000 // len(unit))
    started = time.perf_counter()
    OPENAI_KEY.findall(blob)
    GITHUB_TOKEN.findall(blob)
    assert time.perf_counter() - started < 5.0


@pytest.mark.parametrize("unit", ["sk-proj-", "sk-svcacct-", "sk-admin-", "github_pat_", "ghp_"])
def test_scanning_a_crafted_file_of_prefixed_key_heads_is_linear(tmp_path: Path, unit: str) -> None:
    """Through the scanner. ``github_pat_`` and ``ghp_`` repeated make one unbroken run of
    word characters (the underscore is one), which used to reach the quadratic key=value
    patterns of ``AAK-SECRET-004`` and hold the scan for hours at this size."""
    (tmp_path / "blob.json").write_text(unit * (600_000 // len(unit)), encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 10.0


def test_many_keys_in_one_file_report_their_lines_in_one_pass(tmp_path: Path) -> None:
    token = "ghp_" + "T" * 36
    count = 15_000
    (tmp_path / "tokens.cfg").write_text("\n".join(f"T{i}={token}" for i in range(count)) + "\n", encoding="utf-8")
    started = time.perf_counter()

    findings, _ = scan(tmp_path)

    hits = _hits(findings, "AAK-SECRET-008")
    assert [f.line_number for f in hits] == list(range(1, count + 1))
    assert time.perf_counter() - started < 20.0


# ---------------------------------------------------------------------------
# AAK-SECRET-004 reads a line in linear time
#
# It was two ``re.findall`` patterns that opened ``\w*(?:SECRET|...)\w*``. Along a
# long run of word characters with no "=" after it, the leading ``\w*`` reached the
# end of the run from every start position and backed off looking for a keyword: a
# 10 KB line took 3.4 s, 20 KB 13.7 s, 40 KB 54 s, so the 200 KB lines below would
# have taken about 20 minutes each, and a file at the 1 MB limit hours. One crafted
# line could stall the scan of a repository.
#
# ``_secret_assignments`` is the rewrite: word runs cut once, each tested for a
# keyword, what follows read with classes that cannot backtrack. It must return what
# the two patterns returned, so the table below was produced by running the
# ORIGINAL patterns over each line, quirks included. The patterns themselves are not
# kept here: they are the quadratic part. The rewrite was also compared with them
# offline, with no difference, on 2.4 million random lines, on every line of the
# repository's tracked files and of the local crawl, and on mutated copies of each
# line that holds a keyword.
# ---------------------------------------------------------------------------

_KELVIN = chr(0x212A)  # case-folds to "k", so it spells KEY under re.IGNORECASE
_NBSP = chr(0xA0)  # \s, so it separates like a space

_ORIGINAL_PATTERNS_RETURNED = [
    (
        "an env assignment",
        "SESSION_SECRET=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5jK7",
        [("SESSION_SECRET", "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5jK7")],
    ),
    ("export", "export API_KEY=abcdefghijklmnop1234", [("API_KEY", "abcdefghijklmnop1234")]),
    ("spaces around the equals sign", "API_KEY = abcdefghijklmnop1234", [("API_KEY", "abcdefghijklmnop1234")]),
    (
        "a JSON object with two pairs",
        '{"api_key": "abcdefghijklmnop", "token": "qrstuvwxyz012345"}',
        [("api_key", "abcdefghijklmnop"), ("token", "qrstuvwxyz012345")],
    ),
    ("compact JSON", '{"password":"hunter2hunter2hunter2"}', [("password", "hunter2hunter2hunter2")]),
    (
        "single quotes, read both quoted and bare",
        "credential = 'abcdefghijklmnop1234'",
        [("credential", "abcdefghijklmnop1234"), ("credential", "'abcdefghijklmnop1234'")],
    ),
    ("mixed quotes", "\"KEY\": 'abcdefghijklmnop'", [("KEY", "abcdefghijklmnop")]),
    (
        "a Python call: the bare read runs to the next space",
        "client = Client(api_key=\"abcdefghijklmnop\", secret='qrstuvwxyz012345')",
        [
            ("api_key", "abcdefghijklmnop"),
            ("secret", "qrstuvwxyz012345"),
            ("api_key", '"abcdefghijklmnop",'),
            ("secret", "'qrstuvwxyz012345')"),
        ],
    ),
    (
        "a query string: the value runs to the next space",
        "https://example.test/cb?next=1&api_key=abcdefghijklmnop1234&x=2",
        [("api_key", "abcdefghijklmnop1234&x=2")],
    ),
    ("a name inside an earlier value", "FOO=KEY=abcdefghijklmnop1234", [("KEY", "abcdefghijklmnop1234")]),
    (
        "a keyword inside a quoted value",
        'X_TOKEN="see KEY=abcdefghijklmnop for details"',
        [("X_TOKEN", "see KEY=abcdefghijklmnop for details"), ("X_TOKEN", '"see'), ("KEY", "abcdefghijklmnop")],
    ),
    ("no value", "API_KEY=", []),
    ("no value, trailing space", "API_KEY= ", []),
    ("empty quotes", 'API_KEY=""', [("API_KEY", '""')]),
    ("an unterminated quote", 'API_KEY="abcdefghijklmnop', [("API_KEY", '"abcdefghijklmnop')]),
    ("a doubled equals sign", "API_KEY==abcdefghijklmnop", [("API_KEY", "=abcdefghijklmnop")]),
    ("YAML, unquoted: not read", "api_key: abcdefghijklmnop1234", []),
    ("YAML, quoted", 'api_key: "abcdefghijklmnop1234"', [("api_key", "abcdefghijklmnop1234")]),
    (
        "TOML",
        'secret_key = "abcdefghijklmnop1234"',
        [("secret_key", "abcdefghijklmnop1234"), ("secret_key", '"abcdefghijklmnop1234"')],
    ),
    (
        "mixed case names",
        "Api_Key=abcdefghijklmnop1234 PassWord=qrstuvwxyz0123456",
        [("Api_Key", "abcdefghijklmnop1234"), ("PassWord", "qrstuvwxyz0123456")],
    ),
    ("a keyword inside a longer name", "MY_SECRETS_FILE=/etc/app/secrets.json", [("MY_SECRETS_FILE", "/etc/app/secrets.json")]),
    (
        "a name with three keywords",
        'KEY_TOKEN_SECRET="abcdefghijklmnop"',
        [("KEY_TOKEN_SECRET", "abcdefghijklmnop"), ("KEY_TOKEN_SECRET", '"abcdefghijklmnop"')],
    ),
    ("tabs around the equals sign", "PASSWORD\t=\tabcdefghijklmnop1234", [("PASSWORD", "abcdefghijklmnop1234")]),
    (
        "no-break spaces around the equals sign",
        "PASSWORD" + _NBSP + "=" + _NBSP + "abcdefghijklmnop1234",
        [("PASSWORD", "abcdefghijklmnop1234")],
    ),
    ("no keyword at all", "PORT=8080 HOST=localhost", []),
    ("a keyword and no assignment", "the api key is abcdefghijklmnop1234", []),
    ("a quoted name and a quoted value", "'TOKEN'='abcdefghijklmnop1234'", [("TOKEN", "abcdefghijklmnop1234")]),
    ("spaces around a colon", '"token" : "abcdefghijklmnop"', [("token", "abcdefghijklmnop")]),
    (
        "a Kelvin sign spelling the keyword",
        _KELVIN + "EY=abcdefghijklmnop1234",
        [(_KELVIN + "EY", "abcdefghijklmnop1234")],
    ),
    ("a non-ASCII letter in the name", "clé_token=abcdefghijklmnop", [("clé_token", "abcdefghijklmnop")]),
    (
        "two bare pairs",
        "TOKEN=aaaaaaaaaaaaaaaaaaaa KEY=bbbbbbbbbbbbbbbbbbbb",
        [("TOKEN", "aaaaaaaaaaaaaaaaaaaa"), ("KEY", "bbbbbbbbbbbbbbbbbbbb")],
    ),
    ("text after a closing quote", 'TOKEN="abc"def', [("TOKEN", "abc"), ("TOKEN", '"abc"def')]),
    (
        "nested JSON",
        '{"auth": {"token": "abcdefghijklmnop", "secret": "qrstuvwxyz"}}',
        [("token", "abcdefghijklmnop"), ("secret", "qrstuvwxyz")],
    ),
    ("a variable reference", "TOKEN=$TOKEN_VALUE_FROM_ENV", [("TOKEN", "$TOKEN_VALUE_FROM_ENV")]),
    ("equals signs inside the value", "API_KEY=abc=def==", [("API_KEY", "abc=def==")]),
    ("a bare keyword", "KEY", []),
    (
        "a closing quote that opens the next name",
        'KEY="abcdefghijklmnop"SECRET="qrstuvwxyz012345"',
        [
            ("KEY", "abcdefghijklmnop"),
            ("SECRET", "qrstuvwxyz012345"),
            ("KEY", '"abcdefghijklmnop"SECRET="qrstuvwxyz012345"'),
        ],
    ),
    ("a quote between name and separator", 'KEY"="abcdefghijklmnop"', [("KEY", "abcdefghijklmnop")]),
    ("colon then equals", 'KEY:="abcdefghijklmnop"', []),
]


@pytest.mark.parametrize(
    ("line", "pairs"),
    [(line, pairs) for _label, line, pairs in _ORIGINAL_PATTERNS_RETURNED],
    ids=[label for label, _line, _pairs in _ORIGINAL_PATTERNS_RETURNED],
)
def test_the_linear_reader_returns_what_the_original_patterns_returned(
    line: str, pairs: list[tuple[str, str]]
) -> None:
    assert _secret_assignments(line) == pairs


_HIGH_ENTROPY = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5jK7"

# 200 KB lines. Most are, or contain, one long run of word characters, the shape the
# original patterns could not take. The rest are shapes a rewrite could get wrong: a
# gap before and after the equals sign, many names each followed by a value, quotes
# that never close, a value as long as the line.
_CRAFTED_LINES = [
    ("word characters", "a" * 200_000),
    ("word characters then a keyword", "a" * 200_000 + "KEY"),
    ("keywords back to back", "KEY" * 70_000),
    ("a name then a long gap", "KEY" + " " * 200_000),
    ("a gap before and after the equals sign", "KEY" + " " * 100_000 + "=" + " " * 100_000 + "x" * 20),
    ("names each followed by a value", "KEY=v " * 33_000),
    ("names each followed by an opening quote", 'KEY="' * 40_000),
    ("one value as long as the line", "KEY=" + "x" * 200_000),
    ("a quoted value that never closes", 'KEY="' + "x" * 200_000),
    ("non-ASCII word characters", "é" * 200_000),
    ("an underscore run", "github_pat_" * 18_000),
]
_CRAFTED_IDS = [label for label, _line in _CRAFTED_LINES]


@pytest.mark.parametrize("line", [line for _label, line in _CRAFTED_LINES], ids=_CRAFTED_IDS)
def test_the_linear_reader_takes_a_200_kb_line_in_linear_time(line: str) -> None:
    """About 20 minutes per case with the original patterns, tens of milliseconds now.
    The bound is far above that so a slow runner cannot trip it."""
    started = time.perf_counter()
    _secret_assignments(line)
    assert time.perf_counter() - started < 10.0


@pytest.mark.parametrize("line", [line for _label, line in _CRAFTED_LINES], ids=_CRAFTED_IDS)
def test_scanning_a_200_kb_line_is_linear(tmp_path: Path, line: str) -> None:
    (tmp_path / "blob.json").write_text(line, encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 10.0


def test_a_secret_at_the_end_of_a_200_kb_line_is_still_found(tmp_path: Path) -> None:
    line = "a" * 200_000 + " SESSION_SECRET=" + _HIGH_ENTROPY
    (tmp_path / "app.cfg").write_text(line + "\n", encoding="utf-8")
    started = time.perf_counter()

    findings, _ = scan(tmp_path)

    (hit,) = _hits(findings, "AAK-SECRET-004")
    assert hit.line_number == 1
    assert hit.evidence.startswith("SESSION_SECRET = (high entropy value")
    assert time.perf_counter() - started < 10.0


# ---------------------------------------------------------------------------
# AAK-SECRET-007 reads VS Code's `servers` map too
# ---------------------------------------------------------------------------
#
# `.vscode/mcp.json` keeps its servers under `servers`. Reading `mcpServers` alone
# passed every literal there; the reader now goes through `iter_mcp_servers`.

_VSCODE_SERVERS = Path(__file__).parent / "fixtures" / "vscode_servers" / "secret-007"


def _secret_007(root: Path) -> list[tuple[str, int | None]]:
    return [(f.file_path, f.line_number) for f in scan(root)[0] if f.rule_id == "AAK-SECRET-007"]


def test_secret_007_reads_a_vscode_servers_map() -> None:
    assert _secret_007(_VSCODE_SERVERS / "detecting") == [(".vscode/mcp.json", 8)]


def test_secret_007_stays_quiet_on_vscode_input_and_env_references() -> None:
    """`${input:...}` is VS Code's prompt for a secret, `${env:...}` its environment
    reference; neither is a literal."""
    assert _secret_007(_VSCODE_SERVERS / "clean") == []


def test_secret_007_reads_both_maps_and_skips_a_config_that_is_a_list(tmp_path: Path) -> None:
    config = {
        "mcpServers": {"a": {"command": "node", "env": {"API_KEY": "literal-one"}}},
        "servers": {"b": {"command": "node", "env": {"API_KEY": "literal-two"}}},
    }
    (tmp_path / "mcp.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    evidence = [f.evidence for f in scan(tmp_path)[0] if f.rule_id == "AAK-SECRET-007"]
    assert evidence == [
        "Server 'a' env.API_KEY = (hardcoded value)",
        "Server 'b' env.API_KEY = (hardcoded value)",
    ]
    (tmp_path / "mcp.json").write_text('[{"servers": {}}]', encoding="utf-8")
    assert _secret_007(tmp_path) == []


# ---------------------------------------------------------------------------
# The secret rules read the JavaScript and TypeScript module and JSX extensions
#
# `SCANNABLE_EXTENSIONS` had `.js` and `.ts` and none of `.mjs`, `.cjs`, `.tsx` or
# `.jsx`, so a token in `src/config.mjs` or `app/page.tsx` reported nothing while the
# same line in `config.js` fired AAK-SECRET-008.
# ---------------------------------------------------------------------------


def _varied(length: int) -> str:
    """A body no placeholder test matches: varied, with no repeated run and no word."""
    return ("Zq7Wm2Rt5Yp8Kd3N" * length)[:length]


@pytest.mark.parametrize("name", ["src/config.mjs", "src/config.cjs", "app/page.tsx", "src/widget.jsx"])
def test_the_secret_rules_read_javascript_module_and_jsx_files(tmp_path: Path, name: str) -> None:
    token = "gh" + "p_" + _varied(36)
    path = tmp_path / name
    path.parent.mkdir(parents=True)
    path.write_text(f'// config\nexport const GITHUB_TOKEN = "{token}";\n', encoding="utf-8")

    findings, scanned = scan(tmp_path)

    (hit,) = _hits(findings, "AAK-SECRET-008")
    assert (hit.file_path, hit.line_number) == (name, 2)
    assert name in scanned
    assert token not in hit.evidence


# ---------------------------------------------------------------------------
# The prefix rules read Markdown, behind a stand-in filter
#
# A README shows a provider's key format with a stand-in: `ghp_` and 36 `x`,
# `sk-proj-REPLACE_ME_...`, AWS's own example key. AAK-SECRET-001, -002, -003 and
# -008 read `.md` and skip a value that is one repeated character after its
# prefix, holds REPLACE, YOUR, EXAMPLE, PLACEHOLDER, CHANGEME or a run of `x`, or
# is the documented AWS example. On 1,909 README and docs files from 1,883 public
# MCP repositories they found nothing. AAK-SECRET-004 stays off Markdown: it
# found 16 values there, at most 56% of them shaped like a credential.
# ---------------------------------------------------------------------------

_MD_KEYS = [
    ("AAK-SECRET-001", "sk-" + "ant-" + "api03-" + _varied(40)),
    ("AAK-SECRET-002", "sk-" + "proj-" + _varied(40)),
    ("AAK-SECRET-002", "sk-" + _varied(40)),
    ("AAK-SECRET-003", "AK" + "IA" + "Q7ZWM2RT5YP8KD3N"),
    ("AAK-SECRET-003", "aws_secret_access_key = " + _varied(40)),
    ("AAK-SECRET-008", "gh" + "p_" + _varied(36)),
    ("AAK-SECRET-008", "github" + "_pat_" + _varied(22) + "_" + _varied(59)),
    ("AAK-SECRET-008", "gl" + "pat-" + _varied(24)),
]


@pytest.mark.parametrize(("rule_id", "key"), _MD_KEYS, ids=[f"{r}-{k[:7]}" for r, k in _MD_KEYS])
def test_the_prefix_rules_read_a_key_pasted_into_markdown(tmp_path: Path, rule_id: str, key: str) -> None:
    (tmp_path / "README.md").write_text(f"## Setup\n\n```sh\nexport SERVICE={key}\n```\n", encoding="utf-8")

    findings, scanned = scan(tmp_path)

    (hit,) = _hits(findings, rule_id)
    assert hit.line_number == 4
    assert key not in hit.evidence
    assert "README.md" in scanned


_MD_STAND_INS = [
    # One repeated character after the prefix, in any case and across `-` and `_`.
    "gh" + "p_" + "x" * 36,
    "gh" + "p_" + "A" * 36,
    "github" + "_pat_" + "A" * 22 + "_" + "a" * 59,
    "sk-" + "proj-" + "a" * 40,
    "sk-" + "ant-" + "api03-" + "A" * 40,
    "sk-" + "Q" * 40,
    "gl" + "pat-" + "Z" * 24,
    "AK" + "IA" + "A" * 16,
    # A placeholder word, in any case.
    "sk-" + "proj-" + "REPLACE_ME_" + _varied(30),
    "sk-" + "ant-" + "api03-" + "your-key-" + _varied(30),
    "gh" + "p_" + "EXAMPLE" + _varied(29),
    "sk-" + "PLACEHOLDER" + _varied(20),
    "gl" + "pat-" + "ChangeMe" + _varied(14),
    # A run of x.
    "sk-" + "proj-" + _varied(12) + "xxxx" + _varied(12),
    "gh" + "p_" + _varied(16) + "XXXX" + _varied(16),
    "AK" + "IA" + "XXXX" + "Q7ZWM2RT5YP8",
    # The example key the AWS IAM User Guide documents ("Manage access keys for IAM users").
    "AK" + "IA" + "IOSFODNN7" + "EXAMPLE",
    "aws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
]


@pytest.mark.parametrize("stand_in", _MD_STAND_INS, ids=lambda v: v[:14])
def test_a_stand_in_key_in_markdown_is_not_reported(tmp_path: Path, stand_in: str) -> None:
    (tmp_path / "README.md").write_text(f"## Setup\n\n```sh\nexport SERVICE={stand_in}\n```\n", encoding="utf-8")

    assert scan(tmp_path)[0] == []


@pytest.mark.parametrize("stand_in", [_MD_STAND_INS[0], _MD_STAND_INS[8], _MD_STAND_INS[16]], ids=lambda v: v[:14])
def test_the_stand_in_filter_is_for_markdown_only(tmp_path: Path, stand_in: str) -> None:
    """In an env file, a config or a script a stand-in is still reported: it is where
    the real key will be pasted."""
    (tmp_path / "deploy.sh").write_text(f"export SERVICE={stand_in}\n", encoding="utf-8")

    assert [f.rule_id for f in scan(tmp_path)[0]] != []


def test_the_scanner_source_holds_the_documented_example_without_reporting_it(tmp_path: Path) -> None:
    """CI's self-scan reads secret_exposure.py, where the stand-in filter does not apply,
    so a whole IAM User Guide access key ID in it was a CRITICAL AAK-SECRET-003 finding
    that failed the self-scan. It is written as two adjacent literals; the set must still
    hold the whole value."""
    shutil.copy(secret_exposure.__file__, tmp_path / "secret_exposure.py")

    critical = [f.rule_id for f in run_scan(project_root=tmp_path).findings if f.severity == Severity.CRITICAL]

    assert critical == []
    assert secret_exposure._DOCUMENTED_EXAMPLES == {
        "AK" + "IA" + "IOSFODNN7" + "EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
    }


def test_secret_004_does_not_read_markdown(tmp_path: Path) -> None:
    text = "## Config\n\n```\nSESSION_SECRET=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7b\n```\n"
    (tmp_path / "README.md").write_text(text, encoding="utf-8")
    (tmp_path / "app.cfg").write_text(text, encoding="utf-8")

    assert [f.file_path for f in scan(tmp_path)[0] if f.rule_id == "AAK-SECRET-004"] == ["app.cfg"]


# ---------------------------------------------------------------------------
# AAK-SECRET-009 and -007 read a `.JSON` suffix as `.json`
#
# The walker lowercased the suffix before it chose a file, the two rules compared it
# exactly, so `KEY.JSON` was read and not reported.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["key.json", "KEY.JSON", "key.Json"])
def test_a_service_account_key_is_reported_whatever_the_case_of_its_suffix(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text(
        '{"type": "service_account", "project_id": "demo-proj",\n "client_email": "svc@demo-proj.iam.gserviceaccount.com"}\n',
        encoding="utf-8",
    )

    findings, _ = scan(tmp_path)

    assert [f.file_path for f in _hits(findings, "AAK-SECRET-009")] == [name]


def test_secret_007_reads_a_config_whose_suffix_is_upper_case(tmp_path: Path) -> None:
    config = {"mcpServers": {"x": {"command": "node", "args": ["a.js"], "env": {"API_TOKEN": "literal-value"}}}}
    (tmp_path / "config.JSON").write_text(json.dumps(config, indent=2), encoding="utf-8")

    assert _secret_007(tmp_path) == [("config.JSON", 9)]


# ---------------------------------------------------------------------------
# AAK-SECRET-004 does not read an unquoted YAML value, on a measurement
#
# Read as a third shape, `NAME: value` found 13 values in 1,527 YAML files with
# secret-named keys from 927 public MCP repositories, and 3 were credentials: most of
# the rest were SOPS-encrypted values and lockfile entries. The stated limit pins it.
# ---------------------------------------------------------------------------

_RANDOM_VALUE = "Zk8Q2mPx7LwR4vN9bT1yU6hJ3dAeF5gC"  # 32 distinct characters, entropy 5.0


def test_secret_004_reads_a_quoted_yaml_value_and_states_why_not_an_unquoted_one(tmp_path: Path) -> None:
    compose = "services:\n  app:\n    environment:\n      SECRET_KEY: {v}\n"
    (tmp_path / "quoted").mkdir()
    (tmp_path / "unquoted").mkdir()
    (tmp_path / "quoted" / "docker-compose.yml").write_text(compose.format(v=f'"{_RANDOM_VALUE}"'), encoding="utf-8")
    (tmp_path / "unquoted" / "docker-compose.yml").write_text(compose.format(v=_RANDOM_VALUE), encoding="utf-8")

    assert [f.file_path for f in _hits(scan(tmp_path)[0], "AAK-SECRET-004")] == ["quoted/docker-compose.yml"]
    assert "unquoted YAML" in RULES["AAK-SECRET-004"].limitations


# ---------------------------------------------------------------------------
# AAK-SECRET-006 skips the env templates a project is meant to commit
#
# `.env.example` (and `.env.sample`, `.env.template`, `.env.dist`) lists the
# variables with no values, so reporting it asked users to stop committing the one
# env file that belongs in the repository. The `.gitignore` test was a substring
# test as well: a file whose only mention was `!.env.example` counted as ignoring
# `.env`. It now reads each pattern as git does, the last one that matches deciding.
# ---------------------------------------------------------------------------


def _secret_006(root: Path) -> list[str]:
    return sorted(f.file_path for f in scan(root)[0] if f.rule_id == "AAK-SECRET-006")


@pytest.mark.parametrize("name", [".env.example", ".env.sample", ".env.template", ".env.dist", ".env.local.example"])
@pytest.mark.parametrize("gitignore", [None, "node_modules/\n"])
def test_secret_006_does_not_report_an_env_template(tmp_path: Path, name: str, gitignore: str | None) -> None:
    (tmp_path / name).write_text("DATABASE_URL=postgres://localhost/app\nAPI_TOKEN=\n", encoding="utf-8")
    if gitignore is not None:
        (tmp_path / ".gitignore").write_text(gitignore, encoding="utf-8")

    assert _secret_006(tmp_path) == []


# Each case's expected answer is git's own (`git check-ignore --no-index`), computed in
# the test, so nothing here restates gitignore(5) by hand. The `  .env*  ` case pinned
# the wrong answer before: git keeps leading whitespace, so it ignores nothing.
_GITIGNORE_CASES = [
    b"node_modules/\n", b"!.env.example\n", b"# .env\n", b".envrc\n", b".env/\n", b"config/.env\n",
    b".env\n", b".env\n!.env\n", b".env*\n", b".env.*\n.env\n", b"*.env\n.env.local\n",
    b"/.env\n/.env.local\n", b"**/.env*\n", b"  .env*  \n", b"  .env\n", b"\t.env\n", b".env\t\n",
    b".env  \n", b".env\\ \n", b"\xef\xbb\xbf.env\n", b".env\r\n", b"/**/.env\n", b"**/**/.env\n", b"/**\n",
    b".env # secrets\n", b"\\#.env\n", b"\\.env\n", b"\\!.env\n", b".env\n  !.env\n", b"[.]env\n",
    b"[!a]env\n", b"[^a]env\n", b"*\n", b"**\n", b".e?v\n", b".env.l[a-z]cal\n", b".env[\n",
    # The verification's shapes (gitignore_vs_git2.py), bracket classes first.
    b".env.[]l]*\n", b".env.[!]]*\n", b".env.[[:alpha:]]*\n", b".env.[[:digit:]]*\n", b".env.[!p]*\n",
    b".env.[^p]*\n", b".env.[a-l]*\n", b".env.[\n", b"***\n", b"**/\n", b"**/*\n", b"/*\n", b"*.env\n", b".env.?*\n",
    b".ENV\n", b".env/**\n", b"**/.env/**\n", b"a/../.env\n", b"./.env\n", b".env\\\n", b"*\n!.env\n",
    b".env\n!*\n", b".env\n/.env\n!/.env\n", b".env\r.env.local\r", b"\xff\xfe.\x00e\x00n\x00v\x00\n\x00",
    b".e**v\n", b"?env\n", b".env.loc?l\n", b".env.*\n!.env.*\n", b"!.env.local\n.env*\n",
    b".env*\n!.env.local\n", b"\\.env*\n", b".env\\*\n", b"**/.env*/\n", b"/**/.env.*\n", b"*/.env\n",
    b"**/**\n", b".env.\\l*\n", b"!\n.env\n", b"\n\n   \n.env\n", b"\t\n.env.*\n",
    b".env.*\n!.env.p*\n.env.production\n", b".env#\n", b".env #\n", b"\xef\xbb\xbf!.env\n.env\n",
    # More bracket edges: an unknown POSIX class, `[:` with no `:]`, reversed and open
    # ranges, `]` and `-` placed literally, escapes inside a class, an unclosed class.
    b".env.[[:bogus:]]*\n", b".env.[[:alpha]*\n", b".env.[z-a]*\n", b".env.[a-]*\n", b".env.[]-z]*\n",
    b".env.[\\]l]*\n", b".env.[l\\-n]*\n", b".env.[[:alpha:]\n", b".env.[[:lower:][:digit:]]*\n",
    b".env.[!a-z]*\n", b".env.[*]*\n", b".env.[?]ocal\n", b".env.l[[]cal\n",
    # A `/` inside a class: git still reads the pattern against a root name, where the
    # class can never meet a `/`. Outside a class, it puts the pattern below the root.
    b".env[!/]*\n", b".env.[/l]*\n", b".env[/]\n", b"**/.env[!/]*\n", b".env.[!/]ocal\n",
    b"/.env[!/]*\n", b".env[!/]*/\n", b".env\\/x\n", b".env.[a/]*/x\n",
]


def _git_ignores(root: Path, name: str) -> bool:
    home = root.parent / "git-home"
    home.mkdir(exist_ok=True)
    env = {**os.environ, "HOME": str(home), "XDG_CONFIG_HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"}
    result = subprocess.run(
        ["git", "-C", str(root), "-c", "core.excludesFile=", "-c", "core.ignorecase=false",
         "check-ignore", "-q", "--no-index", name],
        env=env, capture_output=True,
    )
    assert result.returncode in (0, 1), result.stderr
    return result.returncode == 0


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git to say what git ignores")
@pytest.mark.parametrize("gitignore", _GITIGNORE_CASES, ids=repr)
def test_secret_006_reads_gitignore_patterns_as_git_does(tmp_path: Path, gitignore: bytes) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    names = (".env", ".env.local", ".env.production")
    for name in names:
        (root / name).write_text("DATABASE_URL=postgres://localhost/app\n", encoding="utf-8")
    (root / ".env.example").write_text("DATABASE_URL=\n", encoding="utf-8")
    (root / ".gitignore").write_bytes(gitignore)

    expected = sorted(name for name in names if not _git_ignores(root, name))

    assert _secret_006(root) == expected


@pytest.mark.parametrize(
    "gitignore, reported",
    [
        (None, [".env", ".env.local"]),
        ("!.env.example\n", [".env", ".env.local"]),
        (".env\n", [".env.local"]),
        (".env*\n", []),
        ("  .env*  \n", [".env", ".env.local"]),  # leading whitespace is part of the pattern
    ],
)
def test_secret_006_reads_the_common_gitignore_shapes(
    tmp_path: Path, gitignore: str | None, reported: list[str]
) -> None:
    """The same reading without git on the machine, for the shapes most projects use."""
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://localhost/app\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("DATABASE_URL=postgres://localhost/dev\n", encoding="utf-8")
    if gitignore is not None:
        (tmp_path / ".gitignore").write_text(gitignore, encoding="utf-8")

    assert _secret_006(tmp_path) == reported


@pytest.mark.parametrize("stars", [6, 8, 12, 40])
def test_a_star_heavy_gitignore_glob_matches_in_linear_time(tmp_path: Path, stars: int) -> None:
    """Translated to a regex, `*a*a*a*a*a*a*a*b` against `.env.` and 60 `a` took 3.9 s, and one
    more `a*` over 300 s: each `*` was a `.*` that fullmatch backtracked through. Globs are
    now matched segment by segment, each star-free segment at its leftmost place."""
    name = ".env." + "a" * 60
    (tmp_path / name).write_text("A=1\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("*" + "a*" * stars + "b\n", encoding="utf-8")
    started = time.perf_counter()
    assert _secret_006(tmp_path) == [name]
    assert time.perf_counter() - started < 2.0


def test_a_gitignore_full_of_star_heavy_globs_reads_in_linear_time(tmp_path: Path) -> None:
    name = ".env." + "a" * 200
    (tmp_path / name).write_text("A=1\n", encoding="utf-8")
    lines = "".join("*" + "a*" * (k % 90 + 2) + "b\n" for k in range(6_000))
    (tmp_path / ".gitignore").write_text(lines, encoding="utf-8")
    started = time.perf_counter()
    assert _secret_006(tmp_path) == [name]
    assert time.perf_counter() - started < 5.0


def test_a_gitignore_of_many_patterns_reads_in_linear_time(tmp_path: Path) -> None:
    """100,000 patterns and four env files took 13.7 s: each pattern was translated again
    for each file. Patterns are now compiled once, and only those that can match a name
    starting with `.`."""
    for name in (".env", ".env.local", ".env.prod", ".env.test"):
        (tmp_path / name).write_text("A=1\n", encoding="utf-8")
    lines = "".join(f"p{i}*\n" for i in range(100_000)) + "".join(f"*q{i}\n" for i in range(20_000))
    (tmp_path / ".gitignore").write_text(lines, encoding="utf-8")
    started = time.perf_counter()
    assert _secret_006(tmp_path) == [".env", ".env.local", ".env.prod", ".env.test"]
    assert time.perf_counter() - started < 5.0


def _seconds(run: Callable[[], object]) -> float:
    """Best of three, so one descheduled run cannot fail a timing test."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


# shape -> (one `.gitignore` line for n units, n at the smaller size, whether `.env` is
# reported). At the larger size each line is still under the 1,000,000-byte read.
_CRAFTED_GITIGNORE_LINES: dict[str, tuple[Callable[[int], str], int, bool]] = {
    # Each trailing space sliced the line twice to count the backslashes before it:
    # 999,990 of them took 45 s.
    "trailing-spaces": (lambda n: ".env" + " " * n, 99_999, False),
    "escaped-space-then-spaces": (lambda n: ".env\\" + " " * n, 99_999, True),
    # Each `[:` inside a class looked for the class's `]` again: 499,990 took 7.7 s.
    "posix-class-openers": (lambda n: ".env.[" + "[:" * n + "a]", 49_999, True),
    # Each leading `**/` copied the rest of the line: 333,320 took 5.2 s.
    "leading-double-stars": (lambda n: "**/" * n + ".env", 33_332, False),
}


@pytest.mark.parametrize("shape", sorted(_CRAFTED_GITIGNORE_LINES))
def test_a_crafted_gitignore_line_reads_in_linear_time(tmp_path: Path, shape: str) -> None:
    """One crafted line at two sizes 10 times apart, best of three. The larger may take 40
    times the smaller's time plus a fixed slack, under an absolute bound that is loose for
    slow CI runners; the quadratic reads needed 100 times or more."""
    line, n, reported = _CRAFTED_GITIGNORE_LINES[shape]
    times = []
    for size in (n, 10 * n):
        root = tmp_path / str(size)
        root.mkdir()
        (root / ".env").write_text("A=1\n", encoding="utf-8")
        (root / ".gitignore").write_text(line(size) + "\n", encoding="utf-8")
        assert _secret_006(root) == ([".env"] if reported else [])
        times.append(_seconds(lambda: _secret_006(root)))
    t_small, t_large = times
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


@pytest.mark.parametrize(
    "head, last, kept, reported",
    [
        # Cut to `.env`, `.env.local` read as a pattern that ignores `.env`.
        ("", ".env.local", 4, [".env"]),
        # Cut to `!.env`, `!.env.example` after `.env*` took `.env` back.
        (".env*\n", "!.env.example", 5, []),
    ],
)
def test_secret_006_drops_the_gitignore_line_its_read_cuts_in_two(
    tmp_path: Path, head: str, last: str, kept: int, reported: list[str]
) -> None:
    """The read stops at 1,000,000 bytes. A line it ends inside is dropped, not read as
    its head, which is another pattern; git reads the whole line."""
    text = head + "#" * (1_000_000 - len(head) - 1 - kept) + "\n" + last + "\n"
    assert text[1_000_000 - kept : 1_000_000] == last[:kept]
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(text, encoding="utf-8")

    assert _secret_006(tmp_path) == reported


_NON_ASCII_NAMES = (".env.\u00e9", ".env.\u00e9t\u00e9", ".env.\u4e2d", ".env.\U0001f600")


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git to say what git ignores")
@pytest.mark.parametrize(
    "pattern",
    [".env.?", ".env.??", ".env.???", ".env.????", ".env.[!a]", ".env.[!a][!a]", ".env.?t?", ".env.*",
     ".env.[[:alpha:]]", ".env.\u00e9", ".env.?*", ".env.[\u00e9]", ".env.[!\u00e9]?"],
)
def test_secret_006_matches_a_non_ascii_name_byte_by_byte_as_git_does(tmp_path: Path, pattern: str) -> None:
    """git's `?` and classes match one byte. Matched on code points, `.env.?` ignored
    `.env.\u00e9`, two bytes in UTF-8, so the file went unreported where git commits it."""
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    for name in _NON_ASCII_NAMES:
        (root / name).write_text("A=1\n", encoding="utf-8")
    (root / ".gitignore").write_text(pattern + "\n", encoding="utf-8")

    expected = sorted(name for name in _NON_ASCII_NAMES if not _git_ignores(root, name))

    assert _secret_006(root) == expected


_SPACE_NAMES = (".env.\t", ".env.\x0b", ".env.\x0c", ".env. ", ".env.x")


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git to say what git ignores")
@pytest.mark.parametrize("pattern", [".env.[[:space:]]", ".env.[![:space:]]", ".env.[[:space:][:alpha:]]"])
def test_secret_006_reads_space_as_gits_four_characters(tmp_path: Path, pattern: str) -> None:
    """git's `[:space:]` is space, tab, newline and carriage return; Python's adds the
    vertical tab and form feed."""
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    for name in _SPACE_NAMES:
        (root / name).write_text("A=1\n", encoding="utf-8")
    (root / ".gitignore").write_text(pattern + "\n", encoding="utf-8")

    expected = sorted(name for name in _SPACE_NAMES if not _git_ignores(root, name))

    assert _secret_006(root) == expected


def test_secret_006_matches_case_sensitively_and_says_so(tmp_path: Path) -> None:
    """As git does by default on Linux. With core.ignorecase, the macOS and Windows
    default, git would also ignore `.env` here; the limitation says so."""
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".ENV\n", encoding="utf-8")

    assert _secret_006(tmp_path) == [".env"]
    assert "core.ignorecase" in RULES["AAK-SECRET-006"].limitations


def test_secret_006_reads_the_project_root_only(tmp_path: Path) -> None:
    """The stated limitation, proven here rather than by a fixture pair under
    tests/fixtures/limitations: the pair would be two committed env files, the thing
    this rule exists to stop, so it is built at run time."""
    (tmp_path / ".env.test").write_text("APP_ENV=test\n", encoding="utf-8")
    (tmp_path / "services" / "api").mkdir(parents=True)
    (tmp_path / "services" / "api" / ".env.test").write_text("APP_ENV=test\n", encoding="utf-8")

    assert _secret_006(tmp_path) == [".env.test"]
    assert RULES["AAK-SECRET-006"].limitations.count("services/api/.env.test") == 1


def test_secret_006_reads_the_first_megabyte_of_gitignore_and_says_so(tmp_path: Path) -> None:
    """Main read the whole file; the read is bounded now, and git honours a pattern past
    the bound, so a `.env` line after the first 1,000,000 bytes is reported as missing."""
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://localhost/app\n", encoding="utf-8")
    filler = "# filler\n" * (1_000_000 // len("# filler\n") + 1)

    (tmp_path / ".gitignore").write_text(".env\n" + filler, encoding="utf-8")
    assert _secret_006(tmp_path) == []
    (tmp_path / ".gitignore").write_text(filler + ".env\n", encoding="utf-8")
    assert _secret_006(tmp_path) == [".env"]
    assert "1,000,000 bytes" in RULES["AAK-SECRET-006"].limitations


def test_secret_006_reads_a_gitignore_that_is_not_utf8(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_bytes(b"\xff\xfe# caf\xe9\n.env\n")

    assert _secret_006(tmp_path) == []


# ---------------------------------------------------------------------------
# AAK-SECRET-005 reads what a key file holds
#
# It reported a key by its file name (`.pem`, `.key`, `.p12`, `.pfx`, exactly
# `id_rsa` and three more) and read a PEM header only at the top of a `.crt` or
# `.cer`. So the same key as `server-key.txt`, `id_rsa_work`, `deploy_key`, an Apple
# `.p8`, a Java keystore, a PuTTY `.ppk` or a block pasted into a YAML deploy config
# was missed, and a `.pem` holding only a public certificate was reported as a
# private key, because the extension decided before the header was read.
# ---------------------------------------------------------------------------

_KEY_BODY = "\n".join(("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + _varied(32)) for _ in range(3))


def _pem(label: str, body: str = _KEY_BODY) -> str:
    return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n"


_PRIVATE = _pem("OPENSSH " + "PRIVATE KEY")
_CERTIFICATE = _pem("CERTIFICATE")


def _secret_005(root: Path) -> list[tuple[str, int | None]]:
    return sorted((f.file_path, f.line_number) for f in scan(root)[0] if f.rule_id == "AAK-SECRET-005")


@pytest.mark.parametrize(
    "name, text, line",
    [
        ("certs/server-key.txt", _PRIVATE, 1),
        (".ssh/id_rsa_work", _PRIVATE, 1),
        (".ssh/id_rsa.bak", _PRIVATE, 1),
        ("ci/deploy_key", _PRIVATE, 1),
        ("apns/AuthKey_TEST000001.p8", _pem("PRIVATE KEY"), 1),
        ("certs/fullchain-and-key.pem", _CERTIFICATE * 30 + _pem("RSA " + "PRIVATE KEY"), 30 * 5 + 1),
        ("deploy.yml", "deploy:\n  private_key: |\n    " + _PRIVATE.replace("\n", "\n    "), 3),
        ("src/keys.py", 'KEY = """' + _pem("PRIVATE KEY") + '"""\n', 1),
        ("creds/key.json", json.dumps({"private_key": _pem("PRIVATE KEY")}) + "\n", 1),
        ("gpg/secret.asc", _pem("PGP " + "PRIVATE KEY BLOCK"), 1),
        ("legacy/rsa.key", "-----BEGIN RSA " + "PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
         "DEK-Info: AES-128-CBC,3F17F5316E2BAC89\n\n" + _KEY_BODY + "\n-----END RSA " + "PRIVATE KEY-----\n", 1),
    ],
    ids=lambda v: v if isinstance(v, str) and len(v) < 60 else "",
)
def test_secret_005_reports_a_private_key_wherever_it_is_written(
    tmp_path: Path, name: str, text: str, line: int
) -> None:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    assert _secret_005(tmp_path) == [(name, line)]


def _jks(*tags: int) -> bytes:
    """A Java keystore with one entry per tag: 1 a private key, 2 a trusted certificate."""
    out = b"\xfe\xed\xfe\xed" + (2).to_bytes(4, "big") + len(tags).to_bytes(4, "big")
    for i, tag in enumerate(tags):
        alias = f"entry{i}".encode()
        out += tag.to_bytes(4, "big") + len(alias).to_bytes(2, "big") + alias + (0).to_bytes(8, "big")
        if tag == 1:  # the protected key, then a chain of one certificate
            key = b"\x01" * 48
            out += len(key).to_bytes(4, "big") + key + (1).to_bytes(4, "big")
        out += len(b"X.509").to_bytes(2, "big") + b"X.509" + (16).to_bytes(4, "big") + b"\x02" * 16
    return out + b"\x00" * 20  # the keyed SHA-1 digest


@pytest.mark.parametrize(
    "name, data, reported",
    [
        ("android/release.jks", _jks(1), True),
        ("android/release.keystore", _jks(2, 1), True),
        ("certs/server.p12", b"\x30\x82\x0a\x00" + b"\x00" * 64, True),
        ("ssh/putty.ppk", b"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n", True),
        ("certs/server.key", b"\x30\x82\x04\xa4\x02\x01\x00" + b"\x00" * 64, True),  # DER: no PEM text to read
        ("src/main/resources/truststore.jks", _jks(2, 2), False),  # trusted certificates only
        ("certs/cacert.pem", _CERTIFICATE.encode(), False),
        ("certs/ca-bundle.crt", (_CERTIFICATE * 3).encode(), False),
        ("certs/public.key", _pem("PUBLIC KEY").encode(), False),
        ("certs/request.pem", _pem("CERTIFICATE REQUEST").encode(), False),
        (".ssh/id_rsa.pub", b"ssh-ed25519 " + _varied(68).encode() + b" me@example\n", False),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_secret_005_tells_a_key_container_from_a_certificate(
    tmp_path: Path, name: str, data: bytes, reported: bool
) -> None:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

    assert bool(_secret_005(tmp_path)) is reported


@pytest.mark.parametrize(
    "name, text",
    [
        # A parser's marker constant, not a key.
        ("src/pem.py", 'BEGIN = "-----BEGIN RSA ' + 'PRIVATE KEY-----"\nEND = "-----END RSA ' + 'PRIVATE KEY-----"\n'),
        ("src/pem.ts", 'if (pem.startsWith("-----BEGIN ' + 'PRIVATE KEY-----\\n")) { return true; }\n'),
        # Documentation that shows where a key goes.
        ("docs/setup.txt", _pem("PRIVATE KEY", "..."),),
        ("docs/setup.yml", "key: |\n  " + _pem("PRIVATE KEY", "<paste your key here>").replace("\n", "\n  ")),
        ("docs/notes.txt", _pem("RSA " + "PRIVATE KEY", "MIIEowIBAAKCAQEA...")),
        # A header with no END marker.
        ("notes/cut.txt", "-----BEGIN " + "PRIVATE KEY-----\n" + _KEY_BODY + "\n"),
    ],
    ids=lambda v: v if len(v) < 40 else "",
)
def test_secret_005_does_not_report_text_that_only_names_a_key(tmp_path: Path, name: str, text: str) -> None:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    assert _secret_005(tmp_path) == []


def test_secret_005_reports_each_key_in_a_file_on_its_own_line(tmp_path: Path) -> None:
    text = "# keys\n" + _pem("PRIVATE KEY") + "\n" + _pem("EC " + "PRIVATE KEY")
    (tmp_path / "keys.txt").write_text(text, encoding="utf-8")

    assert _secret_005(tmp_path) == [("keys.txt", 2), ("keys.txt", 8)]


@pytest.mark.parametrize(
    "unit",
    [
        "-----BEGIN " + "PRIVATE KEY-----\n",
        "-----BEGIN " + "PRIVATE KEY-----\n" + "A" * 64 + "\n",
        "-----BEGIN A A A A A A A A ",
        "-----BEGIN ",
    ],
    ids=["headers", "headers-and-body", "words", "begins"],
)
def test_secret_005_reads_a_crafted_file_in_linear_time(tmp_path: Path, unit: str) -> None:
    (tmp_path / "blob.txt").write_text(unit * (900_000 // len(unit)), encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 10.0


_STAND_IN_BODIES = [
    "...",
    "<paste your private key here>",
    "YOUR_PRIVATE_KEY_HERE",
    "REPLACE_WITH_YOUR_KEY_CONTENTS",
    "x" * 64,
    "A" * 64,
    "MIIEowIBAAKCAQEA...",
    "PLACEHOLDER" + "0123456789" * 3,
    "EXAMPLEKEY" + _varied(40),
    "changeme" + _varied(40),
    "MIIBOgIBAAJBAK",  # fewer than 16 base64 characters
]


@pytest.mark.parametrize("body", _STAND_IN_BODIES, ids=lambda b: b[:16])
def test_secret_005_leaves_a_stand_in_key_in_markdown_alone(tmp_path: Path, body: str) -> None:
    """Each stand-in its limitation names, in a README's code block."""
    (tmp_path / "README.md").write_text("## Keys\n\n```\n" + _pem("PRIVATE KEY", body) + "```\n", encoding="utf-8")

    assert _secret_005(tmp_path) == []


def test_secret_005_limitation_says_it_reads_markdown_and_skips_stand_ins() -> None:
    text = RULES["AAK-SECRET-005"].limitations
    assert "Markdown included" in text
    for word in ("REPLACE", "YOUR", "EXAMPLE", "PLACEHOLDER", "CHANGEME"):
        assert word in text


def test_secret_005_reports_a_key_written_out_in_markdown(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("## Keys\n\n```\n" + _PRIVATE + "```\n", encoding="utf-8")

    assert _secret_005(tmp_path) == [("README.md", 4)]


@pytest.mark.parametrize("word", ["your", "YOUR", "Example", "xxxx", "replace", "ChangeMe"])
def test_secret_005_reports_a_real_length_key_whose_base64_spells_a_placeholder_word(
    tmp_path: Path, word: str
) -> None:
    """A key's base64 spells a placeholder word now and then: 5 of 1,307 freshly
    generated RSA-2048 keys held "your". The word test reads only a body shorter than
    any real key (64 base64 characters, Ed25519 in PKCS#8)."""
    body = "\n".join(["MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + _varied(32), _varied(20) + word + _varied(40)])
    (tmp_path / "deploy.yml").write_text("key: |\n  " + _pem("PRIVATE KEY", body).replace("\n", "\n  "), encoding="utf-8")

    assert _secret_005(tmp_path) == [("deploy.yml", 2)]


@pytest.mark.parametrize(
    "body",
    [
        "PRIVATE_KEY_CONTENT_GOES_HERE",
        "REDACTED-REDACTED-REDACTED",
        "base64-encoded-key-material",
        "INSERT_KEY_HERE_INSERT_KEY_HERE",
        "NOT-A-REAL-KEY-DO-NOT-USE",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...",
        "<contents of your key>",
    ],
)
def test_secret_005_reads_only_standard_base64_as_key_material(tmp_path: Path, body: str) -> None:
    """PEM base64 never uses `-` or `_`, so a body holding them is a placeholder."""
    (tmp_path / "README.md").write_text("## Setup\n\n```\n" + _pem("RSA " + "PRIVATE KEY", body) + "```\n", encoding="utf-8")

    assert _secret_005(tmp_path) == []


def test_secret_005_accepts_every_freshly_generated_key_body() -> None:
    """Keys generated now, in the algorithms PEM private keys come in: none may be
    taken for a placeholder, whatever its base64 happens to spell."""
    from agent_audit_kit.scanners.secret_exposure import _is_key_body

    crypto = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    def body(key: object) -> str:
        pem = key.private_bytes(  # type: ignore[attr-defined]
            crypto.Encoding.PEM, crypto.PrivateFormat.PKCS8, crypto.NoEncryption()
        ).decode()
        return pem[pem.index("-----", 11) + 5 : pem.index("-----END ")]

    keys = [ed25519.Ed25519PrivateKey.generate() for _ in range(600)]
    keys += [ec.generate_private_key(ec.SECP256R1()) for _ in range(300)]
    keys += [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(6)]
    assert [k for k in keys if not _is_key_body(body(k))] == []


# ---------------------------------------------------------------------------
# The 1,000,000-byte cap is enforced by the read, not by a stat before it (#1060)
# ---------------------------------------------------------------------------

_CAP = secret_exposure._MAX_FILE_BYTES
# Built from pieces so the repository's own self-scan, which reads this file, sees no
# key-shaped literal; the scanned file gets it whole.
_PLACEHOLDER_ANTHROPIC = "sk-ant-" + "api03-" + "q8Zr2Lm9Xc4Vb7Nk1Pw5Ty3Jh6Gf0Ds" + "W2eR4tY6uI8oP0aS"


def _sized(head: str, size: int) -> str:
    """`head` padded with comment lines to exactly `size` bytes."""
    body = head + "# " + "x" * 70 + "\n"
    filler = "# " + "x" * 70 + "\n"
    while len(body) + len(filler) <= size:
        body += filler
    return body + "#" * (size - len(body) - 1) + "\n"


@pytest.mark.parametrize("over", [0, 1])
def test_the_secret_reader_enforces_its_cap_in_the_read(tmp_path: Path, over: int) -> None:
    """A file at the cap is read and its key reported; one byte over is not read at all.
    The read itself refuses it, so a file whose stat understates its size (a stat
    taken before the file grew, or a filesystem that lies) is refused too, where the
    stat-then-read it replaced read it in full."""
    text = _sized(f"ANTHROPIC_API_KEY={_PLACEHOLDER_ANTHROPIC}\n", _CAP + over)
    assert len(text.encode("utf-8")) == _CAP + over
    path = tmp_path / "config.env"
    path.write_text(text, encoding="utf-8")
    rules = {f.rule_id for f in secret_exposure._scan_file_for_secrets(path, tmp_path)}
    assert rules == (set() if over else {"AAK-SECRET-001", "AAK-SECRET-004"})
    for rid in ("AAK-SECRET-001", "AAK-SECRET-002", "AAK-SECRET-003", "AAK-SECRET-004",
                "AAK-SECRET-007", "AAK-SECRET-008", "AAK-SECRET-009"):
        assert "A file over 1,000,000 bytes is not read." in RULES[rid].limitations


def test_the_key_file_reader_enforces_its_cap_in_the_read(tmp_path: Path) -> None:
    """A `.txt` holding a whole PEM key at the cap is reported for the key; one byte
    over is not read. A `.pem` over the cap is still reported by its name, as the
    stat-then-read reported one over the cap."""
    (tmp_path / "at-cap.txt").write_text(_sized(_pem("PRIVATE KEY"), _CAP), encoding="utf-8")
    (tmp_path / "over-cap.txt").write_text(_sized(_pem("PRIVATE KEY"), _CAP + 1), encoding="utf-8")
    (tmp_path / "over-cap.pem").write_text(_sized(_pem("PRIVATE KEY"), _CAP + 1), encoding="utf-8")
    found = sorted(
        (f.file_path, f.evidence) for f in secret_exposure._check_private_key_files(tmp_path)
    )
    assert [path for path, _ in found] == ["at-cap.txt", "over-cap.pem"]
    assert found[1][1] == "Private key file: over-cap.pem"
