from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

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
