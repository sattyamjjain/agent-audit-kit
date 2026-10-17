"""CVE-2026-20205 — Splunk MCP Server token cleartext in logs.

AAK-SPLUNK-TOKLOG-001 fires on (a) token-shaped values in log sinks, and
(b) `splunk-mcp-server<1.0.3` pinned in a manifest.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import log_token_leak
from agent_audit_kit.scanners.log_token_leak import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-20205"


def test_vulnerable_token_log_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-token-log")
    assert any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_redacted_token_log_passes() -> None:
    findings, _ = scan(FIXTURES / "redacted-token-log")
    assert not any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_a_splunk_mcp_server_dependency_is_not_reported(tmp_path: Path) -> None:
    """The rule had a pin on `splunk-mcp-server` below 1.0.3, which can only match the
    wrong package. CVE-2026-20205 is the Splunk MCP Server app (Splunkbase app 7931,
    `Splunk_MCP_Server`), fixed in its 1.0.3 and shipped by no package registry: on
    2026-10-17 PyPI had no `splunk-mcp-server`, and npm's (0.1.1, published
    2026-03-09 with no repository) is another project, every release of which read
    as affected. The log-call check is the rule now."""
    for name, body in (
        ("requirements.txt", "splunk-mcp-server==1.0.2\n"),
        ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["splunk-mcp-server<1.0.3"]\n'),
        ("package.json", '{"dependencies": {"splunk-mcp-server": "0.1.1"}}'),
    ):
        root = tmp_path / name.replace(".", "_")
        root.mkdir()
        (root / name).write_text(body, encoding="utf-8")
        findings, scanned = scan(root)
        assert not any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings), name
        assert name not in scanned


def test_jwt_in_log_fires(tmp_path: Path) -> None:
    (tmp_path / "leak.py").write_text(
        'import logging\nlogging.info("token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.XX.YY")\n',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_ts_console_log_bearer_fires(tmp_path: Path) -> None:
    (tmp_path / "leak.ts").write_text(
        'console.log(`Bearer ${authToken}`);\n',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_unrelated_log_call_passes(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text(
        'import logging\nlogging.info("user %s logged in", username)\n',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


# ---------------------------------------------------------------------------
# The log-sink check knows the common logger spellings
#
# The receiver pattern opened with a word boundary and listed `logger`, `LOGGER`,
# `log` and `logging`, so `_logger`, `self._logger`, `LOG`, an `app_logger` and
# `logging.getLogger(__name__)` were not log sinks, and the method list had no
# `log`, so `logger.log(level, ...)` was not a call to one.
# ---------------------------------------------------------------------------

_RULE = "AAK-SPLUNK-TOKLOG-001"


def _leaks(tmp_path: Path, name: str, source: str) -> list[int | None]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return [f.line_number for f in scan(tmp_path)[0] if f.rule_id == _RULE]


@pytest.mark.parametrize(
    "call",
    [
        'logger.info("auth %s", access_token)',
        '_logger.info("auth %s", access_token)',
        'self._logger.info("auth %s", access_token)',
        'LOG.info("auth %s", access_token)',
        'app_logger.warning("auth %s", access_token)',
        'logging.getLogger(__name__).info("auth %s", access_token)',
        'logger.log(logging.INFO, "auth %s", access_token)',
        'logging.log(logging.INFO, "auth %s", access_token)',
        'structlog.get_logger().debug("auth", token=access_token)',
        'self.log.error("auth %s", access_token)',
        "logger\n        .info('auth %s', access_token)",
    ],
)
def test_a_token_logged_through_any_common_logger_spelling_is_reported(tmp_path: Path, call: str) -> None:
    source = f"import logging\n\n\ndef login(access_token):\n    {call}\n"
    assert _leaks(tmp_path, "auth.py", source) == [5]


@pytest.mark.parametrize(
    "name, call",
    [
        ("auth.ts", "requestLogger.info(`auth ${accessToken}`);"),
        ("auth.ts", "this.logger.warn('auth', accessToken);"),
        ("Auth.java", 'LoggerFactory.getLogger(Auth.class).info("auth {}", accessToken);'),
        ("Auth.java", 'LOG.fine("auth " + accessToken);'),
    ],
)
def test_other_languages_logger_spellings_are_reported(tmp_path: Path, name: str, call: str) -> None:
    assert _leaks(tmp_path, name, f"// auth\n{call}\n") == [2]


@pytest.mark.parametrize(
    "call",
    [
        'catalog.info("auth %s", access_token)',  # a word that ends in log is no logger
        'dialog.error("auth %s", access_token)',
        'math.log(access_token)',
        'self.render.info("auth %s", access_token)',
    ],
)
def test_a_receiver_that_is_not_a_logger_is_not_a_sink(tmp_path: Path, call: str) -> None:
    assert _leaks(tmp_path, "auth.py", f"def login(access_token):\n    {call}\n") == []


# ---------------------------------------------------------------------------
# The log-sink check reads any credential name the call interpolates
#
# The names sat in one `\b...\b` group of seven compounds (`access_token`,
# `api_key`, `bearer` and four more), so bare `token`, `jwt`, `secret`,
# `password` and `authorization` were missed, and so were `github_token`,
# `bearer_token`, `client_secret` and `user_access_token`. The new names are read
# from what the call interpolates (its code and the holes of an f-string or a
# template literal), never from the message text, where "token" and "password"
# are ordinary words.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        'logger.info("token=%s", token)',
        'logger.info("jwt=%s", jwt)',
        'logger.info("secret=%s", secret)',
        'logger.info("password=%s", password)',
        'logger.info("Authorization: %s", authorization)',
        'logger.info("auth %s", github_token)',
        'logger.info("auth %s", bearer_token)',
        'logger.info("auth %s", client_secret)',
        'logger.info("auth %s", user_access_token)',
        'logger.info(f"auth {self.token}")',
        'logger.info("auth {}".format(creds.password))',
        'logger.info("auth %s" % (user, jwt_secret))',
        'logger.debug("Authorization: %s", request.headers["Authorization"])',
        'logger.debug("auth %s", headers.get("authorization"))',
        'print("token:", token)',
    ],
)
def test_an_interpolated_credential_name_is_reported(tmp_path: Path, call: str) -> None:
    source = f"import logging\n\n\ndef login(token, jwt, secret, password, authorization):\n    {call}\n"
    assert _leaks(tmp_path, "auth.py", source) == [5]


@pytest.mark.parametrize(
    "call",
    [
        'logger.info("token expired, refreshing")',  # message text only
        'logger.warning("Invalid password for %s", username)',
        'logger.info(f"Authorization header missing for {user_id}")',
        'logger.info("Processing %d tokens", n_tokens)',
        'logger.info("max_tokens=%d", max_tokens)',
        'logger.info("token_count=%d", token_count)',
        'logger.info("type %s", token_type)',
        'logger.info("secret %s", secret_name)',
        'logger.info("loaded %s", tokenizer)',
        'logger.info("auth %s", masked_token.replace(token, "***"))',
        'print(f"with an inline credential: {r.configs_with_inline_credential}")',
    ],
)
def test_a_name_in_the_message_or_a_non_credential_name_is_not_reported(tmp_path: Path, call: str) -> None:
    source = f"import logging\n\n\ndef login(username, user_id, n_tokens):\n    {call}\n"
    assert _leaks(tmp_path, "auth.py", source) == []


@pytest.mark.parametrize(
    "call",
    [
        'logging.info("Bearer token authentication ENABLED")',
        'logging.info("API key loaded (length: %d)", len(api_key))',
        'logging.warning("Set SERPAPI_KEY or pass api_key")',
        'logging.info("auth=%s", "yes" if api_key else "no")',
        'logging.info("key %s", api_key[:6])',
    ],
)
def test_the_seven_original_names_count_only_where_a_value_is_written(tmp_path: Path, call: str) -> None:
    """They ran over the whole call, so each of these fired: the names in the message
    text, and values computed from a key rather than the key."""
    source = f"import logging\n\n\ndef login(api_key):\n    {call}\n"
    assert _leaks(tmp_path, "auth.py", source) == []


@pytest.mark.parametrize(
    "call",
    [
        'logging.info("auth %s", access_token)',
        'logging.info("auth %s", session_token)',
        'logging.info("auth %s", splunkd_session)',
        'logging.info("auth %s", api_key)',
        'logging.info("auth %s", bearer)',
        'logging.info(f"auth {id_token}")',
    ],
)
def test_the_seven_original_names_still_fire_as_written_values(tmp_path: Path, call: str) -> None:
    source = f"import logging\n\n\ndef login(access_token, session_token, splunkd_session, api_key, bearer, id_token):\n    {call}\n"
    assert _leaks(tmp_path, "auth.py", source) == [5]


@pytest.mark.parametrize(
    "unit",
    ["logger.info(", "_logger.info(token ", "x.log(", "getLogger(", ").info(", '"', "logger.info((", 'logger.info("""'],
)
def test_a_crafted_file_of_unclosed_log_calls_scans_in_linear_time(tmp_path: Path, unit: str) -> None:
    import time

    (tmp_path / "blob.py").write_text(unit * (900_000 // len(unit)), encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 10.0


def test_deeply_nested_arguments_neither_crash_nor_stall(tmp_path: Path) -> None:
    import time

    nested = "logger.info(" + "(" * 1_900 + "token" + ")" * 1_900 + ")\n"
    (tmp_path / "deep.py").write_text(nested * 40, encoding="utf-8")
    started = time.perf_counter()
    findings, _ = scan(tmp_path)
    assert time.perf_counter() - started < 10.0
    assert not [f for f in findings if f.rule_id == "AAK-INTERNAL-SCANNER-FAIL"]


# ---------------------------------------------------------------------------
# Review follow-ups: a value-keeping wrapper is still the value, and a file of
# closed calls with quote-heavy arguments reads in linear time
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        'logger.info("auth %s", str(access_token))',
        'logger.info("auth %s", repr(access_token))',
        'logger.info("auth %s", format(access_token))',
        'logger.info("using %s", access_token.strip())',
        'logger.info("auth %s", token.decode())',
        'logger.info("auth %s", token.decode("utf-8"))',
        'logger.info("auth %s", str(headers.get("Authorization")).strip())',
    ],
)
def test_a_wrapper_that_keeps_the_value_is_still_the_credential(tmp_path: Path, call: str) -> None:
    source = f"import logging\n\n\ndef login(access_token, token, headers):\n    {call}\n"
    assert _leaks(tmp_path, "auth.py", source) == [5]


@pytest.mark.parametrize(
    "call",
    [
        'logger.info("auth %s", len(access_token))',
        'logger.info("auth %s", access_token[:8])',
        'logger.info("auth %s", hash(access_token))',
        'logger.info("auth %s", str(len(access_token)))',
        'logger.debug("%s", token)',  # only `token`, and no credential word in the message
        'logger.info("value=%s", token)',
    ],
)
def test_a_value_computed_from_a_credential_is_not_reported(tmp_path: Path, call: str) -> None:
    source = f"import logging\n\n\ndef login(access_token, token):\n    {call}\n"
    assert _leaks(tmp_path, "auth.py", source) == []


@pytest.mark.parametrize("unit", ['"\\', "`\\", "'\\", '"""', '"', "f'{"])
def test_a_file_of_closed_calls_with_quote_heavy_arguments_reads_in_linear_time(tmp_path: Path, unit: str) -> None:
    """Each argument is 3,990 characters of one unit, inside a call that closes. Retrying
    the literal pattern at every quote cost a scan per quote: 200 such calls took 14 s."""
    import time

    args = (unit * (3_990 // len(unit) + 1))[:3_990]
    (tmp_path / "blob.py").write_text(("logger.info(" + args + ")\n") * 200, encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 5.0


def test_calls_that_open_replace_repeatedly_read_in_linear_time(tmp_path: Path) -> None:
    """The redaction hint read `.replace(` with two unbounded `[^)]*` runs around a token
    word, so each closed call of `.replace(token,` repeated cost about 75 ms and 80 of
    them (0.31 MB) about 6 s, on main as on this branch before the bound. Both runs are
    bounded now, and the 80 calls take 0.1 s."""
    import time

    unit = ".replace(token,"
    k = 3_900 // (len(unit) + 1)
    call = "logger.info(" + unit * k + ")" * k + ")\n"
    (tmp_path / "blob.py").write_text(call * 80, encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 3.0


@pytest.mark.parametrize(
    "call",
    [
        'logger.info("auth %s", masked.replace(token, "***"))',
        'logger.info("auth %s", header.replace(self.api_key, "[REDACTED]"))',
        'logger.info("auth %s", url.replace(bearer_token, "<redacted>"))',
    ],
)
def test_a_replace_that_masks_the_credential_still_reads_as_redacted(tmp_path: Path, call: str) -> None:
    source = f"import logging\n\n\ndef login(masked, header, url, token, bearer_token):\n    {call}\n"
    assert _leaks(tmp_path, "auth.py", source) == []


# ---------------------------------------------------------------------------
# The two bounds that keep a crafted file linear are stated limits, edge for edge
#
# Main read a call of any length and every call in a file. A call whose arguments
# run past 4,000 characters is now skipped, and a call is read only if its arguments
# end within the file's first 2,000,000 characters of call arguments.
# ---------------------------------------------------------------------------


def _leak_call(arguments: int) -> str:
    """A log call that writes `access_token`, with arguments exactly ``arguments`` long."""
    head = '"auth %s", access_token, "'
    return "logger.info(" + head + "x" * (arguments - len(head) - 1) + '")\n'


def test_a_call_past_the_argument_window_is_not_read_and_the_rule_says_so(tmp_path: Path) -> None:
    """The window read at most 3,999 characters, so a call of exactly 4,000 was skipped
    while the sentence said only one past 4,000 is."""
    assert _leaks(tmp_path / "at", "auth.py", _leak_call(4_000)) == [1]
    assert _leaks(tmp_path / "past", "auth.py", _leak_call(4_001)) == []
    assert "past 4,000 characters" in RULES[_RULE].limitations


def test_a_call_is_read_only_if_its_arguments_end_within_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The budget counts the arguments of nested calls once per call around them,
    # so a file under the 512 KB source cap can spend it. Flat calls spend no more
    # than the file holds, so this measures the boundary against a smaller one;
    # the budget the scanner ships, which the rule text states, is pinned here.
    assert log_token_leak._FILE_ARGS_BUDGET == 2_000_000
    budget = 200_000
    monkeypatch.setattr(log_token_leak, "_FILE_ARGS_BUDGET", budget)
    benign = 'logger.info("' + "y" * 3_986 + '")\n'  # 3,988 characters of arguments
    count = budget // 3_988
    used = count * 3_988
    ending_at_the_budget = benign * count + _leak_call(budget - used)
    straddling_it = benign * count + _leak_call(budget - used + 1)
    assert _leaks(tmp_path / "within", "auth.py", ending_at_the_budget) == [count + 1]
    assert _leaks(tmp_path / "straddling", "auth.py", straddling_it) == []
    assert "end within the file's first 2,000,000 characters" in RULES[_RULE].limitations
