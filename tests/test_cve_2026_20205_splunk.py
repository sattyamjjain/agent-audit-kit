"""CVE-2026-20205 — Splunk MCP Server token cleartext in logs.

AAK-SPLUNK-TOKLOG-001 fires on (a) token-shaped values in log sinks, and
(b) `splunk-mcp-server<1.0.3` pinned in a manifest.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.scanners.log_token_leak import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-20205"


def test_vulnerable_token_log_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-token-log")
    assert any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_redacted_token_log_passes() -> None:
    findings, _ = scan(FIXTURES / "redacted-token-log")
    assert not any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_vulnerable_splunk_pin_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-splunk-pin")
    assert any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_patched_splunk_pin_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-splunk-pin")
    assert not any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


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
