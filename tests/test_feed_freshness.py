"""How old the malicious-release and advisory feeds are, said where a user looks.

On 2026-11-18 a scan of `agent-framework==1.26.2` (OSV MAL-2026-20101, published
that day) said "No findings.": no `aak update` had run, so it read the bundled
feed from 2026-11-12, and the only sign was a dim footer line. These tests pin
what a scan now says about an old feed: `ageDays` and `stale` in every report, a
WARNING line in the console footer, a warning notification in the SARIF run,
`--max-feed-age` and `--fail-on-stale-feed`, the Action's `update-feeds` input,
and the bundled agent-framework entry. The clock is pinned and nothing is fetched.
"""

from __future__ import annotations

import ast
import http.client
import json
import os
import shutil
import socket
import subprocess
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit import advisory_feed, malicious_feed
from agent_audit_kit.cli import cli
from agent_audit_kit.commands._common import EXIT_ERROR
from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.console import format_results as console_results
from agent_audit_kit.output.json_report import format_results as json_results
from agent_audit_kit.output.sarif import format_results as sarif_results

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures" / "malicious_releases"
RULE = "AAK-MALICIOUS-RELEASE-001"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
WARNING = "WARNING: malicious-release feed"


def _stamp(days_old: float) -> str:
    return (NOW - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _feeds(malicious: str, advisories: str | None = None) -> None:
    """Cached copies of both feeds, generated at the given times (the advisory feed
    a day old unless given), so the bundled copies' real age plays no part."""
    path = malicious_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": malicious, "source": "test feed", "entries": [
        {"id": "MAL-TEST-1", "aliases": [], "ecosystem": "PyPI", "name": "aak-evil", "versions": ["1.0.0"],
         "modified": "", "url": ""}]}))
    advisory_feed.cache_path().write_text(json.dumps({
        "generated_at": advisories if advisories is not None else _stamp(1), "source": "test advisories",
        "entries": [], "nvd": [], "launch": []}))


SHIPPED_MAX_FEED_AGE_DAYS = 3


@pytest.fixture(autouse=True)
def _pinned_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """The clock at NOW, and the shipped default age back (conftest turns it off
    for every other test)."""
    monkeypatch.setattr(malicious_feed, "_utc_now", lambda: NOW)
    monkeypatch.setattr(malicious_feed, "DEFAULT_MAX_FEED_AGE_DAYS", SHIPPED_MAX_FEED_AGE_DAYS)


def test_the_shipped_default_is_three_days() -> None:
    """Read from the source, since conftest replaces the module's value in every test."""
    tree = ast.parse((REPO / "agent_audit_kit" / "malicious_feed.py").read_text(encoding="utf-8"))
    [value] = [node.value for node in tree.body if isinstance(node, ast.Assign)
               and [getattr(t, "id", None) for t in node.targets] == ["DEFAULT_MAX_FEED_AGE_DAYS"]]
    assert ast.literal_eval(value) == SHIPPED_MAX_FEED_AGE_DAYS
    assert "(default 3)" in " ".join(CliRunner().invoke(cli, ["scan", "--help"]).output.split())


def _scan(*args: str, path: Path = FIXTURES / "negative"):
    """`aak scan`, stdout and stderr together in `.output`."""
    return CliRunner().invoke(cli, ["scan", str(path), *args])


def _split_runner() -> CliRunner:
    """A runner whose results keep stderr apart from stdout on Click 8.1 (the
    Python 3.9 leg) and on 8.2, which always does and dropped the argument."""
    try:
        return CliRunner(mix_stderr=False)  # type: ignore[call-arg]
    except TypeError:
        return CliRunner()


def _notifications(sarif: dict) -> list[dict]:
    return sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]


# ---- feed_staleness -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "generated, limit, age, stale",
    [
        (_stamp(1), 3, "1.0", "false"),
        (_stamp(3), 3, "3.0", "false"),          # exactly the limit is not past it
        (_stamp(3.05), 3, "3.0", "true"),        # past it, though it rounds to 3.0
        (_stamp(5), 3, "5.0", "true"),
        (_stamp(40), 0, "40.0", "false"),        # 0 turns the age test off
        (_stamp(-1), 3, "0.0", "false"),         # a time ahead of the clock is not old
        ("2026-11-19T12:00:00.123456789Z", 3, "1.0", "false"),  # OSV's nine fractional digits
        ("2026-11-19T12:00:00", 3, "1.0", "false"),             # no zone: UTC
        ("2026-11-19T17:30:00+05:30", 3, "1.0", "false"),
        ("", 3, "unknown", "true"),
        ("yesterday", 0, "unknown", "true"),    # unknown age is stale even with the test off
        ("9999-12-31T23:59:59-23:00", 3, "unknown", "true"),
    ],
)
def test_feed_staleness(generated: str, limit: int, age: str, stale: str) -> None:
    assert malicious_feed.feed_staleness({"generatedAt": generated}, limit, now=NOW) == {"ageDays": age, "stale": stale}


def test_a_summary_without_generated_at_is_stale() -> None:
    assert malicious_feed.feed_staleness({"error": "OSError: gone"}, 3, now=NOW) == {"ageDays": "unknown", "stale": "true"}


# ---- the reports ------------------------------------------------------------------------------


def test_a_one_day_old_feed_is_not_stale_and_prints_no_warning() -> None:
    _feeds(_stamp(1))
    result = run_scan(project_root=FIXTURES / "negative")
    assert result.data_feeds["maliciousReleases"]["ageDays"] == "1.0"
    assert result.data_feeds["maliciousReleases"]["stale"] == "false"
    assert result.data_feeds["knownVulnerabilities"]["stale"] == "false"
    assert "WARNING" not in console_results(result)
    assert _notifications(json.loads(sarif_results(result))) == []


def test_a_five_day_old_feed_is_stale_in_every_report() -> None:
    _feeds(_stamp(5))
    result = run_scan(project_root=FIXTURES / "negative")
    feed = result.data_feeds["maliciousReleases"]
    assert (feed["ageDays"], feed["stale"], feed["origin"]) == ("5.0", "true", "cached")
    console = console_results(result)
    assert (f"{WARNING} is the cached copy from {_stamp(5)[:10]} (5.0 days old). Malware published since then "
            "is not checked. Run `agent-audit-kit update` first, or set update-feeds: 'true' on the GitHub "
            "Action.") in console
    assert "advisory feed is" not in console  # the advisory feed is a day old
    sarif = json.loads(sarif_results(result))
    [notice] = _notifications(sarif)
    assert notice["level"] == "warning" and notice["message"]["text"].startswith(WARNING)
    assert notice["properties"] == {"feed": "maliciousReleases", "origin": "cached",
                                    "generatedAt": _stamp(5), "ageDays": "5.0"}
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True
    assert sarif["runs"][0]["properties"]["dataFeeds"]["maliciousReleases"]["stale"] == "true"
    report = json.loads(json_results(result))
    assert report["dataFeeds"]["maliciousReleases"]["ageDays"] == "5.0"
    assert report["dataFeeds"]["knownVulnerabilities"]["stale"] == "false"


def test_a_stale_advisory_feed_is_named_too() -> None:
    _feeds(_stamp(1), advisories=_stamp(9))
    result = run_scan(project_root=FIXTURES / "negative")
    console = console_results(result)
    assert WARNING not in console
    assert "WARNING: advisory feed is the cached copy" in console and "(9.0 days old)" in console
    assert [n["properties"]["feed"] for n in _notifications(json.loads(sarif_results(result)))] == [
        "knownVulnerabilities"]


def test_the_bundled_copy_names_its_entry_count() -> None:
    result = run_scan(project_root=FIXTURES / "negative", max_feed_age_days=0)
    feed = result.data_feeds["maliciousReleases"]
    assert feed["origin"] == "bundled" and feed["stale"] == "false"
    count = len(json.loads(malicious_feed.BUNDLED_FEED.read_text())["entries"])
    assert feed["entries"] == str(count)
    stale = {**feed, "stale": "true", "ageDays": "6.1"}
    [line] = malicious_feed.stale_feed_warnings({"maliciousReleases": stale})
    assert f"{WARNING} is the bundled copy from {feed['generatedAt'][:10]} (6.1 days old, {count} entries)." in line


def test_max_feed_age_zero_turns_the_age_test_off() -> None:
    _feeds(_stamp(40), advisories=_stamp(40))
    result = _scan("--max-feed-age", "0")
    assert result.exit_code == 0, result.output
    assert "WARNING" not in result.output
    assert "Malicious-release feed: cached copy" in result.output


def test_an_unreadable_generated_at_is_stale_of_unknown_age() -> None:
    _feeds("not a time")
    result = run_scan(project_root=FIXTURES / "negative")
    assert result.data_feeds["maliciousReleases"]["ageDays"] == "unknown"
    assert result.data_feeds["maliciousReleases"]["stale"] == "true"
    assert f"{WARNING} is the cached copy, of unknown age (no readable generated_at)." in console_results(result)


def test_an_unreadable_feed_is_stale() -> None:
    feeds = {"maliciousReleases": {"error": "ValueError: no entries", **malicious_feed.feed_staleness({}, 3, now=NOW)}}
    [line] = malicious_feed.stale_feed_warnings(feeds)
    assert line.startswith(f"{WARNING} could not be read (ValueError: no entries), so nothing is checked against it.")


# ---- --fail-on-stale-feed and where the line goes ----------------------------------------------------------


def test_fail_on_stale_feed_exits_2_only_when_a_feed_is_stale(tmp_path: Path) -> None:
    _feeds(_stamp(5))
    out = tmp_path / "report.sarif"
    stale = _scan("--fail-on-stale-feed", "--format", "sarif", "-o", str(out))
    assert stale.exit_code == EXIT_ERROR, stale.output
    assert "STALE FEED: 1 feed(s) older than --max-feed-age 3 day(s)" in stale.output
    assert _notifications(json.loads(out.read_text()))  # the report was written first
    assert _scan("--fail-on-stale-feed", "--max-feed-age", "7").exit_code == 0
    assert _scan().exit_code == 0  # stale without the flag: the warning, not the exit
    _feeds(_stamp(1))
    assert _scan("--fail-on-stale-feed").exit_code == 0


def test_the_warning_goes_to_stderr_when_no_console_footer_shows_it(tmp_path: Path) -> None:
    _feeds(_stamp(5))
    for args in (("--format", "sarif", "-o", str(tmp_path / "r.sarif")), ("--format", "json"), ("--quiet",)):
        result = _split_runner().invoke(cli, ["scan", str(FIXTURES / "negative"), *args])
        assert result.exit_code == 0, result.output
        assert result.stderr.count(WARNING) == 1, args
    footer = _split_runner().invoke(cli, ["scan", str(FIXTURES / "negative")])
    assert footer.stdout.count(WARNING) == 1 and WARNING not in footer.stderr


def test_the_config_file_sets_the_age_and_a_bad_one_is_an_error(tmp_path: Path) -> None:
    _feeds(_stamp(5))
    (tmp_path / ".agent-audit-kit.yml").write_text("max-feed-age: 7\nfail-on-stale-feed: true\n")
    assert _scan(path=tmp_path).exit_code == 0
    (tmp_path / ".agent-audit-kit.yml").write_text("max-feed-age: 2\nfail-on-stale-feed: true\n")
    assert _scan(path=tmp_path).exit_code == EXIT_ERROR
    assert _scan("--max-feed-age", "9", path=tmp_path).exit_code == 0  # the flag wins
    (tmp_path / ".agent-audit-kit.yml").write_text("max-feed-age: -1\n")
    bad = _scan(path=tmp_path)
    assert bad.exit_code == EXIT_ERROR and "max-feed-age in the config must be a whole number" in bad.output


def test_a_scan_that_checks_feed_age_never_touches_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a scan opened a network connection")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    _feeds(_stamp(5))
    result = _scan("--fail-on-stale-feed", "--format", "sarif")
    assert result.exit_code == EXIT_ERROR and WARNING in result.output


# ---- the bundled agent-framework entry ------------------------------------------------------------


def test_agent_framework_1_26_2_is_reported_from_the_bundled_copy() -> None:
    """HOME is empty (conftest), so this reads the bundled feed, as a fresh install or
    an Action run without update-feeds does."""
    result = run_scan(project_root=FIXTURES / "agent-framework-pin")
    assert result.data_feeds["maliciousReleases"]["origin"] == "bundled"
    [finding] = [f for f in result.findings if f.rule_id == RULE]
    assert (finding.file_path, finding.line_number) == ("requirements.txt", 1)
    assert "MAL-2026-20101 (GHSA-764m-3ppc-5m73), which lists agent-framework 1.26.2" in finding.evidence
    clean = run_scan(project_root=FIXTURES / "agent-framework-clean")
    assert [f for f in clean.findings if f.rule_id == RULE] == []


def test_the_bundled_agent_framework_entry_is_the_osv_record() -> None:
    """MAL-2026-20101, saved unedited from https://api.osv.dev/v1/vulns/MAL-2026-20101 on
    2026-11-18, as `aak update` would read it, plus the GHSA id GitHub's advisory
    (GHSA-764m-3ppc-5m73) derives from it, which the OSV record does not alias."""
    record = json.loads((FIXTURES / "osv" / "MAL-2026-20101.json").read_text())
    [expected] = malicious_feed.osv_entries(record, "PyPI")
    expected["aliases"] = ["GHSA-764m-3ppc-5m73"]
    data = json.loads(malicious_feed.BUNDLED_FEED.read_text())
    assert {e["id"]: e for e in data["entries"]}["MAL-2026-20101"] == expected
    assert expected["versions"] == ["1.26.1", "1.26.2"]
    assert "MAL-2026-20101" in data["source"]


# ---- the Action's update-feeds input ----------------------------------------------------------


def _entrypoint(tmp_path: Path, update_feeds: str | None, update_exit: int = 0) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run entrypoint.sh against a stand-in CLI that logs each call and writes an
    empty SARIF for the scan."""
    log = tmp_path / "calls.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "agent-audit-kit"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "$*" >> "{log}"\n'
        f'if [ "$1" = "update" ]; then exit {update_exit}; fi\n'
        "out=''\n"
        'while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done\n'
        """printf '%s' '{"version":"2.1.0","runs":[{"results":[]}]}' > "$out"\n""",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_EVENT_NAME", "GITHUB_TOKEN", "GITHUB_OUTPUT")}
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["GITHUB_STEP_SUMMARY"] = str(tmp_path / "summary.md")
    args = [".", "low", "high", "sarif", "false", "false", "", "", "", "", "", "false", "auto"]
    if update_feeds is not None:
        args.append(update_feeds)
    proc = subprocess.run(["bash", str(REPO / "entrypoint.sh"), *args], cwd=tmp_path, env=env,
                          capture_output=True, text=True)
    return proc, log.read_text().splitlines()


needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


@needs_bash
@pytest.mark.parametrize("update_feeds", ["true", None])  # None: the input left out, as an older action.yml passes
def test_update_feeds_runs_update_before_the_scan(tmp_path: Path, update_feeds: str | None) -> None:
    proc, calls = _entrypoint(tmp_path, update_feeds)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert calls[0] == "update --nvd-days 0" and calls[1].startswith("scan . ")
    assert "::warning" not in proc.stdout


@needs_bash
def test_a_failed_update_warns_once_and_scans_anyway(tmp_path: Path) -> None:
    proc, calls = _entrypoint(tmp_path, "true", update_exit=2)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [c.split()[0] for c in calls] == ["update", "scan"]
    warnings = [line for line in proc.stdout.splitlines() if line.startswith("::warning")]
    assert warnings == ["::warning title=AgentAuditKit feeds::agent-audit-kit update exited 2; scanning with "
                        "the feeds already on hand (the scan names any stale one)."]


@needs_bash
def test_update_feeds_false_scans_offline(tmp_path: Path) -> None:
    proc, calls = _entrypoint(tmp_path, "false")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [c.split()[0] for c in calls] == ["scan"]


def test_update_feeds_is_the_last_action_input_and_defaults_to_true() -> None:
    import yaml

    action = yaml.safe_load((REPO / "action.yml").read_text(encoding="utf-8"))
    assert list(action["inputs"])[-1] == "update-feeds"
    assert action["inputs"]["update-feeds"]["default"] == "true"
    assert action["runs"]["args"][-1] == "${{ inputs.update-feeds }}"
    assert action["runs"]["args"][-2] == "${{ inputs.fingerprint-strategy }}"
    assert len(action["runs"]["args"]) == len(action["inputs"]) == 14
