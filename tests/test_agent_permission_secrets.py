"""AAK-SECRET-010 and AAK-SECRET-011: credentials Claude Code saved in its permission rules.

Apiiro (The Hacker News, 7 Nov 2026): answering "Yes, and don't ask again" makes Claude
Code save the exact command, secret included, as an allow rule in
`.claude/settings.local.json`; 1,122 of 104,185 public copies held at least one secret.
On 0.6.32 the fixture below gave AAK-TRUST-004 and -006 and no secret finding:
AAK-SECRET-004 dropped `PGPASSWORD=` as short and plain, and read no `-p` or `sshpass`.
Every value here is made up; the hosts are `.example` names.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners._agent_permission_secrets import command_credentials
from agent_audit_kit.scanners.secret_exposure import scan

FIXTURES = Path(__file__).parent / "fixtures" / "agent_permission_secrets"
VULNERABLE, CLEAN = FIXTURES / "vulnerable", FIXTURES / "clean"
SETTINGS = ".claude/settings.local.json"
# The fixture's credentials, by the line of the rule that holds each.
FIXTURE_VALUES = {
    4: "Xk9vT2qLm7Rw", 5: "Zq8Nw3Lt5Vb7", 6: "Hy4Kd9Wm2Px6", 8: "Rt7Yw2Pq9Lm4", 9: "Vn3Bx8Kq1Wz5",
}


def _rule(findings: list, rule_id: str) -> list:
    return [f for f in findings if f.rule_id == rule_id]


def _settings(root: Path, *rules: str, gitignore: str | None = ".claude/settings.local.json\n") -> Path:
    (root / ".claude").mkdir(parents=True, exist_ok=True)
    (root / SETTINGS).write_text(json.dumps({"permissions": {"allow": list(rules)}}, indent=2))
    if gitignore is not None:
        (root / ".gitignore").write_text(gitignore)
    return root


# ---- AAK-SECRET-010 on the fixture ------------------------------------------------------------


def test_each_shape_in_the_fixture_fires_once_on_its_rules_line() -> None:
    findings, _ = scan(VULNERABLE)
    assert sorted((f.file_path, f.line_number, f.evidence.split(" in permissions.")[0])
                  for f in _rule(findings, "AAK-SECRET-010")) == [
        (SETTINGS, 4, "assignment to `PGPASSWORD`"),
        (SETTINGS, 5, "password attached to `mysql -p`"),
        (SETTINGS, 6, "password after `sshpass -p`"),
        (SETTINGS, 8, "password in the credentials after `curl -u`"),
        (SETTINGS, 9, "password in a `postgres://` URL"),
    ]


def test_the_message_names_the_list_and_at_most_two_characters() -> None:
    findings, _ = scan(VULNERABLE)
    for finding in _rule(findings, "AAK-SECRET-010"):
        value = FIXTURE_VALUES[finding.line_number]
        assert finding.evidence.endswith(f" in permissions.allow (value starts `{value[:2]}`)")
        assert value[:3] not in finding.evidence
    every = " ".join(f.evidence for f in findings)
    assert not [v for v in FIXTURE_VALUES.values() if v in every]


def test_every_clean_rule_is_quiet() -> None:
    findings, _ = scan(CLEAN)
    assert _rule(findings, "AAK-SECRET-010") == [] and _rule(findings, "AAK-SECRET-011") == []


def test_the_scan_reports_the_fixture_end_to_end() -> None:
    findings, _ = scan(VULNERABLE)
    assert len(_rule(findings, "AAK-SECRET-010")) >= 5
    (unignored,) = _rule(findings, "AAK-SECRET-011")
    assert unignored.file_path == SETTINGS and unignored.evidence.endswith("but .gitignore does not ignore it")
    result = run_scan(project_root=VULNERABLE, rules=["AAK-SECRET-010", "AAK-SECRET-011"])
    assert sorted(f.rule_id for f in result.findings) == ["AAK-SECRET-010"] * 5 + ["AAK-SECRET-011"]


# ---- the shapes ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("rule", "shape", "value"), [
    ("Bash(MYSQL_PWD=Ab3Cd4Ef5 mysql -u r)", "assignment to `MYSQL_PWD`", "Ab3Cd4Ef5"),
    ("Bash(export API_TOKEN=Zy8Xw7Vu6 && ./deploy.sh)", "assignment to `API_TOKEN`", "Zy8Xw7Vu6"),
    ('Bash(env DB_PASSWORD="Ty5Re4Wq3" ./run)', "assignment to `DB_PASSWORD`", "Ty5Re4Wq3"),
    ("Bash(mysqldump -uroot -p'Gh6Jk7Lm8' db)", "password attached to `mysqldump -p`", "Gh6Jk7Lm8"),
    ("Bash(sudo mariadb -pRt5Ew4Qa3)", "password attached to `mariadb -p`", "Rt5Ew4Qa3"),
    ("Bash(mysqladmin -pPl4Ok3Ij2 status)", "password attached to `mysqladmin -p`", "Pl4Ok3Ij2"),
    ("Bash(mysql -pSecret12:*)", "password attached to `mysql -p`", "Secret12"),
    ("Bash(mysql --password=Zx9Cv8Bn7 db)", "value of `--password`", "Zx9Cv8Bn7"),
    ("Bash(docker login --password Qw1Er2Ty3 registry.example)", "value of `--password`", "Qw1Er2Ty3"),
    ("Bash(sshpass -pPo9Iu8Yt7 ssh -p 2222 h)", "password after `sshpass -p`", "Po9Iu8Yt7"),
    ('Bash(sshpass -p "Uy7Tr6Ew5" ssh h)', "password after `sshpass -p`", "Uy7Tr6Ew5"),
    ("Bash(curl --user=admin:Lk5Jh4Gf3 https://x.example)", "password in the credentials after `curl --user`",
     "Lk5Jh4Gf3"),
    ("Bash(curl --user admin:Hg4Fd3Sa2 https://x.example)", "password in the credentials after `curl --user`",
     "Hg4Fd3Sa2"),
    ("Bash(redis-cli -u redis://default:Mn2Bv3Cx4@cache.example:6379 ping)", "password in a `redis://` URL",
     "Mn2Bv3Cx4"),
    ("Bash(mongosh mongodb+srv://u:Pw7Ok6Ij5@c.example/db)", "password in a `mongodb+srv://` URL", "Pw7Ok6Ij5"),
    ("Bash(curl https://bot:Wq2Ea3Sd4@hooks.example/x)", "password in a `https://` URL", "Wq2Ea3Sd4"),
    ("Bash(curl -H 'Authorization: Bearer Ab12Cd34Ef56' https://x.example)",
     "Bearer credentials in an `Authorization` header", "Ab12Cd34Ef56"),
    ("Bash(curl -H Authorization: token Tq9Wr8Ey7 https://x.example)",
     "Token credentials in an `Authorization` header", "Tq9Wr8Ey7"),
    ("Bash(psql -c 'select 1' && PGPASSWORD=Ws3Ed4Rf5 pg_dump app)", "assignment to `PGPASSWORD`", "Ws3Ed4Rf5"),
])
def test_each_shape_reads_its_value(rule: str, shape: str, value: str) -> None:
    assert command_credentials(rule) == [(shape, value)]


@pytest.mark.parametrize("rule", [
    "Bash(npm run:*)", "Bash(mysql -p)", "Bash(mysql -p$DB_PASS)", "Bash(PGPASSWORD=$PGPASSWORD psql)",
    "Bash(PGPASSWORD=${PGPASSWORD} psql)", "Bash(PGPASSWORD=$(cat ~/.pgpw) psql)", "Bash(mysql -p:*)",
    "Bash(mysql -P3306 -h db.example)", "Bash(mysql --password db)", "Bash(mysql --port 3306)",
    "Bash(sshpass -p)", "Bash(sshpass -f pw.txt ssh -p 2222 h)", "Bash(curl -u admin https://x.example)",
    "Bash(TOKEN=* run)", "Bash(TOKEN=abc* run)", "Bash(PWD=/tmp ls)", "Bash(OLDPWD=/x cd)",
    "Bash(DB_PASSWORD_FILE=/run/secrets/db app)", "Bash(TOKEN_URL=https://auth.example/token app)",
    "Bash(git push https://user:${GH}@github.com/a/b)", "Bash(docker login --password-stdin r.example)",
    "Bash(git status)", "WebFetch(domain:example.net)", "Read(./secrets/**)",
])
def test_references_prompts_ports_and_wildcards_are_not_credentials(rule: str) -> None:
    assert command_credentials(rule) == []


def test_a_placeholder_is_left_out(tmp_path: Path) -> None:
    _settings(tmp_path, "Bash(sshpass -p <your-password> ssh x)", "Bash(PGPASSWORD=changeme psql)",
              "Bash(MYSQL_PWD=xxxxxxxx mysql)")
    assert _rule(scan(tmp_path)[0], "AAK-SECRET-010") == []


@pytest.mark.parametrize(
    ("value", "reported"),
    [
        # One character repeated reads as a stand-in, however short.
        ("x", False), ("0000", False), ("1111", False), ("a-a-a", False),
        ("CHANGEME", False), ("xxxx1234", False), ("example-pass", False),
        # Anything else is reported, however short or plain.
        ("hunter2", True), ("1234", True), ("ab", True), ("x1", True),
    ],
)
def test_which_short_values_read_as_placeholders(tmp_path: Path, value: str, reported: bool) -> None:
    """CHANGELOG 0.6.34 said AAK-SECRET-010 has no length or entropy gate, yet
    `PGPASSWORD=x` gave no finding: `_is_placeholder` skips a value of one repeated
    character. The rule's limitations now name every value it skips; this pins them."""
    _settings(tmp_path, f"Bash(PGPASSWORD={value} psql:*)")
    assert bool(_rule(scan(tmp_path)[0], "AAK-SECRET-010")) is reported
    limitations = RULES["AAK-SECRET-010"].limitations
    assert "one character repeated" in limitations and "`PGPASSWORD=x`" in limitations


def test_ask_and_deny_are_read_and_named(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"permissions": {
        "ask": ["Bash(sshpass -p Kj8Hg7Fd6 ssh h)"], "deny": ["Bash(PGPASSWORD=Lo9Ki8Ju7 psql)"],
    }}, indent=2))
    assert sorted(f.evidence.split(" (")[0] for f in _rule(scan(tmp_path)[0], "AAK-SECRET-010")) == [
        "assignment to `PGPASSWORD` in permissions.deny", "password after `sshpass -p` in permissions.ask",
    ]


def test_a_value_a_prefix_rule_reports_is_reported_once(tmp_path: Path) -> None:
    token = "gh" + "p_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
    _settings(tmp_path, f"Bash(GITHUB_TOKEN={token} gh api user)")
    ids = [f.rule_id for f in scan(tmp_path)[0]]
    # AAK-SECRET-004 reads `GITHUB_TOKEN=<high-entropy value>` too, in any file, as it did
    # before this rule; AAK-SECRET-010 adds no third report of the same token.
    assert ids.count("AAK-SECRET-008") == 1 and "AAK-SECRET-010" not in ids


def test_a_value_aak_secret_004_reports_is_reported_once(tmp_path: Path) -> None:
    value = "q7Wz2Xe9Rv4Tb6Yn1Um8Ik3Ol5Pa0Sd"  # 30 characters, entropy over 4.5
    _settings(tmp_path, f"Bash(DB_PASSWORD={value} ./migrate)")
    findings, _ = scan(tmp_path)
    assert [f.rule_id for f in findings if f.rule_id.startswith("AAK-SECRET-0")] == ["AAK-SECRET-004"]


def test_a_rule_written_twice_is_placed_at_each_copy(tmp_path: Path) -> None:
    _settings(tmp_path, "Bash(sshpass -p Mn8Bv7Cx6 ssh h)", "Bash(git status)", "Bash(sshpass -p Mn8Bv7Cx6 ssh h)")
    assert sorted(f.line_number for f in _rule(scan(tmp_path)[0], "AAK-SECRET-010")) == [4, 6]


def test_a_jsonc_settings_file_and_a_nested_project_are_read(tmp_path: Path) -> None:
    folder = tmp_path / "services" / "api" / ".claude"
    folder.mkdir(parents=True)
    (folder / "settings.local.json").write_text(
        '{\n  // saved by Claude Code\n  "permissions": {"allow": [\n    "Bash(mysql -pQa1Ws2Ed3)",\n  ]}\n}\n'
    )
    (finding,) = _rule(scan(tmp_path)[0], "AAK-SECRET-010")
    assert (finding.file_path, finding.line_number) == ("services/api/.claude/settings.local.json", 4)


def test_other_files_and_ignored_paths_are_not_read_for_permission_rules(tmp_path: Path) -> None:
    rules = {"permissions": {"allow": ["Bash(mysql -pQa1Ws2Ed3)"]}}
    (tmp_path / "settings.local.json").write_text(json.dumps(rules))  # not in a .claude folder
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "settings.local.json").write_text(json.dumps(rules))
    (tmp_path / "skip" / ".claude").mkdir(parents=True)
    (tmp_path / "skip" / ".claude" / "settings.json").write_text(json.dumps(rules))
    (tmp_path / "node_modules" / ".claude").mkdir(parents=True)
    (tmp_path / "node_modules" / ".claude" / "settings.json").write_text(json.dumps(rules))
    assert _rule(scan(tmp_path, ignore_paths=["skip"])[0], "AAK-SECRET-010") == []


# ---- AAK-SECRET-011 -------------------------------------------------------------------------------


@pytest.mark.parametrize(("gitignore", "reported"), [
    (None, "no .gitignore found"),
    ("node_modules/\n", ".gitignore does not ignore it"),
    (".claude/\n", None),
    ("settings.local.json\n", None),
    ("/settings.local.json\n", ".gitignore does not ignore it"),
    # git cannot re-include a file whose folder is ignored, so the `!` changes nothing here
    # (`git check-ignore` agrees, below); with `.claude/*` the folder itself is not ignored.
    (".claude/\n!.claude/settings.local.json\n", None),
    (".claude/*\n!.claude/settings.local.json\n", ".gitignore does not ignore it"),
])
def test_settings_local_gitignore_cases(tmp_path: Path, gitignore: str | None, reported: str | None) -> None:
    _settings(tmp_path, "Bash(git status)", gitignore=gitignore)
    found = [f.evidence for f in _rule(scan(tmp_path)[0], "AAK-SECRET-011")]
    assert found == ([] if reported is None else [f"{SETTINGS} exists but {reported}"])


def test_a_gitignore_inside_the_claude_folder_counts(tmp_path: Path) -> None:
    _settings(tmp_path, "Bash(git status)", gitignore="node_modules/\n")
    (tmp_path / ".claude" / ".gitignore").write_text("settings.local.json\n")
    assert _rule(scan(tmp_path)[0], "AAK-SECRET-011") == []
    (tmp_path / ".gitignore").unlink()
    assert _rule(scan(tmp_path)[0], "AAK-SECRET-011") == []


def test_no_settings_local_no_finding(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}")
    assert _rule(scan(tmp_path)[0], "AAK-SECRET-011") == []


def test_aak_secret_006_is_unchanged_by_the_settings_file(tmp_path: Path) -> None:
    _settings(tmp_path, "Bash(git status)", gitignore=".claude/\n")
    (tmp_path / ".env").write_text("A=1\n")
    assert [f.evidence for f in _rule(scan(tmp_path)[0], "AAK-SECRET-006")] == [
        ".env exists but .gitignore does not ignore it"
    ]


# Each case's expected answer is git's own (`git check-ignore --no-index`), as the
# AAK-SECRET-006 cases in test_secret_exposure.py are: (root .gitignore, .claude/.gitignore).
_GIT_CASES = [
    ("", None), (".claude/\n", None), ("settings.local.json\n", None), ("/settings.local.json\n", None),
    (".claude/\n!.claude/settings.local.json\n", None), (".claude/*\n!.claude/settings.local.json\n", None),
    (".claude/**\n", None), (".claude/**\n!.claude/settings.local.json\n", None), ("**/settings.local.json\n", None),
    ("/.claude/settings.local.json\n", None), (".claude\n", None), ("*.local.json\n", None),
    (".claude/settings.local.json/\n", None), ("settings.*.json\n", None), ("*\n!.claude/\n", None),
    ("*\n!.claude/\n!.claude/*\n", None), ("claude/\n", None), (".claude/settings.json\n", None),
    (".claude/\n!.claude/\n", None), ("**/.claude/\n", None), (".claude/**/settings.local.json\n", None),
    ("\\#.claude/\n", None), (".claude/settings.local.json\n", None), ("/.claude/\n", None),
    (".c*e/\n", None), (".claude/s*n\n", None), (".claude/[s]ettings.local.json\n", None),
    ("**/.claude/**\n", None), ("*/settings.local.json\n", None), ("/*/settings.local.json\n", None),
    ("settings.local.json/\n", None), (".claude/settings.local.json\r\n", None), ("  .claude/\n", None),
    ("", "settings.local.json\n"), ("", "*\n"), ("", "/settings.local.json\n"), (".claude/\n", "!settings.local.json\n"),
    ("settings.local.json\n", "!settings.local.json\n"), ("", "settings.json\n"), ("", "**/settings.local.json\n"),
]


def _git_ignores(root: Path) -> bool:
    home = root.parent / "git-home"
    home.mkdir(exist_ok=True)
    env = {**os.environ, "HOME": str(home), "XDG_CONFIG_HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"}
    result = subprocess.run(
        ["git", "-C", str(root), "-c", "core.excludesFile=", "-c", "core.ignorecase=false",
         "check-ignore", "-q", "--no-index", SETTINGS],
        env=env, capture_output=True,
    )
    assert result.returncode in (0, 1), result.stderr
    return result.returncode == 0


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git to say what git ignores")
@pytest.mark.parametrize(("root_ignore", "folder_ignore"), _GIT_CASES, ids=repr)
def test_aak_secret_011_reads_gitignore_as_git_does(tmp_path: Path, root_ignore: str, folder_ignore: str | None) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    _settings(root, "Bash(git status)", gitignore=root_ignore)
    if folder_ignore is not None:
        (root / ".claude" / ".gitignore").write_text(folder_ignore)
    assert (_rule(scan(root)[0], "AAK-SECRET-011") == []) == _git_ignores(root)
