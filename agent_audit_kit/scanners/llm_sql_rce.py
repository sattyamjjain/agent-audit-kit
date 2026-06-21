"""LLM-generated-SQL → privileged-executor RCE scanner — CVE-2026-25879 class.

An agent / LLM application that feeds **model-generated SQL** straight into a
database executor becomes a remote-code-execution surface when the connection
role holds code-execution / filesystem privileges. The DBMS itself provides the
escalation primitive once arbitrary SQL runs:

  * PostgreSQL — ``COPY ... FROM PROGRAM`` / ``COPY ... TO PROGRAM`` and the
    ``pg_execute_server_program`` / ``pg_read_server_files`` /
    ``pg_write_server_files`` roles (shell + filesystem).
  * MySQL / MariaDB — the ``FILE`` privilege: ``LOAD_FILE()``,
    ``INTO OUTFILE`` / ``INTO DUMPFILE``, ``LOAD DATA INFILE``.
  * MS SQL Server — ``xp_cmdshell`` / ``sp_OACreate``.

CVE-2026-25879 is the documented instance (a text-to-SQL "chat with your
database" agent ran LLM output on a superuser connection; a prompt-injected
``COPY ... FROM PROGRAM`` yielded shell). This is **CWE-94 (Code Injection)** /
**CWE-89 (SQL Injection)** chained to **CWE-78 (OS Command Injection)** via an
over-privileged DB role.

Two detection arms (both emit ``AAK-LLM-SQL-RCE-001``):

  (a) **Flow** — an LLM-output value reaches a SQL-execution sink
      (``cursor.execute`` / ``conn.execute`` / SQLAlchemy ``text(...)``) as the
      *query itself* (not a bound parameter), with no allow-list /
      query-validation step in the file. Python is analysed with stdlib
      ``ast`` (taint fixpoint over assignments); TS/JS uses guarded regex.

  (b) **Privilege** — a DB connection string / role that grants the dangerous
      primitives above (superuser connection account, or a literal
      ``FROM PROGRAM`` / ``xp_cmdshell`` / ``GRANT ... FILE`` in the source),
      inside a file that also carries LLM / agent context.

FP guards: a parameterised query (LLM value only in the params tuple), a
validated / allow-listed flow (``sqlglot`` / ``sqlparse`` / explicit SELECT
guard), a least-privilege connection role, and non-agent DB-admin scripts all
PASS. This rule is deliberately distinct from ``AAK-TAINT-005`` (tool *parameter*
→ SQL string-format injection) — here the tainted source is *LLM output* and the
sink role is *RCE-capable*.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

_RULE_ID = "AAK-LLM-SQL-RCE-001"

# --- LLM-output seeds -------------------------------------------------------
# Specific provider/framework APIs that return model text directly.
_LLM_API_RE = re.compile(
    r"chat\.completions\.create"
    r"|\.responses\.create"
    r"|messages\.create"
    r"|\.choices\b"
    r"|generate_sql|text2sql|nl2sql|natural_language_to_sql"
    r"|SQLDatabaseChain|create_sql_query_chain",
    re.IGNORECASE,
)
# Generic "object that looks like an LLM" + "generation verb" — both required
# together so a plain ``db.run(...)`` or ``q.call(...)`` does not seed taint.
_LLM_OBJ_RE = re.compile(
    r"\bllm\b|\bmodel\b|\bchain\b|openai|anthropic|\bgpt\b|claude|gemini"
    r"|\bchat\b|\bagent\b|completion|\bclient\b",
    re.IGNORECASE,
)
_GEN_VERB_RE = re.compile(
    r"\b(invoke|ainvoke|predict|apredict|generate|agenerate|complete|acomplete"
    r"|run|arun|ask|chat|query|create|completions|call)\s*\(",
    re.IGNORECASE,
)

# --- SQL execution sinks (Python attribute names) ---------------------------
_SQL_EXEC_ATTRS = {"execute", "executescript", "executemany", "exec_driver_sql"}

# --- Allow-list / query-validation markers (suppress arm (a) for the file) --
_VALIDATION_RE = re.compile(
    r"sqlglot|sqlparse"
    r"|allow[_-]?list|allowlist|whitelist"
    r"|is_select_only|only_select|validate_sql|assert_select|guard_sql"
    r"|ALLOWED_(?:STATEMENTS|QUERIES|TABLES)",
    re.IGNORECASE,
)

# --- Arm (b): dangerous DB privileges / RCE primitives ----------------------
_DANGEROUS_SQL_RE = re.compile(
    r"COPY\b[^;]*?\bFROM\s+PROGRAM"
    r"|COPY\b[^;]*?\bTO\s+PROGRAM"
    r"|pg_execute_server_program|pg_read_server_files|pg_write_server_files"
    r"|xp_cmdshell|sp_OACreate"
    r"|INTO\s+OUTFILE|INTO\s+DUMPFILE|LOAD_FILE\s*\(|LOAD\s+DATA\s+INFILE"
    r"|GRANT\s+(?:ALL|FILE|SUPERUSER)\b"
    r"|ALTER\s+(?:USER|ROLE)\b[^;]*?SUPERUSER|WITH\s+SUPERUSER",
    re.IGNORECASE,
)
# A connection URI authenticating as a known superuser account.
_SUPERUSER_CONN_RE = re.compile(
    r"(?:postgres(?:ql)?|mysql|mariadb|mssql|sqlserver|jdbc:[a-z]+)://"
    r"(?:postgres|root|sa|admin|superuser)(?::[^@/\s]*)?@",
    re.IGNORECASE,
)
# LLM / agent context required for arm (b) to fire (keeps it off plain
# DB-admin scripts that legitimately manage server-program roles).
_AGENT_CTX_RE = re.compile(
    r"\bllm\b|langchain|langgraph|llama_?index|openai|anthropic|\bagent\b"
    r"|chat.?bot|text2sql|nl2sql|\.invoke\s*\(|completions|messages\.create"
    r"|SQLDatabase|prompt",
    re.IGNORECASE,
)


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


# ---------------------------------------------------------------------------
# Python (AST) — arm (a)
# ---------------------------------------------------------------------------


def _is_llm_output(rhs_src: str) -> bool:
    if _LLM_API_RE.search(rhs_src):
        return True
    return bool(_LLM_OBJ_RE.search(rhs_src) and _GEN_VERB_RE.search(rhs_src))


def _target_names(target: ast.expr) -> list[str]:
    out: list[str] = []
    if isinstance(target, ast.Name):
        out.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            out.extend(_target_names(elt))
    return out


def _has_validation_py(tree: ast.AST) -> bool:
    """True if the module references a SQL allow-list / validation marker as
    real code (identifier, attribute, or string literal). AST-based so a
    comment like ``# no allowlist here`` cannot suppress the rule."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and _VALIDATION_RE.search(node.id):
            return True
        if isinstance(node, ast.Attribute) and _VALIDATION_RE.search(node.attr):
            return True
        if isinstance(node, ast.alias):
            target = node.asname or node.name
            if _VALIDATION_RE.search(target):
                return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _VALIDATION_RE.search(node.value):
                return True
    return False


def _collect_tainted(tree: ast.AST) -> set[str]:
    """Names bound (directly or transitively) to LLM-generated output."""
    assigns: list[ast.Assign | ast.AnnAssign] = [
        n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign))
    ]
    tainted: set[str] = set()
    for _ in range(6):  # fixpoint, bounded against pathological inputs
        changed = False
        for node in assigns:
            value = node.value
            if value is None:
                continue
            targets: list[str] = []
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    targets.extend(_target_names(t))
            else:
                targets.extend(_target_names(node.target))
            if not targets:
                continue
            try:
                rhs_src = ast.unparse(value)
            except Exception:
                rhs_src = ""
            refs_tainted = any(
                isinstance(x, ast.Name) and x.id in tainted
                for x in ast.walk(value)
            )
            if _is_llm_output(rhs_src) or refs_tainted:
                for name in targets:
                    if name not in tainted:
                        tainted.add(name)
                        changed = True
        if not changed:
            break
    return tainted


def _arm_a_python(text: str) -> int | None:
    """Return the line of the first LLM-tainted SQL execution, else None."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    if _has_validation_py(tree):
        return None
    tainted = _collect_tainted(tree)
    if not tainted:
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        attr = func.attr if isinstance(func, ast.Attribute) else ""
        if attr.lower() not in _SQL_EXEC_ATTRS:
            continue
        query_arg = node.args[0]  # the query itself, not the params tuple
        if any(
            isinstance(x, ast.Name) and x.id in tainted
            for x in ast.walk(query_arg)
        ):
            return node.lineno
    return None


# ---------------------------------------------------------------------------
# TS / JS — arm (a) (guarded regex)
# ---------------------------------------------------------------------------

_TS_LLM_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?([^;\n]+)",
)
_TS_EXEC_RE = re.compile(
    r"\.(?:query|execute|raw|unsafe)\s*\(\s*([^,;)]+)",
    re.IGNORECASE,
)


_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_ts_comments(text: str) -> str:
    # Preserve newline count so reported line numbers stay accurate.
    text = _TS_BLOCK_COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    return _TS_LINE_COMMENT_RE.sub("", text)


def _arm_a_ts(text: str) -> int | None:
    text = _strip_ts_comments(text)
    if _VALIDATION_RE.search(text):
        return None
    tainted: set[str] = set()
    for m in _TS_LLM_ASSIGN_RE.finditer(text):
        name, rhs = m.group(1), m.group(2)
        if _is_llm_output(rhs) or any(t in rhs for t in tainted):
            tainted.add(name)
    if not tainted:
        return None
    for m in _TS_EXEC_RE.finditer(text):
        arg = m.group(1)
        if any(re.search(rf"\b{re.escape(t)}\b", arg) for t in tainted):
            return _line_of(text, m.start())
    return None


# ---------------------------------------------------------------------------
# Arm (b) — dangerous privilege / role (Python + TS/JS, text regex)
# ---------------------------------------------------------------------------


def _arm_b(text: str) -> tuple[int, str] | None:
    if not _AGENT_CTX_RE.search(text):
        return None
    for rx in (_DANGEROUS_SQL_RE, _SUPERUSER_CONN_RE):
        m = rx.search(text)
        if m:
            return _line_of(text, m.start()), m.group(0).strip()
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for LLM-generated-SQL → privileged-executor RCE (CVE-2026-25879).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _PY_SUFFIXES + _TS_SUFFIXES:
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_path = str(path.relative_to(project_root))

        if path.suffix in _PY_SUFFIXES:
            flow_line = _arm_a_python(text)
        else:
            flow_line = _arm_a_ts(text)
        priv = _arm_b(text)

        if flow_line is None and priv is None:
            continue
        scanned_files.add(rel_path)

        if flow_line is not None:
            findings.append(make_finding(
                _RULE_ID,
                rel_path,
                (
                    "LLM-generated text flows into a SQL execution sink as the "
                    "query itself, with no allow-list / query-validation step. "
                    "On an RCE-capable DB role a prompt-injected "
                    "`COPY ... FROM PROGRAM` / `xp_cmdshell` / `INTO OUTFILE` "
                    "yields code execution (CVE-2026-25879, CWE-94→CWE-78)."
                ),
                flow_line,
            ))
        if priv is not None:
            line, evidence = priv
            findings.append(make_finding(
                _RULE_ID,
                rel_path,
                (
                    "Database connection / role grants code-execution or "
                    "filesystem privileges (`" + evidence + "`) in an LLM/agent "
                    "context. If model-generated SQL ever reaches this "
                    "connection, the role turns SQL injection into RCE. Use a "
                    "least-privilege, read-only role (CVE-2026-25879, CWE-250)."
                ),
                line,
            ))

    return findings, scanned_files
