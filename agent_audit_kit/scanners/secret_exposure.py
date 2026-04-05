from __future__ import annotations

import json
import math
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding

# API key patterns
ANTHROPIC_KEY = re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}")
OPENAI_KEY = re.compile(r"sk-[a-zA-Z0-9]{20,}")
AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
AWS_SECRET_KEY = re.compile(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}")
GITHUB_TOKEN = re.compile(r"ghp_[a-zA-Z0-9]{36}")
GITLAB_TOKEN = re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}")
GCP_SERVICE_ACCOUNT = re.compile(r'"type"\s*:\s*"service_account"')

# Secret key name patterns
SECRET_KEY_NAMES = re.compile(
    r"(SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|API_KEY)", re.IGNORECASE
)

# Private key file extensions
PRIVATE_KEY_EXTENSIONS = frozenset({".pem", ".key", ".p12", ".pfx"})
PRIVATE_KEY_FILENAMES = frozenset({"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"})
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY-----")

# MCP server env secret patterns (for non-mcp config files)
MCP_ENV_SECRET_KEYS = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY|ANTHROPIC|OPENAI|AWS_)", re.IGNORECASE
)

# Directories to skip
SKIP_DIRS = frozenset({
    "node_modules", ".git", "dist", "build", "__pycache__",
    ".next", ".nuxt", "vendor", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "target", "out", ".terraform",
})

# File extensions to scan for secrets
SCANNABLE_EXTENSIONS = frozenset({
    ".env", ".json", ".yml", ".yaml", ".toml", ".cfg",
    ".ini", ".conf", ".xml", ".properties", ".sh", ".bash",
    ".zsh", ".py", ".js", ".ts", ".rb", ".go", ".rs",
    ".java", ".kt", ".swift", ".dockerfile", ".tf", ".hcl",
})

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


_find_line_number = find_line_number
_make_finding = make_finding


def _should_scan_file(path: Path) -> bool:
    name = path.name
    suffix = path.suffix.lower()
    # Always scan .env files
    if name.startswith(".env") or name.endswith(".env"):
        return True
    if suffix in SCANNABLE_EXTENSIONS:
        return True
    if "mcp" in name.lower() and suffix == ".json":
        return True
    if name.lower().startswith("dockerfile"):
        return True
    if name.lower().startswith("docker-compose"):
        return True
    return False


def _scan_file_for_secrets(file_path: Path, project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel_path = str(file_path.relative_to(project_root))

    try:
        if file_path.stat().st_size > 1_000_000:
            return findings
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    # AAK-SECRET-001: Anthropic API key
    for match in ANTHROPIC_KEY.finditer(content):
        findings.append(_make_finding(
            "AAK-SECRET-001", rel_path,
            f"Found Anthropic API key: {match.group()[:12]}...",
            _find_line_number(content, match.group()[:12]),
        ))

    # AAK-SECRET-002: OpenAI API key (exclude Anthropic keys)
    for match in OPENAI_KEY.finditer(content):
        if not match.group().startswith("sk-ant-"):
            findings.append(_make_finding(
                "AAK-SECRET-002", rel_path,
                f"Found OpenAI API key: {match.group()[:12]}...",
                _find_line_number(content, match.group()[:12]),
            ))

    # AAK-SECRET-003: AWS credentials
    for match in AWS_ACCESS_KEY.finditer(content):
        findings.append(_make_finding(
            "AAK-SECRET-003", rel_path,
            f"Found AWS access key: {match.group()[:8]}...",
            _find_line_number(content, match.group()[:8]),
        ))
    for match in AWS_SECRET_KEY.finditer(content):
        findings.append(_make_finding(
            "AAK-SECRET-003", rel_path,
            "Found AWS secret access key assignment",
            _find_line_number(content, "aws_secret_access_key"),
        ))

    # AAK-SECRET-008: GitHub/GitLab personal access tokens
    for match in GITHUB_TOKEN.finditer(content):
        findings.append(_make_finding(
            "AAK-SECRET-008", rel_path,
            f"Found GitHub token: {match.group()[:8]}...",
            _find_line_number(content, match.group()[:8]),
        ))
    for match in GITLAB_TOKEN.finditer(content):
        findings.append(_make_finding(
            "AAK-SECRET-008", rel_path,
            f"Found GitLab token: {match.group()[:10]}...",
            _find_line_number(content, match.group()[:10]),
        ))

    # AAK-SECRET-009: Google Cloud service account key
    if GCP_SERVICE_ACCOUNT.search(content) and file_path.suffix == ".json":
        findings.append(_make_finding(
            "AAK-SECRET-009", rel_path,
            "Google Cloud service account key JSON file",
            _find_line_number(content, "service_account"),
        ))

    # AAK-SECRET-004: Generic high-entropy secrets
    for line_num, line in enumerate(content.splitlines(), 1):
        # Look for KEY=VALUE or "KEY": "VALUE" patterns
        kv_patterns = [
            re.findall(r'["\']?(\w*(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|API_KEY)\w*)["\']?\s*[:=]\s*["\']([^"\']+)["\']', line, re.IGNORECASE),
            re.findall(r'(\w*(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|API_KEY)\w*)\s*=\s*(\S+)', line, re.IGNORECASE),
        ]
        for matches in kv_patterns:
            for key, value in matches:
                # Skip variable references and short values
                if value.startswith("${") or value.startswith("$") or len(value) < 16:
                    continue
                # Skip common non-secret values
                if value.lower() in ("true", "false", "null", "none", "undefined"):
                    continue
                entropy = _shannon_entropy(value)
                if entropy > 4.5:
                    findings.append(_make_finding(
                        "AAK-SECRET-004", rel_path,
                        f"{key} = (high entropy value, Shannon entropy: {entropy:.2f})",
                        line_num,
                    ))

    # AAK-SECRET-007: Secret in MCP server environment block (for non-.mcp.json files)
    if file_path.suffix == ".json" and file_path.name != ".mcp.json":
        try:
            data = json.loads(content)
            servers = data.get("mcpServers", {})
            if isinstance(servers, dict):
                for server_name, server_cfg in servers.items():
                    if isinstance(server_cfg, dict):
                        env = server_cfg.get("env", {})
                        if isinstance(env, dict):
                            for key, value in env.items():
                                if MCP_ENV_SECRET_KEYS.search(key) and isinstance(value, str):
                                    if not re.match(r"^\$\{.+\}$", value) and value:
                                        findings.append(_make_finding(
                                            "AAK-SECRET-007", rel_path,
                                            f"Server '{server_name}' env.{key} = (hardcoded value)",
                                            _find_line_number(content, key),
                                        ))
        except (json.JSONDecodeError, AttributeError):
            pass

    return findings


def _check_private_key_files(project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        name = path.name
        suffix = path.suffix.lower()
        rel_path = str(path.relative_to(project_root))

        if suffix in PRIVATE_KEY_EXTENSIONS or name in PRIVATE_KEY_FILENAMES:
            findings.append(_make_finding(
                "AAK-SECRET-005", rel_path,
                f"Private key file: {name}",
            ))
        elif suffix in (".pem", ".key", ".crt", ".cer"):
            try:
                header = path.read_text(encoding="utf-8", errors="ignore")[:200]
                if PRIVATE_KEY_HEADER.search(header):
                    findings.append(_make_finding(
                        "AAK-SECRET-005", rel_path,
                        "File contains PEM private key header",
                    ))
            except OSError:
                pass
    return findings


def _check_env_gitignore(project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    env_files = list(project_root.glob(".env")) + list(project_root.glob(".env.*"))
    if not env_files:
        return findings

    gitignore = project_root / ".gitignore"
    if not gitignore.is_file():
        for env_file in env_files:
            rel_path = str(env_file.relative_to(project_root))
            findings.append(_make_finding(
                "AAK-SECRET-006", rel_path,
                f"{env_file.name} exists but no .gitignore found",
            ))
        return findings

    try:
        gitignore_content = gitignore.read_text(encoding="utf-8")
    except OSError:
        return findings

    # Check if .env is covered by gitignore patterns
    env_patterns = [".env", ".env*", ".env.*", "*.env"]
    has_env_pattern = any(
        pattern in gitignore_content
        for pattern in env_patterns
    )

    if not has_env_pattern:
        for env_file in env_files:
            rel_path = str(env_file.relative_to(project_root))
            findings.append(_make_finding(
                "AAK-SECRET-006", rel_path,
                f"{env_file.name} exists but .gitignore lacks .env exclusion",
            ))

    return findings


def scan(project_root: Path, ignore_paths: list[str] | None = None) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned_files: set[str] = set()
    ignore_set = set(ignore_paths or [])

    # Scan files for secret patterns
    for path in project_root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        rel = str(path.relative_to(project_root))
        if any(rel.startswith(ip) for ip in ignore_set):
            continue
        if _should_scan_file(path):
            scanned_files.add(rel)
            findings.extend(_scan_file_for_secrets(path, project_root))

    # Check for private key files
    findings.extend(_check_private_key_files(project_root))

    # Check .env + .gitignore
    gitignore = project_root / ".gitignore"
    if gitignore.is_file():
        scanned_files.add(".gitignore")
    findings.extend(_check_env_gitignore(project_root))

    return findings, scanned_files
