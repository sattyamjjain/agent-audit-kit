"""AAK-AGENT-SERVER-NOAUTH-001: an OpenHands sandbox agent server started without a session key.

CVE-2026-112346 (OpenHands Software Agent SDK before 1.52.0, NVD 9.8): the
DockerWorkspace and ApptainerWorkspace launchers start the agent server with
`--host 0.0.0.0` and no session key, so anyone who can reach its port runs shell
commands in the sandbox as root and reads its secrets. Read from the SDK's own
source (OpenHands/software-agent-sdk at v1.51.0, v1.52.0 and v1.59.0):

* The launchers take no key and no bind host. `openhands.workspace.DockerWorkspace`
  (and its subclass `DockerDevWorkspace`) and `openhands.workspace.ApptainerWorkspace`,
  shipped in `openhands-workspace` in lockstep with `openhands-sdk`, always run
  the server with `--host 0.0.0.0`. The server takes its key from the
  `OH_SESSION_API_KEYS_0` environment variable, else `SESSION_API_KEY`, which
  the launchers forward through `forward_env` (by default `["DEBUG",
  "SESSION_API_KEY", "OH_SESSION_API_KEYS_0"]`). With neither set it starts
  without a key: it logs a warning on a wildcard bind and serves anyway. `host`
  is the client's URL, not a bind address.
* 1.52.0 (PR #5209, "publish Docker ports on loopback") changed only the Docker
  launcher: `-p {host_port}:8000` became `-p 127.0.0.1:{host_port}:8000` (the VS
  Code port 8001 too), and its client now sends the forwarded key; before, it
  sent none. Without a key set the server still starts without one, reachable
  from the host alone.
* ApptainerWorkspace is the same in 1.51.0 and 1.52.0, and in 1.59.0 still runs
  the server with `--host 0.0.0.0` on the host's own network; its client sends
  `SESSION_API_KEY` only.

What it reads (outside `SKIP_DIRS`):

1. Python source that constructs one of the launchers, imported from
   `openhands.workspace` or one of its modules, in a file that sets neither key
   variable (`os.environ[...] =`, `setdefault`, `update`, `putenv`), or with a
   literal `forward_env` that leaves both out, so no key can reach the server.
   A Docker launcher is HIGH when the project locks, pins exactly or has
   installed an `openhands-workspace` or `openhands-sdk` release below 1.52.0,
   else MEDIUM; an Apptainer launcher is HIGH in every release.
2. A compose service running the SDK's image, `ghcr.io/openhands/agent-server`,
   that publishes its port 8000 or 8001 on every interface and sets neither key
   variable: MEDIUM.
3. A `docker run` or `podman run` of that image in a shell script, read the same
   way: MEDIUM.

A key set where this cannot see it (the shell that runs the code, an `env_file`,
the agent-server config file) is not seen; a compose service with an `env_file`,
a call with `**` arguments and a non-literal `forward_env` are not judged.
NVIDIA's NeMo Agent Toolkit advisory of the same week (missing authentication)
names no component, so this rule has no shape for it.
"""

from __future__ import annotations

import ast
import dataclasses
import os
import re
from pathlib import Path
from typing import Any, Callable

import yaml

from agent_audit_kit.malicious_feed import pep440_order
from agent_audit_kit.models import Finding, Severity

from ._dependency_pins import read_text
from ._helpers import (
    CONFIG_MAX_BYTES,
    SKIP_DIRS,
    SOURCE_MAX_BYTES,
    load_yaml,
    make_finding,
    parse_python,
    placed,
    read_text_capped,
)
from ._manifest_deps import MAX_LOCKFILE_BYTES
from ._site_packages import site_entries, site_package_dirs
from .malicious_releases import _LOCKFILES, _REGISTRY, _declared, _is_manifest, exact_pin
from .mcp_cve_pins_2026_07 import _lockfile_raw_entries

RULE = "AAK-AGENT-SERVER-NOAUTH-001"
#: The release whose Docker launcher publishes the server on loopback only.
FIXED = "1.52.0"
_DISTRIBUTIONS = frozenset({"openhands-workspace", "openhands-sdk"})
_CLASSES = {"DockerWorkspace": "docker", "DockerDevWorkspace": "docker", "ApptainerWorkspace": "apptainer"}
_KEY_VARIABLES = ("OH_SESSION_API_KEYS_0", "SESSION_API_KEY")
_PACKAGE = "openhands.workspace"
_IMAGE = "ghcr.io/openhands/agent-server"
_IMAGE_RE = re.compile(r"^ghcr\.io/openhands/agent-server(?:[:@]|$)", re.I)
_SERVER_PORTS = frozenset({8000, 8001})
_RUN_RE = re.compile(r"\b(?:docker|podman)\s+(?:container\s+)?run\b")
_PUBLISH_RE = re.compile(r"(?:^|\s)(?:-p|--publish)(?:=|\s+)(\S+)")
_ENV_RE = re.compile(r"(?:^|\s)(?:-e|--env)(?:=|\s+)[\"']?(?:OH_SESSION_API_KEYS_0|SESSION_API_KEY)\b")
_ENV_FILE_RE = re.compile(r"(?:^|\s)--env-file\b")
_WHY_UNSET = "nothing in this file sets SESSION_API_KEY or OH_SESSION_API_KEYS_0"
_WHY_NOT_FORWARDED = ("its `forward_env` leaves out SESSION_API_KEY and OH_SESSION_API_KEYS_0, so no key reaches "
                      "the server whatever the environment holds")


# ---- the release the project runs ------------------------------------------------------------------


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _releases(project_root: Path, lockfiles: list[Path], manifests: list[Path]) -> list[str]:
    """Every `openhands-workspace` or `openhands-sdk` release the project locks, pins
    exactly or has installed (the two ship in lockstep)."""
    found: list[str] = []
    for path in lockfiles:
        _, reader_name = _LOCKFILES[path.name.lower()]
        text = read_text(path, MAX_LOCKFILE_BYTES)
        if text is not None:
            for rows in _lockfile_raw_entries(text, reader_name, _DISTRIBUTIONS).values():
                found.extend(version for _, version in rows if version)
    for path in manifests:
        declared = _declared(path)
        for declaration in declared[0] if declared else ():
            if _REGISTRY.get(declaration.ecosystem or "") == "PyPI" and _canonical(declaration.name) in _DISTRIBUTIONS:
                pinned = exact_pin(declaration)
                if pinned:
                    found.append(pinned)
    for site_dir in site_package_dirs(project_root):
        for entry in site_entries(site_dir):
            if not entry.name.endswith(".dist-info"):
                continue
            name, sep, version = entry.name[: -len(".dist-info")].rpartition("-")
            if sep and _canonical(name) in _DISTRIBUTIONS:
                found.append(version)
    return found


def _lowest(releases: list[str]) -> str | None:
    keyed = [(key, release) for release in releases if (key := pep440_order(release)) is not None]
    return min(keyed)[1] if keyed else None


# ---- Python launchers ---------------------------------------------------------------------------


def _dotted(node: ast.AST) -> str | None:
    """`a.b.c` for a chain of attributes on a name, else None (iteratively)."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _bindings(tree: ast.Module) -> tuple[dict[str, str], set[str]]:
    """(local name -> launcher class, dotted names bound to `openhands.workspace` modules)."""
    classes: dict[str, str] = {}
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module == _PACKAGE or node.module.startswith(_PACKAGE + "."):
                for alias in node.names:
                    if alias.name in _CLASSES:
                        classes[alias.asname or alias.name] = alias.name
                    elif alias.name in ("docker", "apptainer"):
                        modules.add(alias.asname or alias.name)
            elif node.module == "openhands":
                modules.update(alias.asname or "workspace" for alias in node.names if alias.name == "workspace")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == _PACKAGE or alias.name.startswith(_PACKAGE + "."):
                    modules.add(alias.asname or alias.name)
    return classes, modules


def _launcher(call: ast.Call, classes: dict[str, str], modules: set[str]) -> str | None:
    """The launcher class a call constructs, or None."""
    func = call.func
    if isinstance(func, ast.Name):
        return classes.get(func.id)
    if isinstance(func, ast.Attribute) and func.attr in _CLASSES and _dotted(func.value) in modules:
        return func.attr
    return None


def _string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _sets_a_key(tree: ast.Module) -> bool:
    """Does the module set `OH_SESSION_API_KEYS_0` or `SESSION_API_KEY` in its
    environment: `os.environ[...] = ...`, `os.environ.setdefault(...)`,
    `os.environ.update(...)` or `os.putenv(...)`?"""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Subscript) and _string(t.slice) in _KEY_VARIABLES for t in targets):
                return True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in ("setdefault", "putenv") and node.args and _string(node.args[0]) in _KEY_VARIABLES:
                return True
            if attr == "update" and (
                any(kw.arg in _KEY_VARIABLES for kw in node.keywords)
                or any(isinstance(a, ast.Dict) and any(_string(k) in _KEY_VARIABLES for k in a.keys) for a in node.args)
            ):
                return True
    return False


def _keyless(call: ast.Call, sets_a_key: bool) -> str | None:
    """Why no key reaches the server this call starts, or None when one may."""
    if any(kw.arg is None for kw in call.keywords):
        return None  # `**options` may pass anything
    forwarded = next((kw.value for kw in call.keywords if kw.arg == "forward_env"), None)
    if forwarded is not None:
        if not isinstance(forwarded, (ast.List, ast.Tuple)):
            return None  # not judged
        if not {_string(element) for element in forwarded.elts} & set(_KEY_VARIABLES):
            return _WHY_NOT_FORWARDED
    return None if sets_a_key else _WHY_UNSET


def _launch_evidence(launcher: str, file_name: str, why: str, lowest: Callable[[], str | None]) -> tuple[str, str]:
    head = f"`{launcher}(...)` in {file_name} starts the OpenHands agent server without a session key ({why})"
    if _CLASSES[launcher] == "apptainer":
        return (f"{head}. ApptainerWorkspace runs it with `--host 0.0.0.0` on the host's own network, so anyone "
                "who can reach the port runs commands in the sandbox and reads its secrets (CVE-2026-112346). "
                "1.52.0 changed only the Docker launcher; this one binds every interface in every release "
                "through 1.59.0. Set SESSION_API_KEY where it runs.", "HIGH")
    release = lowest()
    key = pep440_order(release) if release else None
    fixed = pep440_order(FIXED)
    if key is not None and fixed is not None and key < fixed:
        return (f"{head}, and the project runs openhands-workspace or openhands-sdk {release}, whose Docker "
                "launcher publishes port 8000 on every host interface: anyone who can reach it runs commands in "
                "the sandbox as root and reads its secrets (CVE-2026-112346). Upgrade to 1.52.0 or later, which "
                "publishes it on 127.0.0.1, and set SESSION_API_KEY where it runs.", "HIGH")
    if key is not None:
        where = (f"the project runs {release}, which publishes port 8000 on 127.0.0.1 only, so the keyless "
                 "server is reachable from this host alone, by any local process or user")
    else:
        where = ("from 1.52.0 the port is published on 127.0.0.1 only, so the keyless server is reachable from "
                 "this host alone; below 1.52.0 it is published on every interface (CVE-2026-112346), and no "
                 "locked, pinned or installed openhands-workspace release says which one runs")
    return f"{head}: {where}. Set SESSION_API_KEY where it runs.", "MEDIUM"


def _python_findings(path: Path, rel: str, lowest: Callable[[], str | None]) -> list[Finding] | None:
    """The file's findings; None when it is not read past the cheap test for a launcher."""
    try:
        text = read_text_capped(path, SOURCE_MAX_BYTES)
    except (OSError, UnicodeDecodeError):
        return None
    if _PACKAGE not in text or not any(name in text for name in _CLASSES):
        return None
    try:
        tree = parse_python(text, path)
    except (SyntaxError, ValueError):
        return None
    classes, modules = _bindings(tree)
    if not classes and not modules:
        return []
    sets_a_key = _sets_a_key(tree)
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        launcher = _launcher(node, classes, modules)
        why = None if launcher is None else _keyless(node, sets_a_key)
        if launcher is None or why is None:
            continue
        evidence, level = _launch_evidence(launcher, path.name, why, lowest)
        findings.append(_finding(rel, evidence, node.lineno, level))
    findings.sort(key=lambda f: f.line_number or 0)
    return findings


# ---- compose services and docker run lines ---------------------------------------------------------


def _all_interfaces(host_ip: str) -> bool:
    ip = host_ip.strip().strip("[]")
    return not (ip.startswith("127.") or ip in ("::1", "localhost"))


def _exposed(entry: Any) -> str | None:
    """The mapping as written when it publishes port 8000 or 8001 on every interface.

    Short syntax: `8000`, `8000:8000`, `0.0.0.0:8000:8000`, `[::1]:8000:8000`,
    `8000-8001:8000-8001/tcp`; long syntax: `{target: 8000, host_ip: ...}`.
    """
    if isinstance(entry, dict):
        target = entry.get("target")
        if isinstance(target, (int, str)) and not isinstance(target, bool) and str(target).isdigit() \
                and int(target) in _SERVER_PORTS and _all_interfaces(str(entry.get("host_ip") or "")):
            return str(target)
        return None
    if not isinstance(entry, (str, int)) or isinstance(entry, bool):
        return None
    parts = str(entry).strip().split("/", 1)[0].rsplit(":", 2)
    low, _, high = parts[-1].partition("-")
    if not low.isdigit() or (high and not high.isdigit()):
        return None
    first, last = int(low), int(high or low)
    covers = any(first <= port <= last for port in _SERVER_PORTS)
    return str(entry) if covers and _all_interfaces(parts[0] if len(parts) == 3 else "") else None


def _service_keyed(service: dict[str, Any]) -> bool:
    """Does the service set a key variable, or read an `env_file` that may?"""
    if service.get("env_file"):
        return True
    environment = service.get("environment")
    if isinstance(environment, dict):
        return any(str(k) in _KEY_VARIABLES for k in environment)
    if isinstance(environment, list):
        return any(isinstance(e, str) and e.split("=", 1)[0].strip() in _KEY_VARIABLES for e in environment)
    return False


def _compose_findings(path: Path, rel: str) -> list[Finding] | None:
    """The file's findings; None when it does not name the image or does not parse."""
    try:
        text = read_text_capped(path, CONFIG_MAX_BYTES)
    except (OSError, UnicodeDecodeError):
        return None
    if "agent-server" not in text:
        return None
    try:
        data = load_yaml(text, path)
    except (yaml.YAMLError, ValueError):
        return None
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return []
    pending: list[tuple[Finding, str]] = []
    for name, service in sorted(services.items(), key=lambda item: str(item[0])):
        if not isinstance(service, dict) or not _IMAGE_RE.match(str(service.get("image") or "")):
            continue
        ports = service.get("ports")
        published = [m for m in map(_exposed, ports) if m] if isinstance(ports, list) else []
        if not published or _service_keyed(service):
            continue
        # Placed on the service's own key (`placed`, one pass): placed by its port
        # string, every service publishing "8000:8000" would land on the first one's
        # line, and code scanning folds findings on one line into one alert (#792).
        pending.append((_finding(
            rel,
            f"service `{name}` in {path.name} runs {service['image']} and publishes its port on every interface "
            f"(`{published[0]}`) without SESSION_API_KEY or OH_SESSION_API_KEYS_0 in its environment: the "
            "OpenHands agent server then accepts unauthenticated requests that run commands in the sandbox "
            "(CVE-2026-112346). Publish it on 127.0.0.1, or set SESSION_API_KEY.",
            None,
            "MEDIUM",
        ), f"{name}:"))
    return placed(text, pending)


def _commands(text: str) -> list[tuple[int, str]]:
    """(first line, command) for each shell command, `\\`-continued lines joined once."""
    out: list[tuple[int, str]] = []
    pieces: list[str] = []
    start = 1
    for number, line in enumerate(text.split("\n"), 1):
        if not pieces:
            start = number
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pieces.append(stripped[:-1])
            continue
        pieces.append(line)
        out.append((start, " ".join(pieces)))
        pieces = []
    if pieces:
        out.append((start, " ".join(pieces)))
    return out


def _script_findings(path: Path, rel: str) -> list[Finding] | None:
    """The file's findings; None when it does not name the image."""
    try:
        text = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
    except OSError:
        return None
    if "agent-server" not in text:
        return None
    findings: list[Finding] = []
    for start, command in _commands(text):
        if _IMAGE not in command.lower() or not _RUN_RE.search(command):
            continue
        if _ENV_RE.search(command) or _ENV_FILE_RE.search(command):
            continue
        exposed = next((spec for spec in _PUBLISH_RE.findall(command) if _exposed(spec.strip("\"'"))), None)
        if exposed is None:
            continue
        findings.append(_finding(
            rel,
            f"`docker run` of {_IMAGE} in {path.name} publishes its port on every interface (`-p {exposed}`) "
            "without passing SESSION_API_KEY or OH_SESSION_API_KEYS_0: the OpenHands agent server then accepts "
            "unauthenticated requests that run commands in the sandbox (CVE-2026-112346). Publish it on "
            "127.0.0.1, or pass SESSION_API_KEY.",
            start,
            "MEDIUM",
        ))
    return findings


# ---- the scan -----------------------------------------------------------------------------------------


def _finding(rel: str, evidence: str, line: int | None, level: str) -> Finding:
    finding = make_finding(RULE, rel, evidence, line)
    severity = Severity.HIGH if level == "HIGH" else Severity.MEDIUM
    return finding if finding.severity is severity else dataclasses.replace(finding, severity=severity)


def _files(project_root: Path) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {"python": [], "yaml": [], "script": [], "lockfile": [], "manifest": []}
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            low, path = name.lower(), Path(dirpath) / name
            if low.endswith(".py"):
                found["python"].append(path)
            elif low.endswith((".yml", ".yaml")):
                found["yaml"].append(path)
            elif low.endswith(".sh"):
                found["script"].append(path)
            if low in _LOCKFILES:
                found["lockfile"].append(path)
            elif _is_manifest(name):
                found["manifest"].append(path)
    return found


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report OpenHands agent servers started, run or published without a session key.

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    files = _files(project_root)
    resolved: list[str | None] = []

    def lowest() -> str | None:
        """The lowest release the project runs, read once, when a Docker launcher needs it."""
        if not resolved:
            resolved.append(_lowest(_releases(project_root, files["lockfile"], files["manifest"])))
        return resolved[0]

    findings: list[Finding] = []
    scanned: set[str] = set()
    for kind in ("python", "yaml", "script"):
        for path in files[kind]:
            rel = path.relative_to(project_root).as_posix()
            if kind == "python":
                found = _python_findings(path, rel, lowest)
            elif kind == "yaml":
                found = _compose_findings(path, rel)
            else:
                found = _script_findings(path, rel)
            if found is not None:
                scanned.add(rel)
                findings.extend(found)
    return findings, scanned


__all__ = ["FIXED", "RULE", "scan"]
