from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click
import yaml

from agent_audit_kit import __version__
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

FAIL_ON_CHOICES = ["critical", "high", "medium", "low", "none"]

# Exit codes
EXIT_PASS = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _to_list(value: str | list[str] | None) -> list[str] | None:
    """Normalise a CLI string or YAML list into a Python list.

    Args:
        value: A comma-separated string, a list of strings, or None.

    Returns:
        A list of stripped strings, or None if the input is falsy.
    """
    if not value:
        return None
    if isinstance(value, list):
        return [str(v).strip() for v in value if v]
    return [v.strip() for v in value.split(",") if v.strip()]


def _load_config(config_path: str | None, project_root: Path) -> dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Explicit path to config file, or None for auto-detect.
        project_root: Project root directory for auto-detection.

    Returns:
        Dictionary of configuration values, empty if no config found.
    """
    if config_path:
        p = Path(config_path)
    else:
        p = project_root / ".agent-audit-kit.yml"

    if not p.is_file():
        return {}

    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    return data if isinstance(data, dict) else {}


def _apply_config_defaults(
    config: dict[str, Any],
    output_format: str,
    min_severity: str,
    fail_on: str,
    output_file: str | None,
    include_user_config: bool,
    ignore_paths: str | None,
    rules: str | None,
    exclude_rules: str | None,
    verbose: bool,
    show_score: bool,
    owasp_report: bool,
    compliance: str | None,
    verify_secrets: bool,
    diff_base: str | None,
    llm_scan: bool,
) -> dict[str, Any]:
    """Merge config file defaults with CLI flags. CLI flags take priority.

    Returns:
        Merged settings dictionary.
    """
    # Config file values serve as defaults; CLI-provided values override them.
    # We detect "CLI-provided" by checking against Click's own defaults.
    return {
        "output_format": output_format if output_format != "console" else config.get("format", output_format),
        "min_severity": min_severity if min_severity != "low" else config.get("severity", min_severity),
        "fail_on": fail_on if fail_on is not None else config.get("fail-on", "none"),
        "output_file": output_file or config.get("output", None),
        "include_user_config": include_user_config or config.get("include-user-config", False),
        "ignore_paths": ignore_paths or config.get("ignore-paths", None),
        "rules": rules or config.get("rules", None),
        "exclude_rules": exclude_rules or config.get("exclude-rules", None),
        "verbose": verbose or config.get("verbose", False),
        "show_score": show_score or config.get("score", False),
        "owasp_report": owasp_report or config.get("owasp-report", False),
        "compliance": compliance or config.get("compliance", None),
        "verify_secrets": verify_secrets or config.get("verify-secrets", False),
        "diff_base": diff_base or config.get("diff", None),
        "llm_scan": llm_scan or config.get("llm-scan", False),
    }


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version=__version__)
def cli(ctx: click.Context) -> None:
    """AgentAuditKit -- Security scanner for MCP-connected AI agent pipelines."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan_cmd)


@cli.command("scan")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--format", "output_format", type=click.Choice(["console", "json", "sarif"]), default="console", help="Output format.")
@click.option("--severity", "min_severity", type=click.Choice(["critical", "high", "medium", "low", "info"]), default="low", help="Minimum severity to report.")
@click.option("--output", "-o", "output_file", type=click.Path(), default=None, help="Write report to file.")
@click.option("--include-user-config", is_flag=True, default=False, help="Also scan user-level configs (~/.claude/).")
@click.option("--ignore-paths", default=None, help="Comma-separated paths to skip.")
@click.option("--rules", default=None, help="Comma-separated rule IDs to run (default: all).")
@click.option("--exclude-rules", default=None, help="Comma-separated rule IDs to skip.")
@click.option(
    "--fail-on",
    type=click.Choice(FAIL_ON_CHOICES),
    default=None,
    help="Exit code 1 if any finding meets or exceeds this severity. Default: none.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to .agent-audit-kit.yml config file.",
)
@click.option(
    "--ci",
    is_flag=True,
    default=False,
    help="CI mode shorthand: sets format=sarif, fail-on=high, output=agent-audit-results.sarif.",
)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show detailed scan progress.")
@click.option("--score", "show_score", is_flag=True, default=False, help="Show security score and grade.")
@click.option("--owasp-report", is_flag=True, default=False, help="Show OWASP coverage matrix.")
@click.option("--compliance", default=None, help="Compliance framework: eu-ai-act, soc2, iso27001, hipaa, nist-ai-rmf.")
@click.option("--verify-secrets", is_flag=True, default=False, help="Actively verify if detected secrets are live (makes network calls).")
@click.option("--diff", "diff_base", default=None, help="Only report findings in files changed since BASE_REF (e.g., HEAD~1, main).")
@click.option("--llm-scan", is_flag=True, default=False, help="Use local LLM (Ollama) for semantic tool description analysis.")
@click.option(
    "--strict-loading",
    is_flag=True,
    default=False,
    help="Fail loudly if any optional scanner module cannot be imported. Default: silently skip.",
)
def scan_cmd(
    path: str,
    output_format: str,
    min_severity: str,
    output_file: str | None,
    include_user_config: bool,
    ignore_paths: str | None,
    rules: str | None,
    exclude_rules: str | None,
    fail_on: str,
    config_path: str | None,
    ci: bool,
    verbose: bool,
    show_score: bool,
    owasp_report: bool,
    compliance: str | None,
    verify_secrets: bool,
    diff_base: str | None,
    llm_scan: bool,
    strict_loading: bool,
) -> None:
    """Scan a project for MCP agent security vulnerabilities."""
    try:
        _run_scan(
            path=path,
            output_format=output_format,
            min_severity=min_severity,
            output_file=output_file,
            include_user_config=include_user_config,
            ignore_paths=ignore_paths,
            rules=rules,
            exclude_rules=exclude_rules,
            fail_on=fail_on,
            config_path=config_path,
            ci=ci,
            verbose=verbose,
            show_score=show_score,
            owasp_report=owasp_report,
            compliance=compliance,
            verify_secrets=verify_secrets,
            diff_base=diff_base,
            llm_scan=llm_scan,
            strict_loading=strict_loading,
        )
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(EXIT_ERROR)


def _run_scan(
    *,
    path: str,
    output_format: str,
    min_severity: str,
    output_file: str | None,
    include_user_config: bool,
    ignore_paths: str | None,
    rules: str | None,
    exclude_rules: str | None,
    fail_on: str,
    config_path: str | None,
    ci: bool,
    verbose: bool,
    show_score: bool,
    owasp_report: bool,
    compliance: str | None,
    verify_secrets: bool,
    diff_base: str | None,
    llm_scan: bool,
    strict_loading: bool,
) -> None:
    """Core scan logic, separated for clean exit-code handling."""
    from agent_audit_kit.output import console, json_report, sarif

    project_root = Path(path)

    # --- CI shorthand overrides ---
    if ci:
        output_format = "sarif"
        fail_on = "high"
        output_file = output_file or "agent-audit-results.sarif"

    # --- Config file loading ---
    config = _load_config(config_path, project_root)
    merged = _apply_config_defaults(
        config,
        output_format=output_format,
        min_severity=min_severity,
        fail_on=fail_on,
        output_file=output_file,
        include_user_config=include_user_config,
        ignore_paths=ignore_paths,
        rules=rules,
        exclude_rules=exclude_rules,
        verbose=verbose,
        show_score=show_score,
        owasp_report=owasp_report,
        compliance=compliance,
        verify_secrets=verify_secrets,
        diff_base=diff_base,
        llm_scan=llm_scan,
    )

    # Unpack merged settings
    output_format = merged["output_format"]
    min_severity = merged["min_severity"]
    fail_on = merged["fail_on"]
    output_file = merged["output_file"]
    include_user_config = merged["include_user_config"]
    ignore_paths = merged["ignore_paths"]
    rules = merged["rules"]
    exclude_rules = merged["exclude_rules"]
    verbose = merged["verbose"]
    show_score = merged["show_score"]
    owasp_report = merged["owasp_report"]
    compliance = merged["compliance"]
    verify_secrets = merged["verify_secrets"]
    diff_base = merged["diff_base"]
    llm_scan = merged["llm_scan"]

    if verbose:
        click.echo(f"Scanning {project_root.resolve()}...", err=True)

    parsed_ignore = _to_list(ignore_paths)
    parsed_rules = _to_list(rules)
    parsed_excludes = _to_list(exclude_rules)
    severity = SEVERITY_MAP[min_severity]
    verbose_cb = (lambda msg: click.echo(msg, err=True)) if verbose else None

    result = run_scan(
        project_root=project_root,
        include_user_config=include_user_config,
        ignore_paths=parsed_ignore,
        rules=parsed_rules,
        exclude_rules=parsed_excludes,
        verbose_callback=verbose_cb,
        strict_loading=strict_loading,
    )

    # Diff-aware filtering
    if diff_base:
        from agent_audit_kit.diff import filter_by_diff

        result = filter_by_diff(result, project_root, diff_base)

    # Active secret verification
    if verify_secrets:
        from agent_audit_kit.verification import verify_findings

        result = verify_findings(result)

    # LLM semantic analysis (optional, requires Ollama)
    if llm_scan:
        try:
            from agent_audit_kit.llm_scan import run_llm_analysis

            llm_findings = run_llm_analysis(project_root)
            result.findings.extend(llm_findings)
        except ImportError:
            click.echo("LLM scan requires Ollama. Install with: brew install ollama", err=True)
        except Exception as e:
            click.echo(f"LLM scan failed: {e}", err=True)

    # RUGPULL / pin-drift detection now lives in the scanners/pin_drift.py
    # scanner and runs as part of run_scan() above.

    # Compute score
    if show_score or compliance or owasp_report:
        from agent_audit_kit.scoring import compute_score

        compute_score(result)

    # --- Output ---
    if owasp_report:
        from agent_audit_kit.output.owasp_report import format_results as fmt_owasp

        output = fmt_owasp(result)
    elif compliance:
        from agent_audit_kit.output.compliance import format_results as fmt_compliance

        output = fmt_compliance(result, compliance)
    elif output_format == "json":
        output = json_report.format_results(result, severity)
    elif output_format == "sarif":
        output = sarif.format_results(result, severity)
    else:
        output = console.format_results(result, severity, show_score=show_score)

    if output_file:
        Path(output_file).write_text(output, encoding="utf-8")
        if verbose:
            click.echo(f"Report written to {output_file}", err=True)
    else:
        click.echo(output)

    # --- Fail-on threshold check ---
    if fail_on != "none":
        threshold_severity = SEVERITY_MAP[fail_on]
        exceeding = [f for f in result.findings if f.severity >= threshold_severity]
        if exceeding:
            click.echo("", err=True)
            click.echo(
                f"FAILED: {len(exceeding)} finding(s) exceed --fail-on {fail_on} threshold:",
                err=True,
            )
            for f in exceeding:
                location = f.file_path
                if f.line_number:
                    location = f"{f.file_path}:{f.line_number}"
                click.echo(
                    f"  {f.rule_id} [{f.severity.value.upper()}] {f.title} -> {location}",
                    err=True,
                )
            sys.exit(EXIT_FINDINGS)


@cli.command("discover")
@click.option("--verbose", "-v", is_flag=True, default=False)
def discover_cmd(verbose: bool) -> None:
    """Discover all AI agent configurations on this machine."""
    from agent_audit_kit.discovery import discover_agents

    agents = discover_agents(verbose=verbose)
    if not agents:
        click.echo("No AI agent configurations found.")
        return
    click.echo(f"\nDiscovered {len(agents)} agent configuration(s):\n")
    for agent in agents:
        click.echo(f"  {agent.name}")
        for cf in agent.config_files:
            click.echo(f"    {cf}")
        if agent.mcp_server_count:
            click.echo(f"    MCP servers: {agent.mcp_server_count}")
        click.echo()


@cli.command("pin")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
def pin_cmd(path: str) -> None:
    """Pin current MCP tool definitions for rug pull detection."""
    from agent_audit_kit.pinning import create_pins

    project_root = Path(path)
    count = create_pins(project_root)
    click.echo(f"Pinned {count} tool definition(s) to .agent-audit-kit/tool-pins.json")


@cli.command("verify")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
def verify_cmd(path: str) -> None:
    """Verify MCP tool definitions against pinned hashes."""
    from agent_audit_kit.pinning import verify_pins

    project_root = Path(path)
    findings = verify_pins(project_root)
    if not findings:
        click.echo("All tool definitions match their pins.")
    else:
        click.echo(f"{len(findings)} tool definition change(s) detected:")
        for f in findings:
            click.echo(f"  {f.severity.value.upper()}: {f.title} -- {f.evidence}")


@cli.command("fix")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--dry-run", is_flag=True, default=False, help="Preview fixes without applying.")
def fix_cmd(path: str, dry_run: bool) -> None:
    """Auto-fix known security issues."""
    from agent_audit_kit.fix import run_fixes

    project_root = Path(path)
    fixes = run_fixes(project_root, dry_run=dry_run)
    if not fixes:
        click.echo("No auto-fixable issues found.")
        return
    label = "Would fix" if dry_run else "Fixed"
    click.echo(f"{label} {len(fixes)} issue(s):")
    for fix in fixes:
        click.echo(f"  {fix.rule_id}: {fix.description}")


@cli.command("score")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--badge", is_flag=True, default=False, help="Generate SVG badge.")
@click.option("--output", "-o", "output_file", type=click.Path(), default=None)
def score_cmd(path: str, badge: bool, output_file: str | None) -> None:
    """Show security score and grade for a project."""
    from agent_audit_kit.scoring import compute_score, generate_badge

    project_root = Path(path)
    result = run_scan(project_root=project_root)
    compute_score(result)
    click.echo(f"\nSecurity Score: {result.score}/100  Grade: {result.grade}\n")
    if badge:
        svg = generate_badge(result.score or 0, result.grade or "F")
        if output_file:
            Path(output_file).write_text(svg, encoding="utf-8")
            click.echo(f"Badge written to {output_file}")
        else:
            click.echo(svg)


@cli.command("update")
def update_cmd() -> None:
    """Update the vulnerability database."""
    from agent_audit_kit.vuln_db import update_database

    count = update_database()
    if count >= 0:
        click.echo(f"Vulnerability database updated: {count} entries.")
    else:
        click.echo("Update failed. Using bundled database.", err=True)


@cli.command("proxy")
@click.option("--port", default=8765, help="Port to listen on.")
@click.option("--target", required=True, help="Target MCP server URL to proxy.")
def proxy_cmd(port: int, target: str) -> None:
    """Start a local MCP proxy for runtime monitoring."""
    from agent_audit_kit.proxy.interceptor import start_proxy

    click.echo(f"Starting MCP proxy on port {port} -> {target}")
    click.echo("Press Ctrl+C to stop.")
    start_proxy(port=port, target=target)


@cli.command("kill")
def kill_cmd() -> None:
    """Terminate any running MCP proxy connections."""
    import os
    import signal

    pid_file = Path.home() / ".agent-audit-kit" / "proxy.pid"
    if pid_file.is_file():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            pid_file.unlink()
            click.echo(f"Proxy (PID {pid}) terminated.")
        except (ProcessLookupError, ValueError):
            pid_file.unlink(missing_ok=True)
            click.echo("No running proxy found.")
    else:
        click.echo("No running proxy found.")


@cli.command("install-precommit")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
def install_precommit_cmd(path: str) -> None:
    """Add an agent-audit-kit entry to the project's .pre-commit-config.yaml."""
    project = Path(path)
    cfg_path = project / ".pre-commit-config.yaml"
    snippet = (
        "  - repo: https://github.com/sattyamjjain/agent-audit-kit\n"
        "    rev: v0.3.0\n"
        "    hooks:\n"
        "      - id: agent-audit-kit\n"
    )
    if cfg_path.is_file():
        existing = cfg_path.read_text(encoding="utf-8")
        if "agent-audit-kit" in existing:
            click.echo("agent-audit-kit hook already configured in .pre-commit-config.yaml")
            return
        if "repos:" in existing:
            cfg_path.write_text(existing.rstrip() + "\n" + snippet, encoding="utf-8")
        else:
            cfg_path.write_text("repos:\n" + snippet, encoding="utf-8")
    else:
        cfg_path.write_text("repos:\n" + snippet, encoding="utf-8")
    click.echo(f"added agent-audit-kit pre-commit hook to {cfg_path.relative_to(project)}")
    click.echo("next: run `pre-commit install`")


@cli.command("export-rules")
@click.option("--out", "-o", "output_file", type=click.Path(), required=True,
              help="Path to write the signable rule bundle JSON.")
def export_rules_cmd(output_file: str) -> None:
    """Write a deterministic JSON bundle of every rule (for Sigstore signing)."""
    from agent_audit_kit.bundle import write_bundle

    digest = write_bundle(Path(output_file))
    click.echo(f"wrote {output_file}")
    click.echo(f"sha256={digest}")


@cli.command("verify-bundle")
@click.argument("bundle", type=click.Path(exists=True, dir_okay=False))
@click.option("--signature", "-s", "sig_path", type=click.Path(exists=True, dir_okay=False),
              default=None, help="Sigstore signature bundle.")
def verify_bundle_cmd(bundle: str, sig_path: str | None) -> None:
    """Verify a rule bundle's SHA-256 (optionally against a Sigstore signature)."""
    from agent_audit_kit.bundle import verify_bundle

    ok, message = verify_bundle(Path(bundle), Path(sig_path) if sig_path else None)
    click.echo(message)
    if not ok:
        sys.exit(EXIT_ERROR)


@cli.command("sbom")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--format",
    "sbom_format",
    type=click.Choice(["cyclonedx", "spdx"]),
    default="cyclonedx",
    help="SBOM format.",
)
@click.option("--output", "-o", "output_file", type=click.Path(), default=None,
              help="Write SBOM to file (defaults to stdout).")
def sbom_cmd(path: str, sbom_format: str, output_file: str | None) -> None:
    """Emit a CycloneDX 1.5 or SPDX 2.3 SBOM for the project's MCP dependencies."""
    from agent_audit_kit.output.sbom import emit_cyclonedx, emit_spdx

    project = Path(path)
    payload = emit_cyclonedx(project) if sbom_format == "cyclonedx" else emit_spdx(project)
    if output_file:
        Path(output_file).write_text(payload, encoding="utf-8")
        click.echo(f"SBOM written to {output_file}", err=True)
    else:
        click.echo(payload)


@cli.command("report")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--framework",
    required=True,
    type=click.Choice(["eu-ai-act", "soc2", "iso27001", "hipaa", "nist-ai-rmf"]),
    help="Compliance framework to format for.",
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["pdf", "text"]),
    default="pdf",
    help="Output format. 'pdf' requires reportlab; falls back to text when missing.",
)
@click.option("--output", "-o", "output_file", type=click.Path(), default=None)
def report_cmd(path: str, framework: str, report_format: str, output_file: str | None) -> None:
    """Produce an auditor-ready compliance report (EU AI Act Article 15 etc.)."""
    from agent_audit_kit.output.pdf_report import emit_pdf, _text_report

    project = Path(path)
    result = run_scan(project_root=project)

    if report_format == "pdf":
        out = Path(output_file or f"aak-compliance-{framework}.pdf")
        ok, msg = emit_pdf(result, framework, out)
        click.echo(msg, err=True)
        if not ok:
            # Fallback text already written by emit_pdf; nothing else to do.
            return
    else:
        text = _text_report(result, framework)
        if output_file:
            Path(output_file).write_text(text, encoding="utf-8")
            click.echo(f"wrote {output_file}", err=True)
        else:
            click.echo(text)


# Backward compatibility: allow `agent-audit-kit .` without `scan` subcommand
main = cli


if __name__ == "__main__":
    cli()
