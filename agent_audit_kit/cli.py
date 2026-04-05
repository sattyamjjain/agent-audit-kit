from __future__ import annotations

import sys
from pathlib import Path

import click

from agent_audit_kit import __version__
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version=__version__)
def cli(ctx: click.Context) -> None:
    """AgentAuditKit — Security scanner for MCP-connected AI agent pipelines."""
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
@click.option("--ci", is_flag=True, default=False, help="Exit with code 1 if any finding >= severity threshold.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show detailed scan progress.")
@click.option("--score", "show_score", is_flag=True, default=False, help="Show security score and grade.")
@click.option("--owasp-report", is_flag=True, default=False, help="Show OWASP coverage matrix.")
@click.option("--compliance", default=None, help="Compliance framework: eu-ai-act, soc2, iso27001, hipaa, nist-ai-rmf.")
@click.option("--verify-secrets", is_flag=True, default=False, help="Actively verify if detected secrets are live (makes network calls).")
@click.option("--diff", "diff_base", default=None, help="Only report findings in files changed since BASE_REF (e.g., HEAD~1, main).")
@click.option("--llm-scan", is_flag=True, default=False, help="Use local LLM (Ollama) for semantic tool description analysis.")
def scan_cmd(
    path: str,
    output_format: str,
    min_severity: str,
    output_file: str | None,
    include_user_config: bool,
    ignore_paths: str | None,
    rules: str | None,
    exclude_rules: str | None,
    ci: bool,
    verbose: bool,
    show_score: bool,
    owasp_report: bool,
    compliance: str | None,
    verify_secrets: bool,
    diff_base: str | None,
    llm_scan: bool,
) -> None:
    """Scan a project for MCP agent security vulnerabilities."""
    from agent_audit_kit.output import console, json_report, sarif

    project_root = Path(path)
    if verbose:
        click.echo(f"Scanning {project_root.resolve()}...", err=True)

    parsed_ignore = [p.strip() for p in ignore_paths.split(",")] if ignore_paths else None
    parsed_rules = [r.strip() for r in rules.split(",")] if rules else None
    parsed_excludes = [r.strip() for r in exclude_rules.split(",")] if exclude_rules else None
    severity = SEVERITY_MAP[min_severity]
    verbose_cb = (lambda msg: click.echo(msg, err=True)) if verbose else None

    result = run_scan(
        project_root=project_root,
        include_user_config=include_user_config,
        ignore_paths=parsed_ignore,
        rules=parsed_rules,
        exclude_rules=parsed_excludes,
        verbose_callback=verbose_cb,
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

    # Check tool pins (RUGPULL detection as part of scan)
    try:
        from agent_audit_kit.pinning import verify_pins
        pin_findings = verify_pins(project_root)
        result.findings.extend(pin_findings)
    except Exception:
        pass

    # Compute score
    if show_score or compliance or owasp_report:
        from agent_audit_kit.scoring import compute_score
        compute_score(result)

    # Output
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

    if ci:
        filtered = result.findings_at_or_above(severity)
        if filtered:
            sys.exit(1)


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
            click.echo(f"  {f.severity.value.upper()}: {f.title} — {f.evidence}")


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
    import signal
    import os
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


# Backward compatibility: allow `agent-audit-kit .` without `scan` subcommand
main = cli


if __name__ == "__main__":
    cli()
