"""The ``scan`` command: argument surface, orchestration, and reporting.

Moved out of ``cli.py`` verbatim for issue #701 — 440 lines, a quarter of that
file, for one of its 23 commands. Nothing about the command's behaviour or its
``--help`` output changes: the option decorators, the docstring and the parameter
names are the same objects in a different file, and ``cli`` registers the command
with ``add_command`` instead of the ``@cli.command`` decorator so the import runs
one way only.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from agent_audit_kit import __version__
from agent_audit_kit.commands._common import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    FAIL_ON_CHOICES,
    SEVERITY_MAP,
    _apply_config_defaults,
    _load_config,
    _to_list,
)
from agent_audit_kit.engine import run_scan

__all__ = ["scan_cmd"]


@click.command("scan")
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--format", "output_format", type=click.Choice(["console", "json", "sarif"]), default="console", help="Output format.")
@click.option("--severity", "min_severity", type=click.Choice(["critical", "high", "medium", "low", "info"]), default="low", help="Minimum severity to report.")
@click.option("--output", "-o", "output_file", type=click.Path(), default=None, help="Write report to file.")
@click.option("--include-user-config", is_flag=True, default=False, help="Also scan user-level configs (~/.claude/).")
@click.option("--ignore-paths", default=None, help="Comma-separated paths to skip.")
@click.option("--rules", default=None, help="Comma-separated rule IDs to run (default: all).")
@click.option("--exclude-rules", default=None, help="Comma-separated rule IDs to skip.")
@click.option(
    "--preset",
    "preset",
    default=None,
    help=(
        "Activate a curated rule preset (yaml under agent_audit_kit/presets/). "
        "Equivalent to passing --rules with the preset's rule list. "
        "Example: --preset mcp-ox-2026-04."
    ),
)
@click.option(
    "--profile",
    "profile",
    default=None,
    help=(
        "Alias for --preset — a curated readiness profile. "
        "Example: --profile mcp-2026-07-28 (the 07-28 final auth-profile check)."
    ),
)
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
@click.option("--compliance", default=None, help="Compliance framework: eu-ai-act, soc2, iso27001, iso42001, hipaa, nist-ai-rmf, nsa-mcp-csi-2026 (NSA AISC MCP Security CSI, U/OO/6030316-26), aicm (CSA AI Controls Matrix, CSV output), mcp-2026-roadmap (MCP 2026 Roadmap conformance).")
@click.option("--verify-secrets", is_flag=True, default=False, help="Actively verify if detected secrets are live (makes network calls).")
@click.option("--diff", "diff_base", default=None, help="Only report findings in files changed since BASE_REF (e.g., HEAD~1, main).")
@click.option("--llm-scan", is_flag=True, default=False, help="Run LLM semantic analysis on tool descriptions (opt-in).")
@click.option(
    "--sessions",
    default=None,
    type=click.Path(exists=True),
    help=(
        "Session transcript file or directory to run the session-scoped rules over "
        "(AAK-AGENT-COMPOSE-002). Reads OpenAI Agents SDK run traces, LangGraph "
        "checkpoint/thread state, raw JSONL of {tool, args, ts}, and AAK's own "
        "*.session.json."
    ),
)
@click.option(
    "--llm",
    "llm_model",
    default="ollama/gemma2:2b",
    help=(
        "LLM model slug when --llm-scan is set. Prefix selects provider: "
        "claude* (Anthropic, ANTHROPIC_API_KEY), gpt* (OpenAI, OPENAI_API_KEY), "
        "gemini* (Google, GEMINI_API_KEY), or ollama/<model> (local Ollama daemon)."
    ),
)
@click.option(
    "--strict-loading",
    is_flag=True,
    default=False,
    help="Fail loudly if any optional scanner module cannot be imported. Default: silently skip.",
)
@click.option(
    "--advisories",
    "advisories_repo",
    default=None,
    help="Open private GitHub Security Advisories for each CRITICAL finding "
         "against the given repo (owner/name). Requires 'gh' CLI auth.",
)
@click.option(
    "--advisories-dry-run",
    is_flag=True,
    default=False,
    help="With --advisories, preview the advisory payloads without creating them.",
)
@click.option(
    "--step-summary/--no-step-summary",
    "step_summary",
    default=True,
    help="Append a Markdown findings table to $GITHUB_STEP_SUMMARY when running inside GitHub Actions. Default: on.",
)
@click.option(
    "--pr-summary-out",
    "pr_summary_out",
    type=click.Path(),
    default=None,
    help="Also write the Markdown PR-comment body to this path (used by the Docker action).",
)
@click.option(
    "--fingerprint-strategy",
    "fingerprint_strategy",
    type=click.Choice(["auto", "line-hash", "disabled"]),
    default="auto",
    help="SARIF fingerprint mode. 'auto' (default) emits content-hash when source is co-located, else location-hash — matches GitHub Code Scanning's de-dup expectation. 'line-hash' forces the content-hash code path; 'disabled' emits none.",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    default=False,
    help="With --format console, suppress header / summary / tips and only print findings (closes #13).",
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
    preset: str | None,
    profile: str | None,
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
    sessions: str | None,
    llm_model: str,
    strict_loading: bool,
    advisories_repo: str | None,
    advisories_dry_run: bool,
    step_summary: bool,
    pr_summary_out: str | None,
    fingerprint_strategy: str,
    quiet: bool,
) -> None:
    """Scan a project for MCP agent security vulnerabilities."""
    try:
        # Preset/profile → rules expansion. A preset (or its --profile alias)
        # narrows the rule set to a curated list; combining with --rules unions
        # both. --profile is a synonym for --preset; if both are given, their
        # rule lists union.
        preset_names = [p for p in (preset, profile) if p]
        if preset_names:
            from agent_audit_kit.presets import load_preset
            preset_rules: set[str] = set()
            for name in preset_names:
                preset_rules.update(load_preset(name))
            if rules:
                rules = ",".join(sorted(set(rules.split(",")) | preset_rules))
            else:
                rules = ",".join(sorted(preset_rules))
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
            sessions=sessions,
            llm_model=llm_model,
            strict_loading=strict_loading,
            advisories_repo=advisories_repo,
            advisories_dry_run=advisories_dry_run,
            step_summary=step_summary,
            pr_summary_out=pr_summary_out,
            fingerprint_strategy=fingerprint_strategy,
            quiet=quiet,
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
    llm_model: str,
    strict_loading: bool,
    sessions: str | None = None,
    advisories_repo: str | None = None,
    advisories_dry_run: bool = False,
    step_summary: bool = True,
    pr_summary_out: str | None = None,
    quiet: bool = False,
    fingerprint_strategy: str = "auto",
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

    # LLM semantic analysis (opt-in, provider chosen by --llm)
    if llm_scan:
        try:
            from agent_audit_kit.llm_scan import run_llm_analysis

            if verbose:
                click.echo(f"LLM scan using model: {llm_model}", err=True)
            llm_findings = run_llm_analysis(project_root, model=llm_model)
            result.findings.extend(llm_findings)
        except ValueError as e:
            click.echo(f"LLM scan config error: {e}", err=True)
        except Exception as e:
            click.echo(f"LLM scan failed: {e}", err=True)

    # Session-transcript ingest. The session-scoped rules only discover
    # *.session.json / .aak/sessions/ inside the project root, which no agent
    # framework writes. --sessions normalises real transcripts (OpenAI Agents
    # SDK traces, LangGraph checkpoints, raw JSONL) into that shape and runs the
    # same rule over them, unchanged.
    if sessions:
        from agent_audit_kit.sessions.adapters import load_transcripts, scan_sessions

        sessions_path = Path(sessions)
        transcripts = load_transcripts(sessions_path)
        if verbose:
            for tpath, fmt, calls in transcripts:
                click.echo(f"session: {tpath} ({fmt}, {len(calls)} calls)", err=True)
        if not transcripts:
            click.echo(
                f"Warning: no readable session transcript found at {sessions} "
                f"(supported: OpenAI Agents SDK traces, LangGraph checkpoint/thread "
                f"state, JSONL of {{tool, args, ts}}, AAK *.session.json).",
                err=True,
            )
        else:
            result.findings.extend(scan_sessions(sessions_path, config_root=project_root))

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
    elif compliance == "aicm":
        from agent_audit_kit.output.aicm import format_results as fmt_aicm

        output = fmt_aicm(result)
    elif compliance:
        from agent_audit_kit.output.compliance import format_results as fmt_compliance

        output = fmt_compliance(result, compliance)
    elif output_format == "json":
        output = json_report.format_results(result, severity)
    elif output_format == "sarif":
        output = sarif.format_results(
            result,
            severity,
            project_root=project_root,
            fingerprint_strategy=fingerprint_strategy,
        )
    else:
        output = console.format_results(result, severity, show_score=show_score, quiet=quiet)

    if output_file:
        Path(output_file).write_text(output, encoding="utf-8")
        if verbose:
            click.echo(f"Report written to {output_file}", err=True)
    else:
        click.echo(output)

    # --- PR-comment markdown: $GITHUB_STEP_SUMMARY + optional explicit path ---
    if step_summary or pr_summary_out:
        from agent_audit_kit.output.pr_summary import render_markdown, write_step_summary

        body = render_markdown(result)
        if pr_summary_out:
            Path(pr_summary_out).write_text(body, encoding="utf-8")
            if verbose:
                click.echo(f"pr-summary written to {pr_summary_out}", err=True)
        if step_summary:
            write_step_summary(result)

    # --- Optional: open GitHub Security Advisories for CRITICAL findings ---
    if advisories_repo:
        from agent_audit_kit.advisories import open_advisories

        adv_results = open_advisories(
            result.findings,
            advisories_repo,
            dry_run=advisories_dry_run,
        )
        if adv_results:
            prefix = "Would open" if advisories_dry_run else "Opened"
            click.echo(f"{prefix} {len(adv_results)} security advisory/ies:", err=True)
            for r in adv_results:
                if r.created or advisories_dry_run:
                    click.echo(f"  {r.rule_id} -> {r.url}", err=True)
                else:
                    click.echo(f"  {r.rule_id} FAILED: {r.error}", err=True)

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
