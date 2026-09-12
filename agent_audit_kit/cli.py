from __future__ import annotations

import sys
from pathlib import Path

import click

from agent_audit_kit import __version__
from agent_audit_kit.commands._common import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_PASS,
    FAIL_ON_CHOICES,
    SEVERITY_MAP,
    _apply_config_defaults,
    _load_config,
    _to_list,
)
from agent_audit_kit.commands.scan import scan_cmd
from agent_audit_kit.engine import run_scan

# Re-exported so `from agent_audit_kit.cli import SEVERITY_MAP` (and the rest)
# keeps resolving after the #701 split. Listed explicitly rather than left to
# an implicit star-import so ruff does not read them as unused.
__all__ = [
    "cli",
    "main",
    "scan_cmd",
    "SEVERITY_MAP",
    "FAIL_ON_CHOICES",
    "EXIT_PASS",
    "EXIT_FINDINGS",
    "EXIT_ERROR",
    "_to_list",
    "_load_config",
    "_apply_config_defaults",
]


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version=__version__)
@click.option(
    "--emit-coverage",
    is_flag=True,
    default=False,
    help="Emit the per-rule framework coverage crosswalk (id, severity, CVEs, "
         "OWASP MCP, OWASP Agentic, NSA MCP CSI, EU AI Act) and exit.",
)
@click.option(
    "--format",
    "coverage_format",
    type=click.Choice(["json", "md"]),
    default="md",
    help="Output format for --emit-coverage (default: md).",
)
def cli(ctx: click.Context, emit_coverage: bool, coverage_format: str) -> None:
    """AgentAuditKit -- Security scanner for MCP-connected AI agent pipelines."""
    if emit_coverage:
        from agent_audit_kit.output.coverage_map import render_json, render_markdown

        click.echo((render_json() if coverage_format == "json" else render_markdown()), nl=False)
        ctx.exit(0)
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan_cmd)


# Registered rather than decorated: the command lives in
# agent_audit_kit/commands/scan.py, and a `@cli.command` there would need to
# import this module, which imports it. See issue #701.
cli.add_command(scan_cmd)


@cli.command("discover")
@click.version_option(version=__version__)
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["console", "json"]),
    default="console",
    help="Output format. JSON emits a stable schema for programmatic use.",
)
def discover_cmd(verbose: bool, output_format: str) -> None:
    """Discover all AI agent configurations on this machine."""
    from dataclasses import asdict
    import json as _json

    from agent_audit_kit.discovery import discover_agents

    agents = discover_agents(verbose=verbose)

    if output_format == "json":
        # Stable schema: {"count": int, "agents": [{...DiscoveredAgent}]}
        payload = {
            "count": len(agents),
            "agents": [asdict(a) for a in agents],
        }
        click.echo(_json.dumps(payload, indent=2, default=str))
        return

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
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
def pin_cmd(path: str) -> None:
    """Pin current MCP tool definitions for rug pull detection."""
    from agent_audit_kit.pinning import create_pins

    project_root = Path(path)
    count = create_pins(project_root)
    click.echo(f"Pinned {count} tool definition(s) to .agent-audit-kit/tool-pins.json")


@cli.command("verify")
@click.version_option(version=__version__)
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
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--dry-run", is_flag=True, default=False, help="Preview fixes without applying.")
@click.option(
    "--cve",
    "cve_only",
    is_flag=True,
    default=False,
    help="Only run CVE-targeted fixes (safe subset: dependency version bumps for known CVEs).",
)
def fix_cmd(path: str, dry_run: bool, cve_only: bool) -> None:
    """Auto-fix known security issues."""
    from agent_audit_kit.fix import run_cve_fixes, run_fixes

    project_root = Path(path)
    fixes = (
        run_cve_fixes(project_root, dry_run=dry_run)
        if cve_only
        else run_fixes(project_root, dry_run=dry_run)
    )
    if not fixes:
        scope = "CVE-targeted " if cve_only else ""
        click.echo(f"No {scope}auto-fixable issues found.")
        return
    label = "Would fix" if dry_run else "Fixed"
    scope_label = " (CVE mode)" if cve_only else ""
    click.echo(f"{label}{scope_label} {len(fixes)} issue(s):")
    for fix in fixes:
        click.echo(f"  {fix.rule_id}: {fix.description}")


@cli.command("score")
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=True, dir_okay=True, resolve_path=True))
@click.option("--badge", is_flag=True, default=False, help="Generate SVG badge (project-score mode only).")
@click.option("--aivss", is_flag=True, default=False, help="Annotate a SARIF file with AIVSS v0.8 scores.")
@click.option("--output", "-o", "output_file", type=click.Path(), default=None)
def score_cmd(path: str, badge: bool, aivss: bool, output_file: str | None) -> None:
    """Score a project (legacy AAK letter grade) OR annotate a SARIF
    file with AIVSS v0.8 scores via --aivss."""
    import json

    from agent_audit_kit.scoring import compute_score, generate_badge

    target = Path(path)

    # SARIF mode: --aivss + a file path → annotate SARIF.
    if aivss:
        if target.is_dir():
            click.echo("--aivss expects a SARIF file path, not a directory.", err=True)
            sys.exit(EXIT_ERROR)
        from agent_audit_kit.rules.builtin import get_rule
        from agent_audit_kit.scoring.aivss import annotate_sarif

        sarif = json.loads(target.read_text(encoding="utf-8"))
        annotated = annotate_sarif(sarif, get_rule)
        text = json.dumps(annotated, indent=2)
        if output_file:
            Path(output_file).write_text(text, encoding="utf-8")
            click.echo(f"wrote {output_file}", err=True)
        else:
            click.echo(text)
        return

    # Legacy project-score mode.
    if target.is_file():
        click.echo(
            "score: pass a project directory, or pass a SARIF file with --aivss.",
            err=True,
        )
        sys.exit(EXIT_ERROR)
    result = run_scan(project_root=target)
    compute_score(result)
    grade = result.grade or "F"
    # Closes #14: ANSI-color the grade per band.
    grade_color = {
        "A": "green",
        "B": "green",
        "C": "yellow",
        "D": "red",
        "F": "red",
    }.get(grade.upper(), "white")
    score_text = click.style(f"{result.score}/100", bold=True)
    grade_text = click.style(grade, fg=grade_color, bold=True)
    click.echo(f"\nSecurity Score: {score_text}  Grade: {grade_text}\n")
    if badge:
        svg = generate_badge(result.score or 0, result.grade or "F")
        if output_file:
            Path(output_file).write_text(svg, encoding="utf-8")
            click.echo(f"Badge written to {output_file}")
        else:
            click.echo(svg)


@cli.command("update")
@click.version_option(version=__version__)
def update_cmd() -> None:
    """Update the vulnerability database."""
    from agent_audit_kit.vuln_db import update_database

    count = update_database()
    if count >= 0:
        click.echo(f"Vulnerability database updated: {count} entries.")
    else:
        click.echo("Update failed. Using bundled database.", err=True)


@cli.command("proxy")
@click.version_option(version=__version__)
@click.option("--port", default=8765, help="Port to listen on.")
@click.option("--target", required=True, help="Target MCP server URL to proxy.")
def proxy_cmd(port: int, target: str) -> None:
    """Start a local MCP proxy for runtime monitoring."""
    from agent_audit_kit.proxy.interceptor import start_proxy

    click.echo(f"Starting MCP proxy on port {port} -> {target}")
    click.echo("Press Ctrl+C to stop.")
    start_proxy(port=port, target=target)


@cli.command("kill")
@click.version_option(version=__version__)
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


@cli.group("corpus")
def corpus_cmd() -> None:
    """Refresh threat-corpus data files (IPI payloads, FHI suffixes, ...)."""


@corpus_cmd.command("update")
@click.option("--ipi", "update_ipi", is_flag=True, default=False, help="Update the wild IPI payload corpus.")
@click.option("--fhi", "update_fhi", is_flag=True, default=False, help="Update the FHI universal-suffix corpus.")
@click.option("--all", "update_all", is_flag=True, default=False, help="Update every corpus listed in the manifest.")
@click.option("--manifest", "manifest_url", default=None, help="Override the manifest URL (default: gh-pages).")
def corpus_update_cmd(
    update_ipi: bool, update_fhi: bool, update_all: bool, manifest_url: str | None
) -> None:
    """Pull a signed corpus manifest and refresh local data files."""
    from agent_audit_kit.corpus.manifest import (
        CorpusVerificationError,
        fetch_and_verify,
        load_manifest,
        write_corpus,
    )

    if not (update_ipi or update_fhi or update_all):
        click.echo("Error: pass at least one of --ipi / --fhi / --all", err=True)
        sys.exit(EXIT_ERROR)

    selected_ids: set[str] = set()
    if update_all:
        selected_ids = {"ipi_wild_2026_04", "fhi_universal_suffixes"}
    if update_ipi:
        selected_ids.add("ipi_wild_2026_04")
    if update_fhi:
        selected_ids.add("fhi_universal_suffixes")

    try:
        entries = load_manifest(manifest_url)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error: failed to load manifest: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    failures = 0
    for entry in entries:
        if entry.id not in selected_ids:
            continue
        try:
            body = fetch_and_verify(entry)
        except CorpusVerificationError as exc:
            click.echo(f"  {entry.id}: VERIFY FAILED — {exc}", err=True)
            failures += 1
            continue
        except Exception as exc:  # noqa: BLE001
            click.echo(f"  {entry.id}: fetch failed — {exc}", err=True)
            failures += 1
            continue
        write_corpus(entry, body)
        click.echo(f"  {entry.id}: refreshed -> {entry.target_path}")
    if failures:
        sys.exit(EXIT_ERROR)


@cli.command("diff")
@click.version_option(version=__version__)
@click.option(
    "--baseline", "baseline_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=True,
    help="Path to the prior SARIF file to diff against.",
)
@click.option(
    "--current", "current_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=True,
    help="Path to the current SARIF file.",
)
@click.option(
    "--output", "-o", "output_path",
    type=click.Path(),
    default=None,
    help="Write the diff SARIF here. Default: stdout.",
)
@click.option(
    "--fail-on-new",
    is_flag=True,
    default=False,
    help="Exit 1 if any results are tagged `newly_introduced`.",
)
def diff_cmd(
    baseline_path: str, current_path: str, output_path: str | None, fail_on_new: bool
) -> None:
    """Diff two SARIF files: tag every result with newly_introduced /
    newly_resolved / still_present."""
    from agent_audit_kit.sarif.diff import diff_sarif, dump_sarif, load_sarif

    baseline = load_sarif(Path(baseline_path).read_text(encoding="utf-8"))
    current = load_sarif(Path(current_path).read_text(encoding="utf-8"))
    out = diff_sarif(baseline, current)
    body = dump_sarif(out)
    if output_path:
        Path(output_path).write_text(body, encoding="utf-8")
    else:
        click.echo(body)

    summary = (
        out.get("runs", [{}])[0]
        .get("properties", {})
        .get("aak_diff_summary", {})
    )
    click.echo(
        f"diff: {summary.get('newly_introduced', 0)} new, "
        f"{summary.get('newly_resolved', 0)} resolved, "
        f"{summary.get('still_present', 0)} still present.",
        err=True,
    )
    if fail_on_new and summary.get("newly_introduced", 0) > 0:
        sys.exit(EXIT_FINDINGS)


@cli.command("suggest")
@click.version_option(version=__version__)
@click.argument("sarif_path", type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option(
    "--pr", "pr_mode", is_flag=True, default=False,
    help="Emit a Markdown PR body suitable for `gh pr create --body-file -`.",
)
@click.option(
    "--apply-trivial", is_flag=True, default=False,
    help="Apply the mechanically-safe fixes in-place, for rules marked auto-fixable. "
         "Writes a log to .agent-audit-kit/fix-log.json. Same engine as `agent-audit-kit fix`.",
)
@click.option(
    "--project", "project_path", default=".",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    help="Project root to apply fixes to with --apply-trivial (default: current directory). "
         "The SARIF argument says what was found; this says where to fix it.",
)
@click.option(
    "--dry-run", is_flag=True, default=False,
    help="With --apply-trivial or --auto-pr, report what would change without writing.",
)
@click.option(
    "--auto-pr", "auto_pr", is_flag=True, default=False,
    help="Apply allow-listed mechanical fixes on a new branch and open a DRAFT PR "
         "via the `gh` CLI. Off by default. Refuses if any pending fix is for a "
         "rule outside the auto-PR allow-list, or if the working tree is dirty. "
         "AAK never handles a token: delivery runs under your own `gh auth`.",
)
@click.option(
    "--output", "-o", "output_path",
    type=click.Path(),
    default=None,
    help="Write the Markdown body here. Default: stdout.",
)
def suggest_cmd(
    sarif_path: str, pr_mode: bool, apply_trivial: bool, project_path: str,
    dry_run: bool, auto_pr: bool, output_path: str | None
) -> None:
    """Generate per-finding remediation hints from a SARIF run."""
    from agent_audit_kit.remediation.engine import sarif_to_markdown

    sarif_text = Path(sarif_path).read_text(encoding="utf-8")
    body = sarif_to_markdown(sarif_text, pr_mode=pr_mode)
    if output_path:
        Path(output_path).write_text(body, encoding="utf-8")
    else:
        click.echo(body)

    if auto_pr:
        from agent_audit_kit.autopr import AutoPrError, open_auto_pr, plan_auto_pr

        plan = plan_auto_pr(Path(project_path))
        for fix in plan.fixes:
            click.echo(f"  + {fix.rule_id}  {fix.file_path}", err=True)
        for fix in plan.blocked:
            click.echo(f"  - {fix.rule_id}  {fix.file_path}  (not allow-listed)", err=True)
        if dry_run:
            verdict = "would open" if plan.is_runnable else "would refuse"
            click.echo(
                f"suggest: {verdict} a draft PR on branch '{plan.branch or '-'}' "
                f"with {len(plan.fixes)} fix(es).",
                err=True,
            )
            return
        try:
            url = open_auto_pr(Path(project_path), plan)
        except AutoPrError as exc:
            click.echo(f"suggest --auto-pr: {exc}", err=True)
            sys.exit(EXIT_ERROR)
        click.echo(f"suggest: opened draft PR {url}", err=True)
        return

    if not apply_trivial:
        return

    # Delegates to the same engine as `agent-audit-kit fix`. The flag shipped in
    # v0.3.8 printing "not yet implemented (queued for v0.3.9)" and was still
    # printing it seventy releases later, while `fix` did exactly this the whole
    # time — so the work was to wire the two together, not to write a fixer.
    from agent_audit_kit.fix import run_fixes

    fixes = run_fixes(Path(project_path), dry_run=dry_run)
    if not fixes:
        click.echo(
            "suggest: no mechanically-safe fix applies here. Only rules marked "
            "auto-fixable are applied; everything else in the body above needs a "
            "human.",
            err=True,
        )
        return

    verb = "would apply" if dry_run else "applied"
    click.echo(f"suggest: {verb} {len(fixes)} fix(es):", err=True)
    for fix in fixes:
        click.echo(f"  {fix.rule_id}  {fix.file_path}", err=True)
    if not dry_run:
        click.echo(
            "suggest: log written to .agent-audit-kit/fix-log.json. Review the "
            "diff before committing — these are mechanical edits, not reviewed "
            "changes.",
            err=True,
        )


@cli.command("watch")
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--interval", "interval_seconds", type=int, default=300,
              help="Seconds between checks (default 300 = 5 minutes).")
@click.option("--webhook", "webhook_url", default=None,
              help="HTTP endpoint to POST a Slack-shaped JSON when drift is detected. "
                   "Falls back to $AAK_WEBHOOK_URL.")
@click.option("--once", is_flag=True, default=False,
              help="Run a single check and exit (useful for cron/CI).")
def watch_cmd(path: str, interval_seconds: int, webhook_url: str | None, once: bool) -> None:
    """Continuously monitor pinned tool surface for drift (Ctrl-C to stop)."""
    from agent_audit_kit.watch import run_watch

    result = run_watch(
        Path(path),
        interval_seconds=interval_seconds,
        webhook_url=webhook_url,
        max_iterations=1 if once else None,
    )
    click.echo(
        f"watch: exited after {result.iterations} iteration(s), {result.drift_events} drift event(s).",
        err=True,
    )


@cli.command("notify")
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to .aak-notify.yaml. Default: <path>/.aak-notify.yaml.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Run a scan and print which sinks would have been notified, without making network calls.",
)
def notify_cmd(path: str, config_path: str | None, dry_run: bool) -> None:
    """Run a scan and dispatch findings to configured notification sinks
    (Slack today; PagerDuty / Linear stubs in v0.4.0). Closes #66."""
    from agent_audit_kit.integrations import (
        load_notify_config,
        run_notify,
    )

    project_root = Path(path)
    cfg_path = Path(config_path) if config_path else project_root / ".aak-notify.yaml"

    if not cfg_path.is_file():
        click.echo(
            f"notify: no config at {cfg_path}; create one to wire up sinks.",
            err=True,
        )
        sys.exit(EXIT_ERROR)

    cfg = load_notify_config(cfg_path)
    if not cfg.sinks:
        click.echo("notify: config has no sinks configured.", err=True)
        sys.exit(EXIT_ERROR)

    result = run_scan(project_root=project_root)

    if dry_run:
        for sink in cfg.sinks:
            gated = [
                f for f in result.findings
                if f.severity.value >= sink.min_severity.value
            ]
            click.echo(
                f"  [dry-run] {sink.kind}: would post {len(gated)} finding(s) "
                f"at or above {sink.min_severity.name}",
            )
        return

    sent = run_notify(result, cfg)
    for kind, count in sent.items():
        if count == -1:
            click.echo(f"  {kind}: STUB (NotImplementedError) — not yet shipped")
        else:
            click.echo(f"  {kind}: posted {count} finding(s)")


@cli.command("install-precommit")
@click.version_option(version=__version__)
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
@click.version_option(version=__version__)
@click.option("--out", "-o", "output_file", type=click.Path(), required=True,
              help="Path to write the signable rule bundle JSON.")
def export_rules_cmd(output_file: str) -> None:
    """Write a deterministic JSON bundle of every rule (for Sigstore signing)."""
    from agent_audit_kit.bundle import write_bundle

    digest = write_bundle(Path(output_file))
    click.echo(f"wrote {output_file}")
    click.echo(f"sha256={digest}")


@cli.command("scanners")
@click.version_option(version=__version__)
@click.option("--json", "as_json", is_flag=True,
              help="Emit the scanner manifest as JSON (count + module/name list).")
def scanners_cmd(as_json: bool) -> None:
    """List the scanner modules the engine runs — reproduces SCANNER_COUNT.

    The count is derived from this list (and the committed `scanners.json`), not
    asserted, so anyone can check it: `agent-audit-kit scanners --json`.
    """
    import json as _json

    from agent_audit_kit.engine import scanner_manifest

    manifest = scanner_manifest()
    if as_json:
        click.echo(_json.dumps({"count": len(manifest), "scanners": manifest},
                               indent=2, sort_keys=True))
    else:
        for entry in manifest:
            click.echo(f"{entry['module']:38s} {entry['name']}")
        click.echo(f"\n{len(manifest)} scanner modules")


@cli.command("verify-bundle")
@click.version_option(version=__version__)
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
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--format",
    "sbom_format",
    type=click.Choice(["cyclonedx", "spdx", "aibom"]),
    default="cyclonedx",
    help=(
        "SBOM format. `cyclonedx` + `spdx` are standard SBOMs; `aibom` "
        "emits a CycloneDX 1.5 AI/ML-BOM with machine-learning-model "
        "components, detected agent-platform SDKs, and rule-bundle "
        "provenance properties. The companion exploitability document comes "
        "from `agent-audit-kit vex` and joins to this one on purl."
    ),
)
@click.option("--output", "-o", "output_file", type=click.Path(), default=None,
              help="Write SBOM to file (defaults to stdout).")
def sbom_cmd(path: str, sbom_format: str, output_file: str | None) -> None:
    """Emit a CycloneDX 1.5 / SPDX 2.3 SBOM or a CycloneDX AI-BOM (`--format aibom`).

    The companion exploitability document comes from `agent-audit-kit vex`,
    which emits OpenVEX statements keyed by the same purls this SBOM uses, so
    the two join on purl without a mapping table.
    """
    from agent_audit_kit.output.sbom import emit_cyclonedx, emit_spdx

    project = Path(path)
    if sbom_format == "spdx":
        payload = emit_spdx(project)
    elif sbom_format == "aibom":
        # Best-effort: pull the shipped rule-bundle hash if the user has
        # the file committed locally; don't fail the emit if it's absent.
        sha256_path = project / "rules.json.sha256"
        rule_hash: str | None = None
        if sha256_path.is_file():
            try:
                rule_hash = sha256_path.read_text(encoding="utf-8").split()[0]
            except OSError:
                rule_hash = None
        payload = emit_cyclonedx(project, aibom=True, rule_bundle_sha256=rule_hash)
    else:
        payload = emit_cyclonedx(project)
    if output_file:
        Path(output_file).write_text(payload, encoding="utf-8")
        click.echo(f"SBOM written to {output_file}", err=True)
    else:
        click.echo(payload)


@cli.command("vex")
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--format",
    "vex_format",
    type=click.Choice(["openvex"]),
    default="openvex",
    help=(
        "VEX format. Only `openvex` today; the flag exists so a CSAF arm can "
        "be added later without a breaking change to the command's shape."
    ),
)
@click.option("--output", "-o", "output_file", type=click.Path(), default=None,
              help="Write the VEX document to file (defaults to stdout).")
def vex_cmd(path: str, vex_format: str, output_file: str | None) -> None:
    """Emit an OpenVEX v0.2.0 exploitability document for the scanned project.

    Products are the same purls `agent-audit-kit sbom` emits, so the two
    documents join on purl. Statuses are limited to `affected`, `fixed` and
    `under_investigation`: `not_affected` needs a reachability justification a
    static config scan cannot establish, so this emitter never claims it.

    This is an evidence command, not a gate. It exits 0 on a clean emit
    regardless of what the scan found.
    """
    from agent_audit_kit.output.vex import emit_openvex

    project = Path(path)
    result = run_scan(project)
    payload = emit_openvex(project, result)
    if output_file:
        Path(output_file).write_text(payload, encoding="utf-8")
        click.echo(f"VEX document written to {output_file}", err=True)
    else:
        click.echo(payload)


@cli.command("report")
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--framework",
    required=True,
    type=click.Choice([
        "eu-ai-act",
        "eu-ai-act-art55",
        "soc2",
        "iso27001",
        "iso42001",
        "hipaa",
        "nist-ai-rmf",
        "nsa-mcp-csi-2026",
        "singapore-agentic",
        "india-dpdp",
        "alabama-dppa",
        "tennessee-sb1580",
        "colorado-admt",
        "standards-crosswalk",
    ]),
    help="Compliance framework to format for. 'standards-crosswalk' emits the "
         "static rule → NSA MCP CSI + OWASP Agentic Top-10 mapping (no scan).",
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
    # The standards crosswalk is a static rule→control mapping — no scan needed.
    if framework == "standards-crosswalk":
        from agent_audit_kit.output.crosswalk import render_markdown, render_text

        text = render_text() if report_format == "text" else render_markdown()
        if output_file:
            Path(output_file).write_text(text, encoding="utf-8")
            click.echo(f"wrote {output_file}", err=True)
        else:
            click.echo(text)
        return

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


# ---------------------------------------------------------------------------
# v0.3.9 commands: coverage, pipelock import, inspect-ide, parity report
# ---------------------------------------------------------------------------


@cli.command("coverage")
@click.version_option(version=__version__)
@click.option(
    "--source",
    type=click.Choice(["ox", "prisma-airs"]),
    default="ox",
    help="Coverage source to report on.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "text", "badge"]),
    default="text",
)
@click.option("--output", "-o", "output_file", type=click.Path(), default=None)
@click.option(
    "--fail-under",
    type=float,
    default=None,
    help="Exit 1 if coverage_pct < threshold (CI use).",
)
def coverage_cmd(
    source: str, fmt: str, output_file: str | None, fail_under: float | None
) -> None:
    """Report AAK's coverage of external manifests (OX, Prisma AIRS)."""
    import json

    def _ox_row(e: dict) -> str:
        rules = ", ".join(e["rules"]) or "—"
        mark = "✔" if e["covered"] else "✘"
        return f"  {mark} {e['cve']}: {e['title']} → {rules}"

    def _airs_row(e: dict) -> str:
        rules = ", ".join(e["aak_rule_ids"]) or "—"
        mark = "✔" if e["aak_rule_ids"] else "·"
        return f"  {mark} {e['airs_attack_id']} [{e['status']}]: {e['title']} → {rules}"

    if source == "ox":
        from agent_audit_kit.coverage import load_manifest, summarize as ox_summarize

        entries = load_manifest("ox")
        summary = ox_summarize(entries)
        label = "OX coverage"
        total_key = "total"
        item_renderer = _ox_row
        header = (
            f"OX-disclosed CVE coverage: "
            f"{summary['covered']}/{summary[total_key]} "
            f"({summary['coverage_pct']}%)"
        )
    else:
        from agent_audit_kit.translators.prisma_airs import summarize as airs_summarize

        summary = airs_summarize()
        label = "Prisma AIRS coverage"
        total_key = "total_static"
        item_renderer = _airs_row
        header = (
            f"Prisma AIRS coverage (static-relevant only): "
            f"{summary['covered']}/{summary[total_key]} "
            f"({summary['coverage_pct']}%)"
        )

    if fmt == "json":
        text = json.dumps(summary, indent=2, sort_keys=True)
    elif fmt == "badge":
        pct = summary["coverage_pct"]
        colour = "green" if pct >= 90 else ("yellow" if pct >= 70 else "red")
        text = json.dumps(
            {
                "schemaVersion": 1,
                "label": label,
                "message": f"{pct}%",
                "color": colour,
            },
            indent=2,
        )
    else:
        lines = [header, ""]
        for entry in summary["entries"]:
            lines.append(item_renderer(entry))
        text = "\n".join(lines) + "\n"

    if output_file:
        Path(output_file).write_text(text, encoding="utf-8")
        click.echo(f"wrote {output_file}", err=True)
    else:
        click.echo(text)

    if fail_under is not None and summary["coverage_pct"] < fail_under:
        click.echo(
            f"coverage {summary['coverage_pct']}% < --fail-under {fail_under}%",
            err=True,
        )
        sys.exit(EXIT_FINDINGS)


@cli.group("pipelock")
def pipelock_cmd() -> None:
    """Pipelock policy DSL bridge (translate to .agent-audit-kit.yml)."""


@pipelock_cmd.command("import")
@click.argument(
    "policy_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, resolve_path=True),
)
@click.option("--output", "-o", "output_file", type=click.Path(), default=None)
@click.option("--dry-run", is_flag=True, default=False)
def pipelock_import_cmd(
    policy_path: str, output_file: str | None, dry_run: bool
) -> None:
    """Translate a Pipelock v2.3 YAML policy → .agent-audit-kit.yml."""
    from agent_audit_kit.translators.pipelock import translate

    policy = Path(policy_path)
    out_text = translate(policy)
    if dry_run:
        click.echo(out_text)
        return
    target = Path(output_file or ".agent-audit-kit.yml")
    target.write_text(out_text, encoding="utf-8")
    click.echo(f"wrote {target}", err=True)


@cli.command("inspect-ide")
@click.version_option(version=__version__)
@click.argument(
    "path", default=".",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, resolve_path=True),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["lsp", "json", "text"]),
    default="text",
    help="Output format. 'lsp' emits a single LSP-shape diagnostics array.",
)
@click.option(
    "--serve",
    is_flag=True,
    default=False,
    help="Run a minimal stdio LSP server (advertises diagnostics).",
)
def inspect_ide_cmd(path: str, fmt: str, serve: bool) -> None:
    """Run AAK and emit IDE-shaped diagnostics (LSP / JSON / text)."""
    if serve:
        from agent_audit_kit.ide.lsp_diag import serve_stdio

        serve_stdio(Path(path))
        return

    from agent_audit_kit.ide.lsp_diag import diagnostics_for

    diags = diagnostics_for(Path(path))
    if fmt == "lsp":
        import json

        click.echo(json.dumps(diags, indent=2))
    elif fmt == "json":
        import json

        click.echo(json.dumps(diags, indent=2))
    else:
        if not diags:
            click.echo("No findings.")
            return
        for d in diags:
            sev = {1: "ERROR", 2: "WARN", 3: "INFO", 4: "HINT"}.get(
                d.get("severity", 2), "WARN"
            )
            uri = d.get("uri", "<unknown>")
            line = d.get("range", {}).get("start", {}).get("line", 0) + 1
            click.echo(
                f"[{sev}] {d.get('code', '?')} {uri}:{line} — {d.get('message', '')}"
            )


@cli.command("parity")
@click.version_option(version=__version__)
@click.argument(
    "subcommand", type=click.Choice(["report"]), default="report"
)
@click.option(
    "--dimension", default="model", help="Bucket key (default: model)."
)
@click.option(
    "--metric", default="price", help="Metric to compare (default: price)."
)
@click.option(
    "--max-drift-pct",
    type=float,
    default=1.5,
    help="Allowed per-bucket drift from overall mean (default 1.5%).",
)
@click.option("--window", default=None, help="Rolling window: e.g. 7d, 24h, 60m.")
def parity_cmd(
    subcommand: str,
    dimension: str,
    metric: str,
    max_drift_pct: float,
    window: str | None,
) -> None:
    """Report on @aak.parity.check invocations (Project-Deal-class drift)."""
    import json

    from agent_audit_kit.parity import report

    window_seconds: float | None = None
    if window:
        unit = window[-1]
        try:
            n = float(window[:-1])
        except ValueError:
            click.echo(f"Invalid --window: {window}", err=True)
            sys.exit(EXIT_ERROR)
        window_seconds = n * {"d": 86400, "h": 3600, "m": 60, "s": 1}.get(unit, 1)

    try:
        out = report(
            dimension=dimension,
            metric=metric,
            window_seconds=window_seconds,
            max_drift_pct=max_drift_pct,
        )
    except Exception as exc:  # noqa: BLE001 — surface as exit code 1 with a message
        click.echo(f"parity {subcommand}: {type(exc).__name__}: {exc}", err=True)
        sys.exit(EXIT_FINDINGS)
    click.echo(json.dumps(out, indent=2, default=str))


# ---------------------------------------------------------------------------
# v0.3.10 commands: watch, rule lint  (score gained --aivss above)
# ---------------------------------------------------------------------------


@cli.command("watch-cve")
@click.version_option(version=__version__)
@click.option(
    "--feeds",
    default="nvd",
    help="Comma-separated feed IDs. Live: nvd (NVD 2.0 API). Stubbed (no fetcher "
    "yet): ox, cert-cc, thaicert, ironplate.",
)
@click.option(
    "--online",
    is_flag=True,
    default=False,
    help="Allow the nvd feed to fetch from the network. Off by default so CI and "
    "offline runs never make a network call; without it the nvd feed reads its "
    "on-disk cache.",
)
@click.option(
    "--emit",
    default=None,
    help="Notification sink: slack://...|webhook://...|github://owner/repo",
)
@click.option("--interval-seconds", type=int, default=1800)
@click.option("--max-iterations", type=int, default=0, help="0 = run forever.")
@click.option("--dry-run", is_flag=True, default=False)
def watch_cve_cmd(
    feeds: str,
    online: bool,
    emit: str | None,
    interval_seconds: int,
    max_iterations: int,
    dry_run: bool,
) -> None:
    """[experimental] Poll CVE feeds and surface new entries that lack an AAK rule.

    Exactly one feed is live: nvd (the NVD 2.0 API). Its network call is opt-in
    behind --online; without that flag the feed reads its on-disk cache, so a
    default run never touches the network. The other feeds (ox, cert-cc, thaicert,
    ironplate) are unimplemented stubs and print "not implemented"; the command
    exits non-zero only when every requested feed is a stub, and 0 when at least one
    live feed polled cleanly. Distinct from `aak watch` (the pin-drift monitor)."""
    from agent_audit_kit.feeds import run_watch as run_feed_watch

    feed_ids = [f.strip() for f in feeds.split(",") if f.strip()]
    rc = run_feed_watch(
        feed_ids=feed_ids,
        emit=emit,
        interval_seconds=interval_seconds,
        max_iterations=max_iterations,
        dry_run=dry_run,
        online=online,
    )
    sys.exit(rc)


@cli.group("rule")
def rule_cmd() -> None:
    """Rule-registry hygiene commands."""


@rule_cmd.command("lint")
@click.option("--ci", is_flag=True, default=False, help="Exit 1 on any violation.")
@click.option("--rule", "rule_filter", default=None, help="Lint only this rule_id.")
def rule_lint_cmd(ci: bool, rule_filter: str | None) -> None:
    """Validate the RuleDefinition registry against AAK metadata invariants."""
    from agent_audit_kit.rule_lint import run_lint

    violations = run_lint(rule_filter=rule_filter)
    if not violations:
        click.echo("rule lint: clean.")
        return
    for v in violations:
        click.echo(f"  {v['rule_id']}: {v['message']}", err=True)
    click.echo(f"rule lint: {len(violations)} violation(s).", err=True)
    if ci:
        sys.exit(EXIT_FINDINGS)


# Backward compatibility: allow `agent-audit-kit .` without `scan` subcommand
main = cli


if __name__ == "__main__":
    cli()
