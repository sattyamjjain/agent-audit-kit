#!/usr/bin/env python3
"""Crawl public GitHub repos for .mcp.json files and benchmark AgentAuditKit.

Uses the GitHub Search API (via urllib -- no external dependencies) to discover
publicly committed MCP configuration files, downloads them, runs the
agent-audit-kit scanner on each, and produces aggregate statistics.

Usage:
    python benchmarks/crawler.py --limit 50 --output benchmarks/results.json
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
GITHUB_API_VERSION = "2022-11-28"
SEARCH_QUERY = "mcpServers filename:.mcp.json"
PER_PAGE = 100  # max allowed by GitHub
RATE_LIMIT_PAUSE_S = 10  # seconds to wait when rate-limited
DATA_DIR = Path(__file__).resolve().parent / "data"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ConfigResult:
    """Result of scanning a single config file."""

    source_repo: str
    source_path: str
    local_path: str
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    rule_violations: list[str] = field(default_factory=list)
    has_hardcoded_secrets: bool = False
    has_enable_all_servers: bool = False
    scan_error: str | None = None


@dataclass
class BenchmarkResults:
    """Aggregate benchmark results."""

    total_configs_scanned: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    most_common_violations: list[dict[str, Any]] = field(default_factory=list)
    pct_hardcoded_secrets: float = 0.0
    pct_enable_all_servers: float = 0.0
    configs: list[dict[str, Any]] = field(default_factory=list)
    crawl_timestamp: str = ""
    errors: int = 0


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------


def _github_headers() -> dict[str, str]:
    """Build headers for GitHub API requests.

    Respects the GITHUB_TOKEN environment variable for authenticated access
    (higher rate limits: 30 req/min vs 10 req/min).
    """
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": "AgentAuditKit-Benchmark/0.2",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _api_get(url: str) -> dict[str, Any]:
    """Perform a GET request against the GitHub API with retry on rate-limit."""
    headers = _github_headers()
    req = urllib.request.Request(url, headers=headers)

    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                # Rate limited -- back off and retry
                retry_after = int(exc.headers.get("Retry-After", RATE_LIMIT_PAUSE_S))
                logger.warning(
                    "Rate limited (attempt %d/3). Waiting %ds...",
                    attempt + 1,
                    retry_after,
                )
                time.sleep(retry_after)
                continue
            raise
    raise RuntimeError(f"GitHub API request failed after 3 attempts: {url}")


# ---------------------------------------------------------------------------
# Search & download
# ---------------------------------------------------------------------------


def search_mcp_configs(limit: int = 100) -> list[dict[str, Any]]:
    """Search GitHub for public .mcp.json files containing mcpServers.

    Args:
        limit: Maximum number of results to return.

    Returns:
        List of search result items from the GitHub Code Search API.
    """
    items: list[dict[str, Any]] = []
    page = 1
    per_page = min(limit, PER_PAGE)

    while len(items) < limit:
        url = (
            f"{GITHUB_SEARCH_URL}"
            f"?q={urllib.request.quote(SEARCH_QUERY)}"
            f"&per_page={per_page}&page={page}"
        )
        logger.info("Searching page %d (collected %d/%d)...", page, len(items), limit)
        data = _api_get(url)

        page_items = data.get("items", [])
        if not page_items:
            break

        items.extend(page_items)
        page += 1

        # Respect rate limits between pages
        time.sleep(2)

    return items[:limit]


def download_config(item: dict[str, Any], index: int) -> Path | None:
    """Download a single .mcp.json file from its GitHub API URL.

    Args:
        item: A search result item from the GitHub Code Search API.
        index: Numeric index used for the local filename.

    Returns:
        Path to the downloaded file, or None on failure.
    """
    api_url = item.get("url")
    if not api_url:
        return None

    try:
        content_data = _api_get(api_url)
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", api_url, exc)
        return None

    # The content API returns base64-encoded file content
    encoded = content_data.get("content", "")
    if not encoded:
        return None

    try:
        raw = base64.b64decode(encoded)
    except Exception:
        return None

    # Validate it's actually JSON before saving
    try:
        json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Skipping non-JSON content from %s", api_url)
        return None

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    repo_name = item.get("repository", {}).get("full_name", "unknown").replace("/", "_")
    dest = DATA_DIR / f"{index:04d}_{repo_name}.mcp.json"
    dest.write_bytes(raw)
    return dest


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_config(config_path: Path) -> dict[str, Any] | None:
    """Run agent-audit-kit scan on a single config file and return JSON results.

    The config is placed in a temporary directory structure so the scanner can
    discover it as a .mcp.json file.

    Args:
        config_path: Path to the .mcp.json file to scan.

    Returns:
        Parsed JSON output from agent-audit-kit, or None on error.
    """
    import shutil
    import tempfile

    # Create a temp directory and copy the config as .mcp.json inside it
    # so the scanner discovers it correctly
    tmpdir = Path(tempfile.mkdtemp(prefix="aak_bench_"))
    try:
        shutil.copy2(config_path, tmpdir / ".mcp.json")
        result = subprocess.run(
            [sys.executable, "-m", "agent_audit_kit.cli", "scan", str(tmpdir), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode not in (0, 1):
            logger.warning(
                "Scan returned exit code %d for %s: %s",
                result.returncode,
                config_path.name,
                result.stderr.strip(),
            )
        if result.stdout.strip():
            return json.loads(result.stdout)
        return None
    except subprocess.TimeoutExpired:
        logger.warning("Scan timed out for %s", config_path.name)
        return None
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        logger.warning("Scan parse error for %s: %s", config_path.name, exc)
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def analyze_config(
    config_path: Path,
    source_repo: str,
    source_file_path: str,
) -> ConfigResult:
    """Scan a single config and extract structured results.

    Args:
        config_path: Local path to the downloaded .mcp.json.
        source_repo: GitHub repository full name.
        source_file_path: File path within the repository.

    Returns:
        A ConfigResult with scan findings and flags.
    """
    result = ConfigResult(
        source_repo=source_repo,
        source_path=source_file_path,
        local_path=str(config_path),
    )

    # Check raw content for specific patterns
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        result.scan_error = "Failed to parse JSON"
        return result

    if raw.get("enableAllProjectMcpServers") is True:
        result.has_enable_all_servers = True

    # Run the actual scanner
    scan_output = scan_config(config_path)
    if scan_output is None:
        result.scan_error = "Scanner returned no output"
        return result

    findings = scan_output.get("findings", [])
    result.total_findings = len(findings)

    severity_counts: Counter[str] = Counter()
    rule_ids: list[str] = []
    for finding in findings:
        sev = finding.get("severity", "info")
        severity_counts[sev] += 1
        rule_id = finding.get("ruleId", "unknown")
        rule_ids.append(rule_id)
        # Check for secret-related findings
        if "secret" in finding.get("category", "").lower():
            result.has_hardcoded_secrets = True

    result.findings_by_severity = dict(severity_counts)
    result.rule_violations = rule_ids

    return result


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def aggregate_results(config_results: list[ConfigResult]) -> BenchmarkResults:
    """Aggregate individual config results into benchmark statistics.

    Args:
        config_results: List of per-config scan results.

    Returns:
        Aggregated BenchmarkResults with percentages and top violations.
    """
    from datetime import datetime, timezone

    total = len(config_results)
    if total == 0:
        return BenchmarkResults(crawl_timestamp=datetime.now(timezone.utc).isoformat())

    total_findings = sum(r.total_findings for r in config_results)
    severity_totals: Counter[str] = Counter()
    violation_counter: Counter[str] = Counter()
    secrets_count = sum(1 for r in config_results if r.has_hardcoded_secrets)
    enable_all_count = sum(1 for r in config_results if r.has_enable_all_servers)
    errors = sum(1 for r in config_results if r.scan_error)

    for r in config_results:
        for sev, count in r.findings_by_severity.items():
            severity_totals[sev] += count
        violation_counter.update(r.rule_violations)

    most_common = [
        {"rule_id": rule_id, "count": count}
        for rule_id, count in violation_counter.most_common(20)
    ]

    return BenchmarkResults(
        total_configs_scanned=total,
        total_findings=total_findings,
        findings_by_severity=dict(severity_totals),
        most_common_violations=most_common,
        pct_hardcoded_secrets=round((secrets_count / total) * 100, 1) if total else 0.0,
        pct_enable_all_servers=round((enable_all_count / total) * 100, 1) if total else 0.0,
        configs=[asdict(r) for r in config_results],
        crawl_timestamp=datetime.now(timezone.utc).isoformat(),
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run_benchmark(limit: int, output_path: Path) -> BenchmarkResults:
    """Execute the full benchmark pipeline.

    1. Search GitHub for public .mcp.json files.
    2. Download each config to benchmarks/data/.
    3. Run agent-audit-kit scan on each.
    4. Aggregate and write results.

    Args:
        limit: Maximum number of configs to process.
        output_path: Path to write the JSON results file.

    Returns:
        The aggregated BenchmarkResults.
    """
    logger.info("Searching GitHub for public .mcp.json files (limit=%d)...", limit)
    items = search_mcp_configs(limit=limit)
    logger.info("Found %d results from GitHub Search API.", len(items))

    config_results: list[ConfigResult] = []

    for idx, item in enumerate(items, start=1):
        repo = item.get("repository", {}).get("full_name", "unknown/unknown")
        file_path = item.get("path", "unknown")
        logger.info("[%d/%d] Processing %s/%s", idx, len(items), repo, file_path)

        local_path = download_config(item, idx)
        if local_path is None:
            logger.warning("  Skipped (download failed)")
            continue

        result = analyze_config(local_path, repo, file_path)
        config_results.append(result)
        logger.info(
            "  Findings: %d | Secrets: %s | EnableAll: %s",
            result.total_findings,
            result.has_hardcoded_secrets,
            result.has_enable_all_servers,
        )

        # Brief pause between scans to be respectful of API limits
        time.sleep(1)

    # Aggregate
    benchmark = aggregate_results(config_results)

    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(asdict(benchmark), indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Results written to %s", output_path)

    # Print summary to stdout
    _print_summary(benchmark)

    return benchmark


def _print_summary(results: BenchmarkResults) -> None:
    """Print a human-readable summary of benchmark results to stdout."""
    print("\n" + "=" * 60)
    print("  AgentAuditKit Benchmark Results")
    print("=" * 60)
    print(f"  Configs scanned:          {results.total_configs_scanned}")
    print(f"  Total findings:           {results.total_findings}")
    print(f"  Scan errors:              {results.errors}")
    print()
    print("  Findings by severity:")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = results.findings_by_severity.get(sev, 0)
        print(f"    {sev:<12} {count}")
    print()
    print(f"  Hardcoded secrets:        {results.pct_hardcoded_secrets:.1f}%")
    print(f"  enableAllProjectMcpServers: {results.pct_enable_all_servers:.1f}%")
    print()
    if results.most_common_violations:
        print("  Top rule violations:")
        for entry in results.most_common_violations[:10]:
            print(f"    {entry['rule_id']:<30} {entry['count']}")
    print("=" * 60 + "\n")


def main() -> None:
    """Entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="Benchmark AgentAuditKit against public GitHub MCP configs.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of configs to download and scan (default: 100).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(Path(__file__).resolve().parent / "results.json"),
        help="Path for the JSON results file (default: benchmarks/results.json).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable verbose logging.",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    run_benchmark(limit=args.limit, output_path=Path(args.output))


if __name__ == "__main__":
    main()
