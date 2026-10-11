#!/usr/bin/env python3
"""Step 3 prep: a stratified random sample of 150 AAK-MCP-001 hits, and a blind sheet.

The maintainer adjudicates 150 hits by hand; ``ppi.py`` then combines his
verdicts with a model's labels on all 1,311. This module draws the sample and
writes what he reads. It labels nothing.

**Strata** are fixed by evidence that exists before anyone labels anything:
the host class from ``measure.py`` and the probe's answer to the unauthenticated
``initialize``. They exist to spend the sample where the answer is least
predictable and to guarantee that rare kinds of hit are seen at all, not to
pre-judge a verdict, which is why the sheet never shows a hit's stratum.

**Allocation** is proportional to stratum size (largest remainder), except that
a stratum gets at least ``MIN_PER_STRATUM`` hits, or all of them if it is
smaller, so every stratum's rectifier variance is estimable. The estimators in
``ppi.py`` weight by stratum, so this departure from proportional costs no bias.

**Selection** ranks every hit in a stratum by ``SHA-256(SEED + ":" + hit_id)`` and
takes the lowest ``n_h``. That is a uniformly random subset (SHA-256 as the coin)
that anyone can recompute from the frame in ``sample.json`` with any language,
with no dependence on a Python RNG's version. ``SEED`` was fixed in this file
before the draw.

Outputs:

* ``sample.json`` (committed): seed, strata rules, ``N_h`` and ``n_h``, the frame
  (every hit_id by stratum) and the sampled hit_ids. Ids are opaque: a SHA-256
  prefix of the config's content key and the server name, re-derivable from the
  corpus and identifying nothing without it.
* ``verdicts.json`` (committed): one null verdict per sampled hit, in sheet order.
* ``CODEBOOK.md`` (committed): the label definitions.
* the blind sheet, Markdown and CSV, written OUTSIDE the repository: it holds
  third-party evidence (URLs, registry text, probe answers), all redacted.

    python benchmarks/aak_mcp_001/sample.py --population P.jsonl --write --sheet-dir /outside/repo
    python benchmarks/aak_mcp_001/sample.py --import-csv /outside/repo/adjudication-sheet.csv
    python benchmarks/aak_mcp_001/sample.py --status
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SAMPLE_JSON = HERE / "sample.json"
VERDICTS_JSON = HERE / "verdicts.json"
CODEBOOK_MD = HERE / "CODEBOOK.md"

SAMPLE_SIZE = 150
MIN_PER_STRATUM = 4
SEED = "aak-mcp-001/2026-10-12"

LABELS = ("hosted-oauth", "public-by-design", "loopback", "truly-open", "auth-other", "unknown")

# Ordered: a hit takes the first stratum whose rule holds.
STRATA: tuple[tuple[str, str], ...] = (
    ("nonpublic-host", "host is loopback or a private-network name or address"),
    ("unresolvable-host", "host is a template variable, a placeholder name, or unparseable"),
    ("credential-elsewhere", "the URL carries a credential (literal or placeholder), or the "
                             "config carries an auth-looking header the rule does not recognize"),
    ("probe-auth-required", "public https; the unauthenticated initialize got HTTP 401 or 403"),
    ("probe-accepted", "public https; the unauthenticated initialize got a JSON-RPC result"),
    ("probe-other", "public https; any other answer, no answer, or not probed"),
)

CODEBOOK = """\
# AAK-MCP-001 adjudication codebook

One code per hit. A hit is one `AAK-MCP-001` finding: one server entry, in one
config, whose `url` the rule reported as having no authentication. Judge the
**server the URL points at**, as the evidence shows it on the probe date, not
the rule and not the config's style. Look things up (the provider's docs, the
registry page, the repository) whenever the sheet is not enough, and say so in
the note. When two codes fit, take the first one in this list that does.

| Code | Use it when |
|------|-------------|
| `loopback` | The URL points at the local machine or a private network: `localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0`, RFC 1918 / link-local / CGNAT addresses, or a name that only resolves inside a LAN or container network (`host.docker.internal`, a single-label name such as `mcp-server`). Not reachable from the internet, whatever it does or does not check. |
| `hosted-oauth` | The server refuses an unauthenticated client and expects the credential to be obtained **at connect time**, not stored in the config: an HTTP 401/403 carrying a `Bearer` challenge, RFC 9728 protected-resource metadata naming an authorization server, or provider documentation saying the client signs in through OAuth. The config is correct to carry no header. |
| `auth-other` | The server enforces authentication by some other means: an API key or token in a header the rule does not recognize, a credential in the URL (a key query parameter, a capability path), or a 401/403 that asks for a static key the config does not hold. Not open; not OAuth at connect time. If the credential is a literal written into a public config, still use this code and write `literal credential` in the note: that is a secret-exposure problem, not an unauthenticated server. |
| `public-by-design` | The server accepts unauthenticated clients **on purpose**, and what it exposes is meant to be public: documentation or code search over public repositories, public reference data, a free read-only lookup, a demo the publisher labels as public. The publisher's own description or docs should say so, or the tool surface should make it plain. |
| `truly-open` | The server accepts unauthenticated clients and should not: it acts on a user's accounts or private data, writes, sends, deploys, spends, executes, exposes an organisation's internal system, or its own documentation says it requires authentication that it does not enforce. This is the true positive the rule exists to find. |
| `unknown` | The evidence does not decide it: no answer from the server (DNS failure, timeout, TLS or 5xx error), an answer that is neither a refusal nor an MCP reply, a templated or placeholder host, or an open server whose purpose cannot be determined. Write what is missing in the note. |

Decision notes:

- A 401 or 403 is a refusal, so the server is not open. Pick `hosted-oauth` or
  `auth-other` by the mechanism; if the mechanism cannot be told, `auth-other`.
  A 402 Payment Required is an access gate (x402 and the like): `auth-other`.
- A JSON-RPC `result` to the unauthenticated `initialize` means the server
  accepted the client. It does not by itself make the server `truly-open`: some
  servers accept `initialize` and authenticate later, per tool call or once a
  tool needs an account. Use `hosted-oauth` when that later step is OAuth (the
  server also serves RFC 9728 metadata, or its docs say so) and `auth-other`
  when it is something else. Otherwise choose between `public-by-design` and
  `truly-open` by what the server exposes and what its publisher says.
- A 404, 405 or 406 to the `initialize` POST usually means the URL is not the
  MCP endpoint the probe assumed (an older SSE transport, a path the client
  rewrites). Decide from the registry and docs, or use `unknown`.
- Write a one-line reason in `note` for every `truly-open` and every
  `public-by-design` verdict. Those two are the codes most open to dispute.
"""


def stratum_of(rec: dict[str, Any]) -> str:
    """The first ``STRATA`` rule a population record satisfies."""
    if rec["host_class"] in ("loopback", "private"):
        return "nonpublic-host"
    if rec["host_class"] in ("template", "placeholder", "invalid"):
        return "unresolvable-host"
    if rec.get("url_credential", "none") != "none" or rec.get("header_auth", "none") != "none":
        return "credential-elsewhere"
    probe = rec.get("probe") or {}
    init = probe.get("initialize") or {}
    outcome = init.get("outcome")
    if probe.get("status") == "probed" and outcome == "auth-required":
        return "probe-auth-required"
    if probe.get("status") == "probed" and outcome == "accepted":
        return "probe-accepted"
    return "probe-other"


def allocate(sizes: dict[str, int], n: int = SAMPLE_SIZE,
             minimum: int = MIN_PER_STRATUM) -> dict[str, int]:
    """Proportional allocation by largest remainder, with a per-stratum floor.

    A stratum smaller than the floor is taken whole; every other stratum gets
    at least the floor; the rest of the budget goes proportionally. Deterministic:
    remainders tie-break by stratum name.
    """
    total = sum(sizes.values())
    if n > total:
        raise ValueError(f"sample size {n} exceeds population {total}")
    fixed: dict[str, int] = {}
    while True:
        free = {h: s for h, s in sizes.items() if h not in fixed and s > 0}
        budget = n - sum(fixed.values())
        free_total = sum(free.values())
        quotas = {h: budget * s / free_total for h, s in free.items()} if free_total else {}
        low = {h: min(sizes[h], minimum) for h, q in quotas.items() if q < min(sizes[h], minimum)}
        if not low:
            break
        fixed.update(low)
        if sum(fixed.values()) > n:
            raise ValueError(f"sample size {n} cannot give every stratum its floor of {minimum}")
    alloc = dict(fixed)
    base = {h: int(q) for h, q in quotas.items()}
    alloc.update(base)
    left = n - sum(alloc.values())
    order = sorted(quotas, key=lambda h: (-(quotas[h] - base[h]), h))
    for h in order[:left]:
        alloc[h] += 1
    for h in sizes:
        alloc.setdefault(h, 0)
        if alloc[h] > sizes[h]:
            raise ValueError(f"allocation overflow in {h!r}")
    return dict(sorted(alloc.items()))


def rank(seed: str, hit_id: str) -> str:
    return hashlib.sha256(f"{seed}:{hit_id}".encode("utf-8")).hexdigest()


def draw(frame: dict[str, list[str]], alloc: dict[str, int], seed: str = SEED) -> list[dict[str, Any]]:
    """The ``n_h`` lowest-ranked hits per stratum, then a stratum-blind sheet order."""
    picked: list[dict[str, Any]] = []
    for h in sorted(frame):
        ids = sorted(frame[h], key=lambda i: rank(seed, i))[: alloc.get(h, 0)]
        picked.extend({"hit_id": i, "stratum": h} for i in ids)
    picked.sort(key=lambda r: rank(seed + "/sheet-order", r["hit_id"]))
    for no, r in enumerate(picked, 1):
        r["sheet_no"] = no
    return picked


def build_sample(records: list[dict[str, Any]], seed: str = SEED, n: int = SAMPLE_SIZE,
                 probe_dates: list[str] | None = None) -> dict[str, Any]:
    frame: dict[str, list[str]] = {h: [] for h, _ in STRATA}
    for rec in records:
        frame[stratum_of(rec)].append(rec["hit_id"])
    frame = {h: sorted(ids) for h, ids in frame.items() if ids}
    sizes = {h: len(ids) for h, ids in frame.items()}
    alloc = allocate(sizes, n)
    sample = draw(frame, alloc, seed)
    return {
        "_comment": (
            "Stratified random sample of AAK-MCP-001 hits for blind human adjudication. "
            "Selection: within each stratum, the n_h hits with the lowest "
            "SHA-256(seed + ':' + hit_id). Re-derive with sample.py from the frame below. "
            "hit_id = first 16 hex of SHA-256(config content key + NUL + server name)."
        ),
        "seed": seed,
        "sample_size": n,
        "min_per_stratum": MIN_PER_STRATUM,
        "probe_dates_utc": probe_dates or [],
        "strata": [
            {"stratum": h, "rule": rule, "N": sizes.get(h, 0), "n": alloc.get(h, 0)}
            for h, rule in STRATA if h in sizes
        ],
        "population": sum(sizes.values()),
        "frame": frame,
        "sample": [{"hit_id": r["hit_id"], "stratum": r["stratum"], "sheet_no": r["sheet_no"]}
                   for r in sample],
    }


def verdicts_template(sample_doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "_comment": (
            "Human adjudication of the AAK-MCP-001 sample. No script writes a verdict "
            "except sample.py --import-csv, which copies them from the sheet you filled. "
            f"Codes: {', '.join(LABELS)} (CODEBOOK.md). While any verdict is null the "
            "measurement is pending and no rate may be stated."
        ),
        "rater": None,
        "run_date": None,
        "codebook": "benchmarks/aak_mcp_001/CODEBOOK.md",
        "verdicts": [
            {"sheet_no": r["sheet_no"], "hit_id": r["hit_id"], "verdict": None, "note": ""}
            for r in sorted(sample_doc["sample"], key=lambda r: r["sheet_no"])
        ],
    }


# ---------------------------------------------------------------------------
# The blind sheet
# ---------------------------------------------------------------------------


def _repo_hint(config_id: str) -> str:
    """``0001_owner_repo.mcp.json`` -> ``owner_repo`` (the crawler replaced "/"
    with "_", so the split between owner and repo is ambiguous)."""
    stem = config_id[:-len(".mcp.json")] if config_id.endswith(".mcp.json") else config_id
    return stem.split("_", 1)[1] if "_" in stem else stem


def _probe_lines(probe: dict[str, Any] | None) -> list[str]:
    if not probe:
        return ["- probe: no record"]
    if probe.get("status") == "not probed":
        return [f"- probe: not probed ({probe.get('reason')})"]
    if probe.get("status") == "skipped":
        return [f"- probe: skipped ({probe.get('skip_reason')})"]
    init = probe.get("initialize") or {}
    out = []
    if init.get("error"):
        out.append(f"- initialize POST: no HTTP answer ({init['error']})")
    else:
        out.append(f"- initialize POST: HTTP {init.get('http_status')}, "
                   f"content-type `{init.get('content_type') or ''}`")
    for v in init.get("www_authenticate") or []:
        out.append(f"  - WWW-Authenticate: `{v}`")
    rpc = init.get("jsonrpc") or {}
    if rpc.get("result"):
        out.append(f"  - JSON-RPC result: server `{rpc.get('server_name')}` "
                   f"{rpc.get('server_version') or ''}, protocol {rpc.get('protocol_version')}, "
                   f"capabilities {', '.join(rpc.get('capabilities') or []) or '(none)'}")
    elif rpc.get("error_code") is not None:
        out.append(f"  - JSON-RPC error {rpc.get('error_code')}: {rpc.get('error_message')}")
    if init.get("mcp_session_id"):
        out.append("  - the server issued a protocol session id (value not recorded)")
    if init.get("body_snippet"):
        out.append(f"  - body starts: `{init['body_snippet']}`")
    prm = probe.get("prm") or {}
    variants = prm.get("by_variant") or {}
    for k, v in variants.items():
        if v is None:
            continue
        what = v.get("error") or f"HTTP {v.get('http_status')}"
        extra = ""
        if v.get("served"):
            aus = ", ".join(v.get("authorization_servers") or []) or "none listed"
            extra = f", metadata served, authorization servers: {aus}"
        out.append(f"- RFC 9728 metadata, {k} URL: {what}{extra}")
    return out


def _registry_lines(reg: dict[str, Any] | None) -> list[str]:
    if not reg:
        return []
    # No `auth_mode`: it is fetch_registry's own summary of the remotes' headers,
    # a derived label, and the headers themselves are listed below.
    out = [f"- registry: `{reg.get('name')}` v{reg.get('version')}, status {reg.get('registry_status')}"]
    if reg.get("title"):
        out.append(f"  - title: {reg['title']}")
    if reg.get("description"):
        out.append(f"  - description: {reg['description']}")
    for r in reg.get("remotes") or []:
        hdrs = "; ".join(
            f"{h['name']} (secret={h['is_secret']}, required={h['is_required']}, value={h['value_kind']})"
            for h in r.get("headers") or []
        ) or "no headers"
        out.append(f"  - remote {r.get('type')}: `{r.get('url')}` ({hdrs})")
    for key in ("website_url", "repository_url"):
        if reg.get(key):
            out.append(f"  - {key.replace('_', ' ')}: {reg[key]}")
    return out


def sheet_markdown(sample_doc: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> str:
    parts = [
        "# AAK-MCP-001 blind adjudication sheet",
        "",
        "Third-party evidence, redacted. Keep this file out of the repository.",
        f"Sample: {len(sample_doc['sample'])} of {sample_doc['population']} hits, stratified "
        f"random, seed `{sample_doc['seed']}`. Probe run (UTC): "
        f"{', '.join(sample_doc.get('probe_dates_utc') or []) or 'none'}.",
        "Record verdicts in `benchmarks/aak_mcp_001/verdicts.json`, or fill the `verdict` "
        "column of the CSV beside this file and run `sample.py --import-csv`.",
        "",
        CODEBOOK,
        "---",
        "",
    ]
    for row in sorted(sample_doc["sample"], key=lambda r: r["sheet_no"]):
        rec = by_id[row["hit_id"]]
        parts.append(f"## {row['sheet_no']}. `{row['hit_id']}`")
        parts.append("")
        src = rec["source"]
        if src == "crawl":
            parts.append(f"- source: GitHub crawl, file `{rec['config_id']}` "
                         f"(repository hint `{_repo_hint(rec['config_id'])}`)")
        else:
            parts.append(f"- source: MCP Registry, server `{rec['config_id']}`")
        parts.append(f"- server entry: `{rec['server_name']}`, declared type `{rec['declared_type'] or '(none)'}`, "
                     f"entry keys {json.dumps(rec['entry_shape'], sort_keys=True)}")
        parts.append(f"- URL: `{rec['url']}`")
        if rec.get("headers"):
            hdrs = ", ".join(f"`{h['name']}` ({h['value_kind']})" for h in rec["headers"])
            parts.append(f"- configured headers (names only): {hdrs}")
        parts.append(f"- hits in the same config: {rec['config_hits']}")
        parts.extend(_registry_lines(rec.get("registry")))
        parts.extend(_probe_lines(rec.get("probe")))
        parts.append("")
        parts.append("**Verdict:** `__________`  **Note:** ")
        parts.append("")
    return "\n".join(parts) + "\n"


SHEET_COLUMNS = (
    "sheet_no", "hit_id", "source", "config_id", "server_name", "url",
    "registry_title", "registry_description", "registry_remote_headers",
    "initialize_http_status", "www_authenticate", "jsonrpc_server", "rfc9728_metadata_served",
    "verdict", "note",
)


def sheet_rows(sample_doc: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for row in sorted(sample_doc["sample"], key=lambda r: r["sheet_no"]):
        rec = by_id[row["hit_id"]]
        reg = rec.get("registry") or {}
        probe = rec.get("probe") or {}
        init = probe.get("initialize") or {}
        rpc = init.get("jsonrpc") or {}
        rows.append({
            "sheet_no": row["sheet_no"],
            "hit_id": row["hit_id"],
            "source": rec["source"],
            "config_id": rec["config_id"],
            "server_name": rec["server_name"],
            "url": rec["url"],
            "registry_title": reg.get("title") or "",
            "registry_description": reg.get("description") or "",
            "registry_remote_headers": "; ".join(
                f"{h['name']} (secret={h['is_secret']})"
                for r in reg.get("remotes") or [] for h in r.get("headers") or []
            ),
            "initialize_http_status": init.get("http_status") or init.get("error") or probe.get("status") or "",
            "www_authenticate": " | ".join(init.get("www_authenticate") or []),
            "jsonrpc_server": rpc.get("server_name") or "",
            "rfc9728_metadata_served": "" if probe.get("status") != "probed" else
            ("yes" if (probe.get("prm") or {}).get("served") else "no"),
            "verdict": "",
            "note": "",
        })
    return rows


def write_sheet(sample_doc: dict[str, Any], records: list[dict[str, Any]], out_dir: Path) -> tuple[Path, Path]:
    leaks = _endpoints().leak_report
    by_id = {r["hit_id"]: r for r in records}
    md = sheet_markdown(sample_doc, by_id)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(SHEET_COLUMNS))
    writer.writeheader()
    writer.writerows(sheet_rows(sample_doc, by_id))
    csv_text = buf.getvalue()
    found = leaks(md) + leaks(csv_text)
    if found:
        raise RuntimeError(f"refusing to write the sheet: {len(found)} secret-pattern match(es)")
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path, csv_path = out_dir / "adjudication-sheet.md", out_dir / "adjudication-sheet.csv"
    md_path.write_text(md, encoding="utf-8")
    csv_path.write_text(csv_text, encoding="utf-8")
    return md_path, csv_path


def _endpoints() -> Any:
    import importlib.util

    key = "aak_mcp_001_endpoints"
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, HERE / "endpoints.py")
    if spec is None or spec.loader is None:
        raise ImportError("endpoints.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


def import_csv(csv_path: Path, verdicts_doc: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Copy filled ``verdict``/``note`` cells into a verdicts document. Rejects an
    unknown code or a hit_id that is not in the sample; blank cells stay null."""
    by_id = {v["hit_id"]: v for v in verdicts_doc["verdicts"]}
    set_count = 0
    with csv_path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            hid = (row.get("hit_id") or "").strip()
            verdict = (row.get("verdict") or "").strip()
            if hid not in by_id:
                raise ValueError(f"hit_id {hid!r} is not in the sample")
            if not verdict:
                continue
            if verdict not in LABELS:
                raise ValueError(f"sheet {row.get('sheet_no')}: {verdict!r} is not a code ({', '.join(LABELS)})")
            by_id[hid]["verdict"] = verdict
            by_id[hid]["note"] = (row.get("note") or "").strip()
            set_count += 1
    return verdicts_doc, set_count


def write_artifacts(sample_doc: dict[str, Any], sample_path: Path = SAMPLE_JSON,
                    verdicts_path: Path = VERDICTS_JSON, codebook_path: Path = CODEBOOK_MD) -> None:
    """Write the committed sample, the null-verdict template and the codebook.

    Refuses once any verdict is set: a re-draw would orphan hand-made verdicts
    or, worse, silently replace them with nulls. Delete verdicts.json by hand if
    a fresh sample is really wanted, and say why in the commit.
    """
    if verdicts_path.is_file():
        existing = json.loads(verdicts_path.read_text(encoding="utf-8"))
        if any(v.get("verdict") is not None for v in existing.get("verdicts", [])):
            raise ValueError(f"{verdicts_path.name} already holds verdicts; not overwriting it")
    sample_path.write_text(json.dumps(sample_doc, indent=2) + "\n", encoding="utf-8")
    verdicts_path.write_text(json.dumps(verdicts_template(sample_doc), indent=2) + "\n", encoding="utf-8")
    codebook_path.write_text(CODEBOOK, encoding="utf-8")


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO)
    except ValueError:
        return False
    return True


def read_population(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--population", type=Path, help="population.jsonl from measure.py")
    ap.add_argument("--write", action="store_true", help="write sample.json, verdicts.json, CODEBOOK.md")
    ap.add_argument("--sheet-dir", type=Path, default=None, help="where the blind sheet goes (outside the repo)")
    ap.add_argument("--import-csv", type=Path, default=None, help="copy verdicts from a filled sheet CSV")
    ap.add_argument("--status", action="store_true", help="how many verdicts are set")
    args = ap.parse_args(argv)

    if args.status or args.import_csv:
        doc = json.loads(VERDICTS_JSON.read_text(encoding="utf-8"))
        if args.import_csv:
            doc, n = import_csv(args.import_csv, doc)
            VERDICTS_JSON.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
            print(f"imported {n} verdicts into {VERDICTS_JSON.relative_to(REPO)}")
        counts = Counter(v["verdict"] or "(pending)" for v in doc["verdicts"])
        print(f"verdicts: {dict(sorted(counts.items()))}")
        return 0

    if not args.population:
        ap.error("--population is required to draw the sample")
    records = read_population(args.population)
    dates = sorted({str((r.get("probe") or {}).get("initialize", {}).get("ts") or "")[:10]
                    for r in records if (r.get("probe") or {}).get("status") == "probed"} - {""})
    sample_doc = build_sample(records, probe_dates=dates)
    for s in sample_doc["strata"]:
        print(f"  {s['stratum']:22} N={s['N']:5}  n={s['n']:4}")
    if args.write:
        try:
            write_artifacts(sample_doc)
        except ValueError as exc:
            print(f"refusing: {exc}", file=sys.stderr)
            return 1
        print(f"wrote {SAMPLE_JSON.name}, {VERDICTS_JSON.name}, {CODEBOOK_MD.name}")
    if args.sheet_dir:
        if _inside_repo(args.sheet_dir):
            print("refusing to write third-party evidence inside the repository", file=sys.stderr)
            return 2
        md, csv_path = write_sheet(sample_doc, records, args.sheet_dir)
        print(f"wrote {md} and {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
