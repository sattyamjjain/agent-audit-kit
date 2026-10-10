"""Corpus manifest loader + verifier (digest-pinned, Sigstore TODO).

The manifest at `public/corpora/manifest.json` (unsigned) lists each
payload corpus AAK ships with its current SHA-256, source URL, and
last-updated timestamp. `aak corpus update` fetches the manifest,
verifies the named corpus's expected digest, and writes the body to
`agent_audit_kit/data/<corpus_id>.<ext>`.

Verification is SHA-256 digest pinning, and that is the whole of it.
Sigstore bundle verification was scoped for v0.3.9 and is not shipped;
the note saying otherwise stood for seventy-odd releases. Two reasons
it has not been built, both still true: `public/corpora/manifest.json`
publishes no signature field for a verifier to check, so the work
starts upstream of this module, and `sigstore-python` is a heavy
dependency for a tool whose stated position is stdlib-first. Digest
pinning is real verification -- it is what npm `integrity` and pip
hashes do -- so this is a deliberate stopping point rather than a
half-finished one. Signed release *assets* are a separate, working
flow (`.github/workflows/release.yml`); do not read that as covering
the corpora.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from dataclasses import dataclass
from pathlib import Path


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DEFAULT_MANIFEST_URL = (
    "https://raw.githubusercontent.com/sattyamjjain/agent-audit-kit/"
    "main/public/corpora/manifest.json"
)


@dataclass
class CorpusEntry:
    id: str
    target_path: Path
    body_url: str
    sha256: str
    source_url: str | None = None
    license: str | None = None
    fetched_at: str | None = None


class CorpusVerificationError(Exception):
    """Raised when a fetched corpus body's digest does not match."""


def _http_get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "agent-audit-kit corpus-update"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def load_manifest(url: str | None = None) -> list[CorpusEntry]:
    """Fetch + parse the corpus manifest. Raises on bad URL / JSON."""
    target = url or _DEFAULT_MANIFEST_URL
    text = _http_get(target).decode("utf-8")
    data = json.loads(text)
    entries: list[CorpusEntry] = []
    for raw in data.get("corpora", []) or []:
        cid = raw.get("id")
        target_filename = raw.get("target_filename") or f"{cid}"
        body_url = raw.get("body_url")
        sha256 = raw.get("sha256")
        if not (cid and target_filename and body_url and sha256):
            continue
        entries.append(CorpusEntry(
            id=cid,
            target_path=_DATA_DIR / target_filename,
            body_url=body_url,
            sha256=sha256,
            source_url=raw.get("source_url"),
            license=raw.get("license"),
            fetched_at=raw.get("fetched_at"),
        ))
    return entries


def fetch_and_verify(entry: CorpusEntry) -> bytes:
    """Fetch the corpus body and verify its SHA-256."""
    body = _http_get(entry.body_url)
    digest = hashlib.sha256(body).hexdigest()
    if digest.lower() != entry.sha256.lower():
        raise CorpusVerificationError(
            f"sha256 mismatch for {entry.id}: "
            f"expected {entry.sha256}, got {digest}"
        )
    return body


def write_corpus(entry: CorpusEntry, body: bytes) -> None:
    entry.target_path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic-ish write: write tempfile, then rename.
    tmp = entry.target_path.with_suffix(entry.target_path.suffix + ".tmp")
    tmp.write_bytes(body)
    os.replace(tmp, entry.target_path)
