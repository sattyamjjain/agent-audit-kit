"""Out-of-band corpus refresh for IPI / FHI payload data files.

`aak corpus update` pulls a signed JSON manifest and writes the latest
payload corpora into `agent_audit_kit/data/`. Lets defenders refresh
threat data without waiting for an AAK release.

Sigstore verification scaffolded; v0.3.8 ships SHA-256 verification
against a manifest-pinned digest. Sigstore-bundle verification queues
for v0.3.9 (matches the existing release-asset signing flow).
"""
