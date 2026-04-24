# OWASP Top 10 for Agentic Applications — Reference-Tool Submission

Packet for the OWASP Agentic Project reference-tool registry, per
<https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>.

## Tool metadata

- **Name:** AgentAuditKit (AAK)
- **Maintainer:** sattyamjjain (<https://github.com/sattyamjjain>)
- **Repository:** <https://github.com/sattyamjjain/agent-audit-kit>
- **License:** MIT
- **Scope:** Static scanner for MCP-connected AI agent pipelines
  (OWASP Agentic + MCP + CSA AICM overlap)
- **Integration points:** CLI, GitHub Action (Marketplace), VS Code
  extension, SARIF upload to GitHub Security tab

## Coverage statement

Every row in the OWASP Agentic Top 10 2026 has ≥3 AAK rules tagged
against it. The density floor is enforced by
`tests/test_owasp_agentic_coverage.py` — CI fails on any regression.

Machine-readable artefact (updated on every release):
`https://raw.githubusercontent.com/sattyamjjain/agent-audit-kit/main/public/owasp-agentic-coverage.json`

JSON schema (v1):

```json
{
  "schema_version": "1",
  "last_updated": "<ISO8601>",
  "aak_version": "<semver>",
  "rule_count": <int>,
  "coverage": [
    {
      "asi_id": "ASI01",
      "title": "Goal Hijack",
      "rule_density": <int>,
      "rules": [
        {"id": "AAK-...", "severity": "high",
         "cve_references": [...], "aicm_references": [...]}
      ]
    }
  ]
}
```

The human-facing rendering of the same data lives at
[docs/owasp-agentic-coverage.md](../owasp-agentic-coverage.md).

## Evidence claims

- **Density ≥3 per ASI slot:** enforced by
  `test_owasp_density_floor`, parametrised across ASI01…ASI10.
- **No typos in references:** enforced by
  `test_no_typo_owasp_agentic_references`.
- **JSON artefact schema conformance:** enforced by
  `tests/test_owasp_public_json.py`.
- **Regeneration cleanness:** enforced by
  `test_gen_coverage_script_runs_clean`.

## Contact

Issue tracker: <https://github.com/sattyamjjain/agent-audit-kit/issues>

Closes #24, #25.
