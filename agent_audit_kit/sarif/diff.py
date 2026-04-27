"""SARIF baseline diff — newly_introduced / newly_resolved / still_present.

`aak diff --baseline prev.sarif --current now.sarif` consumes two
SARIF files and emits a third with every result tagged
`properties.aak_diff_state`. Lets PR-blocking workflows gate on
*regression* rather than absolute count.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class ResultKey:
    rule_id: str
    file_path: str
    line: int
    fingerprint: str

    @classmethod
    def from_result(cls, result: dict) -> "ResultKey":
        rule_id = result.get("ruleId", "")
        loc = (result.get("locations") or [{}])[0]
        phys = (loc.get("physicalLocation") or {})
        artifact = phys.get("artifactLocation") or {}
        region = phys.get("region") or {}
        file_path = artifact.get("uri", "")
        line = int(region.get("startLine", 0))
        fp = (
            (result.get("partialFingerprints") or {})
            .get("primaryLocationLineHash")
        )
        if not fp:
            digest_input = f"{rule_id}|{file_path}|{line}|{result.get('message', {}).get('text', '')}"
            fp = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        return cls(rule_id=rule_id, file_path=file_path, line=line, fingerprint=fp)


def _result_set(sarif: dict) -> dict[ResultKey, dict]:
    out: dict[ResultKey, dict] = {}
    for run in sarif.get("runs", []) or []:
        for result in run.get("results", []) or []:
            key = ResultKey.from_result(result)
            out[key] = result
    return out


def diff_sarif(baseline: dict, current: dict) -> dict:
    """Return a SARIF document with each result tagged via diff state.

    States:

    - ``newly_introduced`` — present in current, absent in baseline.
    - ``newly_resolved``   — present in baseline, absent in current.
    - ``still_present``    — present in both.
    """
    base_map = _result_set(baseline)
    cur_map = _result_set(current)
    base_keys = set(base_map)
    cur_keys = set(cur_map)

    introduced = cur_keys - base_keys
    resolved = base_keys - cur_keys
    persistent = cur_keys & base_keys

    out_results: list[dict] = []
    for key in sorted(introduced, key=lambda k: (k.rule_id, k.file_path, k.line)):
        r = dict(cur_map[key])
        r.setdefault("properties", {})["aak_diff_state"] = "newly_introduced"
        out_results.append(r)
    for key in sorted(persistent, key=lambda k: (k.rule_id, k.file_path, k.line)):
        r = dict(cur_map[key])
        r.setdefault("properties", {})["aak_diff_state"] = "still_present"
        out_results.append(r)
    for key in sorted(resolved, key=lambda k: (k.rule_id, k.file_path, k.line)):
        r = dict(base_map[key])
        r.setdefault("properties", {})["aak_diff_state"] = "newly_resolved"
        out_results.append(r)

    # Take the current run shell, replace results.
    runs = current.get("runs") or [{}]
    new_run = dict(runs[0])
    new_run["results"] = out_results
    new_run.setdefault("properties", {})["aak_diff_summary"] = {
        "newly_introduced": len(introduced),
        "newly_resolved": len(resolved),
        "still_present": len(persistent),
    }
    return {
        "$schema": current.get("$schema") or baseline.get("$schema"),
        "version": current.get("version") or baseline.get("version"),
        "runs": [new_run],
    }


def load_sarif(text: str) -> dict:
    return json.loads(text)


def dump_sarif(doc: dict, indent: int = 2) -> str:
    return json.dumps(doc, indent=indent)
