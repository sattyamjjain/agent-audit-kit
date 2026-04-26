"""Rule presets — curated bundles of rule IDs for narrow scans.

A preset is a YAML file at `agent_audit_kit/presets/<name>.yaml` that
lists the rule IDs to activate. The CLI exposes presets via
`--preset <name>`; preset rule lists union with any `--rules`
override.

Adding a preset:

1. Create `agent_audit_kit/presets/<name>.yaml` with `rules: [...]`.
2. Document it in `docs/presets/<name>.md`.
3. Add a smoke test under `tests/test_preset_<name>.py`.
"""

from __future__ import annotations

from pathlib import Path

import yaml


_PRESETS_DIR = Path(__file__).resolve().parent


class PresetNotFoundError(KeyError):
    """Raised when --preset names a file that does not exist."""


def available_presets() -> list[str]:
    return sorted(p.stem for p in _PRESETS_DIR.glob("*.yaml"))


def load_preset(name: str) -> list[str]:
    """Return the rule-id list for a preset.

    Raises PresetNotFoundError if the file does not exist.
    """
    path = _PRESETS_DIR / f"{name}.yaml"
    if not path.is_file():
        raise PresetNotFoundError(
            f"unknown preset {name!r}; available: {', '.join(available_presets()) or '<none>'}"
        )
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return []
    rules = data.get("rules") or []
    return [r for r in rules if isinstance(r, str)]
