"""AIVSS v0.8 schema (dataclasses, no Pydantic dependency).

AIVSS v0.8 (https://aivss.owasp.org, public review 2026-04-16) layers
four optional vectors on top of a CVSS-like base:

    AARS                — Agentic Autonomy Risk Score multipliers
                          (tool-use, internet-egress, persistent-memory,
                           human-in-loop)
    Environmental       — deployment-context modifiers
    Threat              — threat-intel availability of a working PoC
    ExploitAvailability — public exploit / patch state

Every emitted score carries `aivss_version: "0.8"` so a reader can
dispatch on schema version. AAK only emits v0.8 today; v0.9/v1.0 land
in their own modules.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


@dataclass
class AARSVector:
    """Agentic Autonomy Risk Score booleans."""

    has_tool_use: bool = False
    internet_egress: bool = False
    persistent_memory: bool = False
    # Inverted: human_in_loop=True LOWERS risk.
    human_in_loop: bool = False

    def multiplier(self) -> float:
        """Compute the AARS multiplier in [0.5, 1.6].

        Each "true" autonomy flag adds 0.15; human-in-loop subtracts
        0.25 (capped at 0.5 floor). Numbers are AAK's pinned defaults
        for the v0.8 review window — documented in
        docs/scoring/aivss.md and revisited when v0.9 ships.
        """
        score = 1.0
        for key in ("has_tool_use", "internet_egress", "persistent_memory"):
            if getattr(self, key):
                score += 0.15
        if self.human_in_loop:
            score -= 0.25
        return max(0.5, min(1.6, round(score, 3)))


@dataclass
class EnvironmentalVector:
    """Deployment-context modifiers."""

    network_exposure: Literal["internal", "vpc", "internet"] = "internal"
    data_sensitivity: Literal["public", "internal", "confidential", "regulated"] = "internal"
    blast_radius: Literal["pod", "host", "cluster", "tenant"] = "host"


@dataclass
class ThreatVector:
    """Threat-intel signals."""

    poc_public: bool = False
    weaponized: bool = False
    in_the_wild: bool = False


@dataclass
class ExploitAvailability:
    """Patch / exploit state."""

    patch_available: bool = False
    patch_version: str | None = None
    workaround_available: bool = False


@dataclass
class AIVSSScore:
    """Full v0.8 score record."""

    aivss_version: Literal["0.8"] = "0.8"
    base_score: float = 0.0
    aars: AARSVector = field(default_factory=AARSVector)
    environmental: EnvironmentalVector = field(default_factory=EnvironmentalVector)
    threat: ThreatVector = field(default_factory=ThreatVector)
    exploit: ExploitAvailability = field(default_factory=ExploitAvailability)
    final_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AIVSSScore":
        return cls(
            aivss_version=data.get("aivss_version", "0.8"),
            base_score=float(data.get("base_score", 0.0)),
            aars=AARSVector(**data.get("aars", {})),
            environmental=EnvironmentalVector(**data.get("environmental", {})),
            threat=ThreatVector(**data.get("threat", {})),
            exploit=ExploitAvailability(**data.get("exploit", {})),
            final_score=float(data.get("final_score", 0.0)),
        )


__all__ = [
    "AARSVector",
    "AIVSSScore",
    "EnvironmentalVector",
    "ExploitAvailability",
    "ThreatVector",
]
