"""Threat Model Models for ZeroDay v2.0."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class StrideCategory(enum.Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass
class ThreatActor:
    name: str
    motivation: str
    capabilities: str
    access_level: str  # "anonymous", "authenticated_user", "insider", "admin"


@dataclass
class TrustBoundary:
    boundary_id: str
    name: str
    description: str
    inside_assets: list[str] = field(default_factory=list)
    outside_assets: list[str] = field(default_factory=list)


@dataclass
class EntryPoint:
    entry_id: str
    name: str
    protocol: str
    target: str  # URL or port
    auth_required: bool
    trust_boundary_id: str | None = None


@dataclass
class Threat:
    threat_id: str
    title: str
    stride_category: StrideCategory
    description: str
    affected_asset_id: str
    attack_technique: str = ""  # MITRE ATT&CK technique e.g. T1190
    owasp_category: str = ""
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    mitigation: str = ""


@dataclass
class SecurityControl:
    control_id: str
    name: str  # WAF, JWT verification, RBAC, Rate Limiter
    type: str  # preventative, detective, responsive
    protects_asset_ids: list[str] = field(default_factory=list)
    effective: bool = True


@dataclass
class ThreatModel:
    model_id: str
    target_name: str
    actors: list[ThreatActor] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)
    controls: list[SecurityControl] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "target_name": self.target_name,
            "actors": [asdict(a) for a in self.actors],
            "trust_boundaries": [asdict(tb) for tb in self.trust_boundaries],
            "entry_points": [asdict(ep) for ep in self.entry_points],
            "threats": [
                {**asdict(t), "stride_category": t.stride_category.value} for t in self.threats
            ],
            "controls": [asdict(c) for c in self.controls],
        }
