"""Threat Intelligence Engine for ZeroDay v2.0."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ThreatIntelAdvisory:
    cve_id: str
    title: str
    severity: str
    cvss: float
    affected_packages: list[str] = field(default_factory=list)
    description: str = ""
    exploit_available: bool = False
    epss_score: float = 0.0  # Exploit Prediction Scoring System

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ThreatIntelEngine:
    """Provides threat intelligence, exploitability metrics, and CVE lookups."""

    def __init__(self) -> None:
        self._advisories: dict[str, ThreatIntelAdvisory] = {}

    def register_advisory(self, advisory: ThreatIntelAdvisory) -> None:
        self._advisories[advisory.cve_id.upper()] = advisory

    def lookup_cve(self, cve_id: str) -> ThreatIntelAdvisory | None:
        return self._advisories.get(cve_id.upper().strip())

    def match_package(self, package_name: str, version: str) -> list[ThreatIntelAdvisory]:
        matches = []
        pkg_lower = package_name.lower()
        for adv in self._advisories.values():
            for aff in adv.affected_packages:
                if pkg_lower in aff.lower():
                    matches.append(adv)
        return matches
