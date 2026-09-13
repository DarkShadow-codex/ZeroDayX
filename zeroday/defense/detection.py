"""Detection Rule & Gap Management for ZeroDay v2.0."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    format: str  # "sigma", "yara", "suricata", "waf", "siem"
    content: str
    technique_id: str
    severity: str  # critical, high, medium, low
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionGap:
    gap_id: str
    technique_id: str
    technique_name: str
    observed_attack: str
    missing_telemetry_source: str
    suggested_remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DetectionEngine:
    """Manages generated defensive rules and detected visibility gaps."""

    def __init__(self) -> None:
        self.rules: list[DetectionRule] = []
        self.gaps: list[DetectionGap] = []

    def add_rule(self, rule: DetectionRule) -> None:
        self.rules.append(rule)

    def add_gap(self, gap: DetectionGap) -> None:
        self.gaps.append(gap)

    def list_rules(self, format_filter: str | None = None) -> list[DetectionRule]:
        if format_filter is None:
            return list(self.rules)
        return [r for r in self.rules if r.format == format_filter]
