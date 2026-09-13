"""Coverage Engine for ZeroDay v2.0."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class CoverageMetric:
    name: str
    discovered: int = 0
    tested: int = 0
    items: list[str] = field(default_factory=list)

    @property
    def percentage(self) -> float:
        return round((self.tested / self.discovered) * 100, 1) if self.discovered > 0 else 100.0


class CoverageManager:
    """Tracks systematic security testing coverage across attack surface dimensions."""

    def __init__(self) -> None:
        self.endpoints = CoverageMetric(name="Endpoints")
        self.parameters = CoverageMetric(name="Parameters")
        self.auth_flows = CoverageMetric(name="Authentication Flows")
        self.authz_matrices = CoverageMetric(name="Authorization Matrices")
        self.technologies = CoverageMetric(name="Technologies")
        self.attack_techniques = CoverageMetric(name="Attack Techniques")

    def record_discovered(self, category: str, item: str) -> None:
        metric = getattr(self, category, None)
        if isinstance(metric, CoverageMetric):
            if item not in metric.items:
                metric.items.append(item)
                metric.discovered += 1

    def record_tested(self, category: str, item: str) -> None:
        metric = getattr(self, category, None)
        if isinstance(metric, CoverageMetric):
            if item not in metric.items:
                metric.items.append(item)
                metric.discovered += 1
            metric.tested += 1

    def get_summary(self) -> dict[str, Any]:
        metrics = [
            self.endpoints,
            self.parameters,
            self.auth_flows,
            self.authz_matrices,
            self.technologies,
            self.attack_techniques,
        ]
        total_discovered = sum(m.discovered for m in metrics)
        total_tested = sum(m.tested for m in metrics)
        overall_pct = (
            round((total_tested / total_discovered) * 100, 1) if total_discovered > 0 else 100.0
        )

        return {
            "overall_coverage_percent": overall_pct,
            "total_items_discovered": total_discovered,
            "total_items_tested": total_tested,
            "metrics": {
                m.name: {
                    "discovered": m.discovered,
                    "tested": m.tested,
                    "percentage": m.percentage,
                }
                for m in metrics
            },
        }
