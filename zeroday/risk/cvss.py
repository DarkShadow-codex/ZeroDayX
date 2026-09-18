"""CVSS Calculation & Metric Extraction for ZeroDay v2.0."""

from __future__ import annotations

import logging
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CvssBreakdown:
    version: str  # "3.1" or "4.0"
    base_score: float
    vector_string: str
    attack_vector: str  # Network, Adjacent, Local, Physical
    attack_complexity: str  # Low, High
    privileges_required: str  # None, Low, High
    user_interaction: str  # None, Required
    scope: str  # Unchanged, Changed
    confidentiality_impact: str  # High, Low, None
    integrity_impact: str  # High, Low, None
    availability_impact: str  # High, Low, None


class CvssCalculator:
    """Parses and evaluates CVSS v3.1 / v4.0 metrics."""

    @staticmethod
    def parse_vector(vector_str: str) -> CvssBreakdown:
        parts = vector_str.strip().split("/")
        metrics: dict[str, str] = {}
        version = "3.1"

        for p in parts:
            if p.startswith("CVSS:"):
                version = p.split(":")[1]
            elif ":" in p:
                k, v = p.split(":", 1)
                metrics[k] = v

        av_map = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
        ac_map = {"L": "Low", "H": "High"}
        pr_map = {"N": "None", "L": "Low", "H": "High"}
        ui_map = {"N": "None", "R": "Required"}
        s_map = {"U": "Unchanged", "C": "Changed"}
        cia_map = {"H": "High", "L": "Low", "N": "None"}

        # Approximate base score if not externally computed
        score = 5.0
        if metrics.get("AV") == "N":
            score += 2.0
        if metrics.get("PR") == "N":
            score += 1.5
        if metrics.get("AC") == "L":
            score += 0.5
        if metrics.get("C") == "H" or metrics.get("I") == "H":
            score += 1.0

        score = min(10.0, max(0.0, score))

        return CvssBreakdown(
            version=version,
            base_score=round(score, 1),
            vector_string=vector_str,
            attack_vector=av_map.get(metrics.get("AV", "N"), "Network"),
            attack_complexity=ac_map.get(metrics.get("AC", "L"), "Low"),
            privileges_required=pr_map.get(metrics.get("PR", "N"), "None"),
            user_interaction=ui_map.get(metrics.get("UI", "N"), "None"),
            scope=s_map.get(metrics.get("S", "U"), "Unchanged"),
            confidentiality_impact=cia_map.get(metrics.get("C", "L"), "Low"),
            integrity_impact=cia_map.get(metrics.get("I", "L"), "Low"),
            availability_impact=cia_map.get(metrics.get("A", "N"), "None"),
        )
