"""Context-Aware Risk Engine & ZeroDay Security Score for ZeroDay v2.0."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from zeroday.findings.models import Finding
from zeroday.intelligence.attack_surface.models import Asset, AssetCriticality, ExposureLevel
from zeroday.risk.asset_risk import AssetRiskScorer
from zeroday.risk.exploitability import ExploitabilityScorer, ExploitabilityTier
from zeroday.risk.exposure import ExposureScorer


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RiskScoreResult:
    score: float  # 0.0 to 100.0
    tier: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_base: float
    asset_criticality_factor: float
    exposure_factor: float
    exploitability_factor: float
    business_impact_factor: float
    confidence_factor: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "tier": self.tier,
            "cvss_base": self.cvss_base,
            "asset_criticality_factor": self.asset_criticality_factor,
            "exposure_factor": self.exposure_factor,
            "exploitability_factor": self.exploitability_factor,
            "business_impact_factor": self.business_impact_factor,
            "confidence_factor": self.confidence_factor,
        }


class ContextAwareRiskEngine:
    """Calculates prioritized business risk by contextualizing technical CVSS."""

    @classmethod
    def calculate_risk(
        cls,
        finding: Finding,
        asset: Asset | None = None,
        *,
        business_impact: float = 1.0,  # 0.5 to 1.5
    ) -> RiskScoreResult:
        cvss = finding.cvss
        crit_factor = AssetRiskScorer.get_multiplier(asset.criticality if asset else AssetCriticality.MEDIUM)
        exp_factor = ExposureScorer.get_multiplier(asset.exposure if asset else ExposureLevel.INTERNET_FACING)

        has_poc = bool(finding.poc.request_content or finding.poc.script_code)
        exp_tier = ExploitabilityTier.POC_VERIFIED if has_poc else ExploitabilityTier.THEORETICAL
        exploit_factor = ExploitabilityScorer.get_multiplier(exp_tier)

        confidence = max(0.1, min(1.0, finding.confidence))

        # Base calculation: normalized from 0-10 CVSS base
        base_ratio = cvss / 10.0
        computed = (
            base_ratio
            * crit_factor
            * exp_factor
            * exploit_factor
            * business_impact
            * confidence
            * 100.0
        )

        final_score = max(0.0, min(100.0, computed))

        if final_score >= 85.0:
            tier = "CRITICAL"
        elif final_score >= 65.0:
            tier = "HIGH"
        elif final_score >= 40.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        return RiskScoreResult(
            score=final_score,
            tier=tier,
            cvss_base=cvss,
            asset_criticality_factor=crit_factor,
            exposure_factor=exp_factor,
            exploitability_factor=exploit_factor,
            business_impact_factor=business_impact,
            confidence_factor=confidence,
        )


@dataclass(slots=True)
class SecurityScoreReport:
    current_score: int  # 0 to 100
    previous_score: int | None
    score_delta: int
    open_findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    detection_coverage_percent: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_score": self.current_score,
            "previous_score": self.previous_score,
            "score_delta": self.score_delta,
            "open_findings_count": self.open_findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "detection_coverage_percent": self.detection_coverage_percent,
        }


class ZeroDaySecurityScore:
    """Calculates holistic organizational security score (0-100) and delta trends."""

    @staticmethod
    def calculate_posture_score(
        findings: list[Finding],
        *,
        detection_coverage: float = 80.0,
        previous_score: int | None = None,
    ) -> SecurityScoreReport:
        # Base perfect score: 100
        score = 100.0

        crit = sum(1 for f in findings if f.severity.value == "CRITICAL")
        high = sum(1 for f in findings if f.severity.value == "HIGH")
        med = sum(1 for f in findings if f.severity.value == "MEDIUM")
        low = sum(1 for f in findings if f.severity.value == "LOW")

        # Deductions
        score -= crit * 15.0
        score -= high * 7.0
        score -= med * 3.0
        score -= low * 1.0

        # Adjust for detection coverage (if low detection coverage, slight penalty)
        if detection_coverage < 50.0:
            score -= 5.0

        final_score = int(max(0, min(100, round(score))))
        delta = (final_score - previous_score) if previous_score is not None else 0

        return SecurityScoreReport(
            current_score=final_score,
            previous_score=previous_score,
            score_delta=delta,
            open_findings_count=len(findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            detection_coverage_percent=detection_coverage,
        )
