"""Finding Validation Engine for ZeroDay v2.0.

Enforces: Hypothesis -> Test -> Observation -> Evidence -> Validation -> Finding.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from zeroday.findings.models import Finding, FindingStatus


logger = logging.getLogger(__name__)


@dataclass
class ValidationStep:
    hypothesis: str
    test_action: str
    observation: str
    evidence_verified: bool
    confidence_score: float  # 0.0 to 1.0


class FindingValidator:
    """Validates that a finding is backed by empirical proof and meets confirmation criteria."""

    def __init__(self, min_confidence_for_confirmed: float = 0.70) -> None:
        self.min_confidence = min_confidence_for_confirmed

    def validate_evidence(self, finding: Finding) -> tuple[bool, str]:
        """Verify that the finding possesses concrete evidence artifacts."""
        if not finding.evidence and not finding.poc.request_content and not finding.poc.script_code:
            return False, "Finding lacks any evidence, PoC request, or reproduction script"

        if finding.confidence < self.min_confidence:
            return (
                False,
                f"Confidence score {finding.confidence} is below confirmation "
                f"threshold ({self.min_confidence})",
            )

        if not finding.endpoint and not finding.asset_id:
            return False, "Finding must be bound to a specific endpoint or asset"

        return True, "Finding satisfies evidence and confidence validation requirements"

    def verify_finding(self, finding: Finding) -> bool:
        valid, reason = self.validate_evidence(finding)
        if valid:
            finding.status = FindingStatus.CONFIRMED
            return True
        finding.status = FindingStatus.OBSERVED
        logger.warning("Finding %s failed validation: %s", finding.finding_id, reason)
        return False
