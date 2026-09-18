"""Finding Lifecycle State Machine for ZeroDay v2.0."""

from __future__ import annotations

import logging
import time

from zeroday.findings.models import Finding, FindingStatus


logger = logging.getLogger(__name__)


# Allowed state transitions based on Section 18
VALID_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.POTENTIAL: {FindingStatus.OBSERVED, FindingStatus.UNDER_VALIDATION},
    FindingStatus.OBSERVED: {FindingStatus.UNDER_VALIDATION, FindingStatus.CONFIRMED},
    FindingStatus.UNDER_VALIDATION: {FindingStatus.CONFIRMED, FindingStatus.OBSERVED},
    FindingStatus.CONFIRMED: {FindingStatus.DEDUPLICATED, FindingStatus.RISK_SCORED},
    FindingStatus.DEDUPLICATED: {FindingStatus.RISK_SCORED},
    FindingStatus.RISK_SCORED: {FindingStatus.REPORTED},
    FindingStatus.REPORTED: {FindingStatus.REMEDIATION, FindingStatus.RETEST},
    FindingStatus.REMEDIATION: {FindingStatus.RETEST},
    FindingStatus.RETEST: {FindingStatus.RESOLVED, FindingStatus.REOPENED},
    FindingStatus.RESOLVED: {FindingStatus.REOPENED},
    FindingStatus.REOPENED: {FindingStatus.UNDER_VALIDATION, FindingStatus.CONFIRMED},
}


class InvalidFindingTransitionError(Exception):
    """Raised when an illegal finding lifecycle transition is attempted."""


class FindingLifecycleManager:
    """Enforces deterministic lifecycle transitions for vulnerability findings."""

    @staticmethod
    def transition(
        finding: Finding,
        target_status: FindingStatus,
        *,
        reason: str = "",
    ) -> None:
        current = finding.status
        allowed = VALID_TRANSITIONS.get(current, set())

        if target_status not in allowed:
            allowed_vals = [s.value for s in allowed]
            msg = (
                f"Cannot transition finding '{finding.finding_id}' from {current.value} "
                f"to {target_status.value}. Allowed: {allowed_vals}"
            )
            logger.error(msg)
            raise InvalidFindingTransitionError(msg)

        finding.status = target_status
        finding.updated_at = time.time()
        logger.info(
            "Finding %s transitioned %s -> %s (%s)",
            finding.finding_id,
            current.value,
            target_status.value,
            reason or "no rationale provided",
        )
