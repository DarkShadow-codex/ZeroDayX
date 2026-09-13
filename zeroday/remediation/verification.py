"""Automated Retesting & Fix Verification for ZeroDay v2.0."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from zeroday.findings.lifecycle import FindingLifecycleManager
from zeroday.findings.models import Finding, FindingStatus
from zeroday.remediation.regression import RegressionTestSpec


logger = logging.getLogger(__name__)


@dataclass
class RetestResult:
    finding_id: str
    status: str  # "RESOLVED", "REOPENED"
    observed_response_code: int
    rationale: str


class AutomatedRetestVerifier:
    """Verifies whether remediation attempts successfully mitigated a finding."""

    @staticmethod
    def evaluate_retest(
        finding: Finding,
        test_spec: RegressionTestSpec,
        actual_http_status: int,
        actual_response_body: str,
    ) -> RetestResult:
        # Check if actual status matches expected secure status codes
        if actual_http_status in test_spec.expected_status:
            finding.status = FindingStatus.RESOLVED
            test_spec.passed = True
            test_spec.execution_notes = f"Verified: returned secure status {actual_http_status}"
            logger.info("Retest passed: Finding %s is RESOLVED", finding.finding_id)
            return RetestResult(
                finding_id=finding.finding_id,
                status="RESOLVED",
                observed_response_code=actual_http_status,
                rationale="Target successfully blocked the exploit payload",
            )
        else:
            finding.status = FindingStatus.REOPENED
            test_spec.passed = False
            test_spec.execution_notes = (
                f"Failed: expected {test_spec.expected_status}, received {actual_http_status}"
            )
            logger.warning("Retest failed: Finding %s is REOPENED", finding.finding_id)
            return RetestResult(
                finding_id=finding.finding_id,
                status="REOPENED",
                observed_response_code=actual_http_status,
                rationale=f"Target still accepted payload with HTTP {actual_http_status}",
            )
