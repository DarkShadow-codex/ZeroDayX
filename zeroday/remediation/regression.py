"""Security Regression Testing Engine for ZeroDay v2.0."""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from zeroday.findings.models import Finding


logger = logging.getLogger(__name__)


@dataclass
class RegressionTestSpec:
    """Executable regression test definition generated from a validated finding."""

    test_id: str  # e.g. "ZD-REG-001"
    finding_id: str  # e.g. "ZD-F-000001"
    title: str
    category: str  # authorization, injection, authentication, etc.
    endpoint: str
    method: str
    payload: str
    expected_status: list[int] = field(default_factory=lambda: [401, 403, 404])
    expected_behavior: str = "unauthorized_request_denied"
    passed: bool | None = None
    execution_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SecurityRegressionEngine:
    """Transforms confirmed security findings into reproducible regression test suites."""

    def __init__(self) -> None:
        self.tests: dict[str, RegressionTestSpec] = {}

    def create_regression_test(self, finding: Finding) -> RegressionTestSpec:
        test_id = f"ZD-REG-{len(self.tests) + 1:03d}"
        category = finding.cwe[0] if finding.cwe else "general_vulnerability"

        # Determine expected status code for secure state
        expected_status = [401, 403] if "auth" in category.lower() or "639" in category else [400, 422]

        spec = RegressionTestSpec(
            test_id=test_id,
            finding_id=finding.finding_id,
            title=f"Regression test for {finding.title}",
            category=category,
            endpoint=finding.endpoint,
            method=finding.method,
            payload=finding.poc.request_content or "",
            expected_status=expected_status,
            expected_behavior="exploit_blocked_or_rejected",
        )
        self.tests[test_id] = spec
        logger.info("Created regression test %s for finding %s", test_id, finding.finding_id)
        return spec

    def list_tests(self) -> list[RegressionTestSpec]:
        return list(self.tests.values())
