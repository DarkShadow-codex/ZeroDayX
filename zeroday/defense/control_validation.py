"""Security Control Validation for ZeroDay v2.0."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class ControlValidationResult:
    control_name: str  # WAF, Rate Limiting, Security Headers, AuthZ
    target: str
    status: str  # "EFFECTIVE", "GAP", "NOT_TESTED"
    evidence: str
    bypass_possible: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SecurityControlValidator:
    """Validates real-world effectiveness of target security controls."""

    def __init__(self) -> None:
        self.results: list[ControlValidationResult] = []

    def evaluate_waf(
        self,
        target: str,
        http_status: int,
        response_body: str,
    ) -> ControlValidationResult:
        """Analyze whether WAF successfully blocked malicious probe."""
        blocked = http_status in (403, 406, 429) or any(
            sig in response_body.lower()
            for sig in (
                "cloudflare",
                "waf",
                "access denied",
                "blocked by security policy",
                "mod_security",
            )
        )
        status = "EFFECTIVE" if blocked else "GAP"
        evidence = f"HTTP {http_status} returned on attack probe"

        res = ControlValidationResult(
            control_name="Web Application Firewall (WAF)",
            target=target,
            status=status,
            evidence=evidence,
            bypass_possible=not blocked,
        )
        self.results.append(res)
        return res

    def evaluate_rate_limit(
        self,
        target: str,
        requests_sent: int,
        rate_limited: bool,
    ) -> ControlValidationResult:
        status = "EFFECTIVE" if rate_limited else "GAP"
        evidence = f"Sent {requests_sent} rapid requests; 429 received: {rate_limited}"

        res = ControlValidationResult(
            control_name="Rate Limiting",
            target=target,
            status=status,
            evidence=evidence,
            bypass_possible=not rate_limited,
        )
        self.results.append(res)
        return res
