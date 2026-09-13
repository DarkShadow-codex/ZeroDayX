"""Vulnerability & Finding Data Models for ZeroDay v2.0."""

from __future__ import annotations

import enum
import time
from dataclasses import asdict, dataclass, field
from typing import Any


class FindingSeverity(enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(enum.Enum):
    POTENTIAL = "potential"
    OBSERVED = "observed"
    UNDER_VALIDATION = "under_validation"
    CONFIRMED = "confirmed"
    DEDUPLICATED = "deduplicated"
    RISK_SCORED = "risk_scored"
    REPORTED = "reported"
    REMEDIATION = "remediation"
    RETEST = "retest"
    RESOLVED = "resolved"
    REOPENED = "reopened"


@dataclass
class PoCSpec:
    """Proof-of-concept reproduction specification."""

    type: str = "http_request"  # http_request, curl_command, python_script, manual
    steps: list[str] = field(default_factory=list)
    request_content: str = ""
    expected_response: str = ""
    script_code: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationSpec:
    """Remediation and mitigation advice."""

    recommendation: str = ""
    root_cause: str = ""
    code_diff: str = ""  # Proposed patch diff
    fix_effort: str = "medium"  # low, medium, high
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """Standardized finding record adhering to Section 17 schema."""

    finding_id: str  # e.g. "ZD-F-000001"
    title: str
    severity: FindingSeverity
    confidence: float  # 0.0 to 1.0
    cvss: float  # 0.0 to 10.0
    cwe: list[str] = field(default_factory=list)  # e.g. ["CWE-639"]
    owasp: list[str] = field(default_factory=list)  # e.g. ["A01:2021"]
    attack: list[str] = field(default_factory=list)  # e.g. ["T1190"]
    asset_id: str = ""
    endpoint: str = ""
    method: str = "GET"
    description: str = ""
    impact: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    poc: PoCSpec = field(default_factory=PoCSpec)
    reproduction: list[str] = field(default_factory=list)
    remediation: RemediationSpec = field(default_factory=RemediationSpec)
    status: FindingStatus = FindingStatus.CONFIRMED
    scan_id: str = ""
    agent_id: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d
