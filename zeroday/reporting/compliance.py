"""Regulatory Compliance Mapping for ZeroDay v2.0."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from zeroday.findings.models import Finding


@dataclass
class ComplianceMapping:
    standard: str  # "NIST_CSF", "ISO_27001", "SOC_2", "PCI_DSS", "CIS_CONTROLS"
    control_id: str
    control_title: str
    status: str  # "NON_COMPLIANT", "COMPLIANT"
    impacted_by_finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ComplianceMapper:
    """Maps security findings to major industry compliance and regulatory frameworks."""

    @classmethod
    def map_findings(cls, findings: list[Finding]) -> dict[str, list[ComplianceMapping]]:
        mappings: dict[str, list[ComplianceMapping]] = {
            "SOC_2": [],
            "PCI_DSS": [],
            "ISO_27001": [],
            "NIST_CSF": [],
        }

        # Check for access control failures (A01 / CWE-639 / CWE-862)
        authz_findings = [
            f.finding_id
            for f in findings
            if any(c in f.cwe for c in ("CWE-639", "CWE-862", "CWE-287"))
        ]
        if authz_findings:
            mappings["SOC_2"].append(
                ComplianceMapping(
                    standard="SOC_2",
                    control_id="CC6.1",
                    control_title="Logical Access Controls",
                    status="NON_COMPLIANT",
                    impacted_by_finding_ids=authz_findings,
                )
            )
            mappings["PCI_DSS"].append(
                ComplianceMapping(
                    standard="PCI_DSS",
                    control_id="Req 7.1",
                    control_title="Restrict Access to Cardholder Data by Need to Know",
                    status="NON_COMPLIANT",
                    impacted_by_finding_ids=authz_findings,
                )
            )
            mappings["ISO_27001"].append(
                ComplianceMapping(
                    standard="ISO_27001",
                    control_id="A.9.4.1",
                    control_title="Information Access Restriction",
                    status="NON_COMPLIANT",
                    impacted_by_finding_ids=authz_findings,
                )
            )
            mappings["NIST_CSF"].append(
                ComplianceMapping(
                    standard="NIST_CSF",
                    control_id="PR.AC-4",
                    control_title="Access Permissions and Authorizations Enforced",
                    status="NON_COMPLIANT",
                    impacted_by_finding_ids=authz_findings,
                )
            )

        # Check for injection vulnerabilities (CWE-89, CWE-78, CWE-79)
        injection_findings = [
            f.finding_id
            for f in findings
            if any(c in f.cwe for c in ("CWE-89", "CWE-78", "CWE-79"))
        ]
        if injection_findings:
            mappings["PCI_DSS"].append(
                ComplianceMapping(
                    standard="PCI_DSS",
                    control_id="Req 6.5.1",
                    control_title="Injection Flaws (SQL, Command, XSS)",
                    status="NON_COMPLIANT",
                    impacted_by_finding_ids=injection_findings,
                )
            )
            mappings["SOC_2"].append(
                ComplianceMapping(
                    standard="SOC_2",
                    control_id="CC7.1",
                    control_title="Vulnerability Management and Secure Development",
                    status="NON_COMPLIANT",
                    impacted_by_finding_ids=injection_findings,
                )
            )
            mappings["NIST_CSF"].append(
                ComplianceMapping(
                    standard="NIST_CSF",
                    control_id="DE.CM-8",
                    control_title="Vulnerability Scans & Flaw Remediation",
                    status="NON_COMPLIANT",
                    impacted_by_finding_ids=injection_findings,
                )
            )

        return mappings
