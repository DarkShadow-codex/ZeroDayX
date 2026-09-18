"""CWE (Common Weakness Enumeration) Database for ZeroDay v2.0."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class CweDefinition:
    cwe_id: str  # e.g. "CWE-89"
    name: str  # e.g. "Improper Neutralization of Special Elements ('SQL Injection')"
    owasp_web_category: str  # e.g. "A03:2021"
    owasp_api_category: str | None
    typical_severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    typical_cvss: float
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CWE_DATABASE: dict[str, CweDefinition] = {
    "CWE-89": CweDefinition(
        cwe_id="CWE-89",
        name="SQL Injection",
        owasp_web_category="A03:2021",
        owasp_api_category=None,
        typical_severity="CRITICAL",
        typical_cvss=8.8,
        description="Improper Neutralization of Special Elements used in an SQL Command.",
    ),
    "CWE-79": CweDefinition(
        cwe_id="CWE-79",
        name="Cross-Site Scripting (XSS)",
        owasp_web_category="A03:2021",
        owasp_api_category=None,
        typical_severity="MEDIUM",
        typical_cvss=6.1,
        description=(
            "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')."
        ),
    ),
    "CWE-639": CweDefinition(
        cwe_id="CWE-639",
        name="Authorization Bypass Through User-Controlled Key (IDOR)",
        owasp_web_category="A01:2021",
        owasp_api_category="API1:2023",
        typical_severity="HIGH",
        typical_cvss=8.1,
        description=(
            "Authorization Bypass Through User-Controlled Key allowing unauthorized object access."
        ),
    ),
    "CWE-22": CweDefinition(
        cwe_id="CWE-22",
        name="Path Traversal",
        owasp_web_category="A01:2021",
        owasp_api_category=None,
        typical_severity="HIGH",
        typical_cvss=7.5,
        description=(
            "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')."
        ),
    ),
    "CWE-78": CweDefinition(
        cwe_id="CWE-78",
        name="OS Command Injection",
        owasp_web_category="A03:2021",
        owasp_api_category=None,
        typical_severity="CRITICAL",
        typical_cvss=9.8,
        description=(
            "Improper Neutralization of Special Elements used in an OS Command "
            "('OS Command Injection')."
        ),
    ),
    "CWE-918": CweDefinition(
        cwe_id="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        owasp_web_category="A10:2021",
        owasp_api_category="API7:2023",
        typical_severity="HIGH",
        typical_cvss=8.6,
        description="Server-Side Request Forgery (SSRF).",
    ),
    "CWE-352": CweDefinition(
        cwe_id="CWE-352",
        name="Cross-Site Request Forgery (CSRF)",
        owasp_web_category="A01:2021",
        owasp_api_category=None,
        typical_severity="MEDIUM",
        typical_cvss=6.5,
        description="Cross-Site Request Forgery (CSRF).",
    ),
    "CWE-287": CweDefinition(
        cwe_id="CWE-287",
        name="Improper Authentication",
        owasp_web_category="A07:2021",
        owasp_api_category="API2:2023",
        typical_severity="HIGH",
        typical_cvss=8.2,
        description=(
            "Improper Authentication allowing unauthorized access to application functions."
        ),
    ),
    "CWE-798": CweDefinition(
        cwe_id="CWE-798",
        name="Use of Hard-coded Credentials",
        owasp_web_category="A07:2021",
        owasp_api_category="API2:2023",
        typical_severity="HIGH",
        typical_cvss=7.8,
        description="Use of Hard-coded Credentials in application source or configuration.",
    ),
    "CWE-862": CweDefinition(
        cwe_id="CWE-862",
        name="Missing Authorization",
        owasp_web_category="A01:2021",
        owasp_api_category="API5:2023",
        typical_severity="HIGH",
        typical_cvss=8.1,
        description="Missing Authorization check for a restricted function or API endpoint.",
    ),
    "CWE-362": CweDefinition(
        cwe_id="CWE-362",
        name="Race Condition (TOCTOU)",
        owasp_web_category="A04:2021",
        owasp_api_category="API4:2023",
        typical_severity="HIGH",
        typical_cvss=7.4,
        description=(
            "Concurrent Execution using Shared Resource with Improper "
            "Synchronization ('Race Condition')."
        ),
    ),
}


class CweDatabase:
    """Provides querying and mapping for Common Weakness Enumeration records."""

    @staticmethod
    def get(cwe_id: str) -> CweDefinition | None:
        norm = cwe_id.upper().strip()
        if not norm.startswith("CWE-") and norm.isdigit():
            norm = f"CWE-{norm}"
        return CWE_DATABASE.get(norm)

    @staticmethod
    def list_all() -> list[CweDefinition]:
        return list(CWE_DATABASE.values())
