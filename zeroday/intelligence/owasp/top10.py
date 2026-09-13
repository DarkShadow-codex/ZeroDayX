"""OWASP Top 10 & API Security Top 10 Frameworks for ZeroDay v2.0."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class OwaspCategory:
    code: str  # e.g. "A01:2021"
    name: str  # e.g. "Broken Access Control"
    framework: str  # "OWASP_WEB_2021", "OWASP_API_2023"
    description: str


OWASP_WEB_2021: dict[str, OwaspCategory] = {
    "A01:2021": OwaspCategory(
        code="A01:2021",
        name="Broken Access Control",
        framework="OWASP_WEB_2021",
        description="Failures to enforce least privilege; horizontal/vertical escalation, IDOR.",
    ),
    "A02:2021": OwaspCategory(
        code="A02:2021",
        name="Cryptographic Failures",
        framework="OWASP_WEB_2021",
        description="Exposing sensitive data in transit or at rest; weak cryptography.",
    ),
    "A03:2021": OwaspCategory(
        code="A03:2021",
        name="Injection",
        framework="OWASP_WEB_2021",
        description="SQL, NoSQL, OS command, and LDAP injection.",
    ),
    "A04:2021": OwaspCategory(
        code="A04:2021",
        name="Insecure Design",
        framework="OWASP_WEB_2021",
        description="Missing security controls in architecture; business logic flaws.",
    ),
    "A05:2021": OwaspCategory(
        code="A05:2021",
        name="Security Misconfiguration",
        framework="OWASP_WEB_2021",
        description="Default configs, unnecessary services, open cloud storage, verbose errors.",
    ),
    "A06:2021": OwaspCategory(
        code="A06:2021",
        name="Vulnerable and Outdated Components",
        framework="OWASP_WEB_2021",
        description="Unpatched dependencies, unsupported OS, known CVEs.",
    ),
    "A07:2021": OwaspCategory(
        code="A07:2021",
        name="Identification and Authentication Failures",
        framework="OWASP_WEB_2021",
        description="Brute force susceptibility, session fixation, credential stuffing.",
    ),
    "A08:2021": OwaspCategory(
        code="A08:2021",
        name="Software and Data Integrity Failures",
        framework="OWASP_WEB_2021",
        description="Untrusted CI/CD pipelines, deserialization of untrusted data.",
    ),
    "A09:2021": OwaspCategory(
        code="A09:2021",
        name="Security Logging and Monitoring Failures",
        framework="OWASP_WEB_2021",
        description="Insufficient logging, audit trails, and real-time alerting.",
    ),
    "A10:2021": OwaspCategory(
        code="A10:2021",
        name="Server-Side Request Forgery (SSRF)",
        framework="OWASP_WEB_2021",
        description="Fetching a remote resource without validating user-supplied URL.",
    ),
}

OWASP_API_2023: dict[str, OwaspCategory] = {
    "API1:2023": OwaspCategory(
        code="API1:2023",
        name="Broken Object Level Authorization (BOLA)",
        framework="OWASP_API_2023",
        description="Manipulating object IDs in API endpoints to access other users' data.",
    ),
    "API2:2023": OwaspCategory(
        code="API2:2023",
        name="Broken Authentication",
        framework="OWASP_API_2023",
        description="Weak token validation, JWT tampering, missing auth checks.",
    ),
    "API3:2023": OwaspCategory(
        code="API3:2023",
        name="Broken Object Property Level Authorization",
        framework="OWASP_API_2023",
        description="Excessive data exposure and mass assignment of sensitive properties.",
    ),
    "API4:2023": OwaspCategory(
        code="API4:2023",
        name="Unrestricted Resource Consumption",
        framework="OWASP_API_2023",
        description="Lack of request/payload size limits, rate limiting, or execution timeouts.",
    ),
    "API5:2023": OwaspCategory(
        code="API5:2023",
        name="Broken Function Level Authorization (BFLA)",
        framework="OWASP_API_2023",
        description="Regular users invoking administrative endpoints.",
    ),
    "API6:2023": OwaspCategory(
        code="API6:2023",
        name="Unrestricted Access to Sensitive Business Flows",
        framework="OWASP_API_2023",
        description="Automated abuse of checkout, coupon, review, or ticket reservation flows.",
    ),
    "API7:2023": OwaspCategory(
        code="API7:2023",
        name="Server Side Request Forgery",
        framework="OWASP_API_2023",
        description="API fetching external webhooks or resources without validation.",
    ),
    "API8:2023": OwaspCategory(
        code="API8:2023",
        name="Security Misconfiguration",
        framework="OWASP_API_2023",
        description="Unsecured CORS, open debug routes, verbose error outputs.",
    ),
    "API9:2023": OwaspCategory(
        code="API9:2023",
        name="Improper Inventory Management",
        framework="OWASP_API_2023",
        description="Exposing unmaintained v1 API versions or shadow endpoints.",
    ),
    "API10:2023": OwaspCategory(
        code="API10:2023",
        name="Unsafe Consumption of APIs",
        framework="OWASP_API_2023",
        description="Trusting third-party API payloads without sanitation.",
    ),
}


def lookup_owasp(code: str) -> OwaspCategory | None:
    norm = code.upper().strip()
    return OWASP_WEB_2021.get(norm) or OWASP_API_2023.get(norm)
