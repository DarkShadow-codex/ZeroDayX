"""Remediation & Root-Cause Advice Engine for ZeroDay v2.0."""

from __future__ import annotations

import logging

from zeroday.findings.models import Finding, RemediationSpec


logger = logging.getLogger(__name__)


class RemediationAdvisor:
    """Provides tailored root-cause analysis and secure code fix recommendations."""

    @staticmethod
    def generate_recommendation(finding: Finding) -> RemediationSpec:
        cwe_list = [c.upper() for c in finding.cwe]

        if "CWE-89" in cwe_list:
            return RemediationSpec(
                root_cause="Untrusted user input concatenated directly into raw database query",
                recommendation=(
                    "Use parameterized queries or ORM object models (e.g. PreparedStatements). "
                    "Never concatenate variables into SQL query strings."
                ),
                code_diff="",
                fix_effort="low",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ],
            )
        if "CWE-79" in cwe_list:
            return RemediationSpec(
                root_cause=(
                    "User-controlled input reflected or stored in DOM without "
                    "context-aware HTML entity encoding"
                ),
                recommendation=(
                    "Use context-sensitive output encoding (e.g. DOMPurify or framework "
                    "auto-escaping) and implement a strict Content Security Policy (CSP)."
                ),
                code_diff="",
                fix_effort="low",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ],
            )
        if "CWE-639" in cwe_list or "CWE-862" in cwe_list:
            return RemediationSpec(
                root_cause=(
                    "Missing server-side authorization check comparing requesting "
                    "user identity with object owner"
                ),
                recommendation=(
                    "Enforce object-level access control on every record lookup. "
                    "Retrieve objects using `WHERE id = ? AND tenant_id = ?` or verify "
                    "user session ownership before serving data."
                ),
                code_diff="",
                fix_effort="medium",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
                ],
            )
        if "CWE-918" in cwe_list:
            return RemediationSpec(
                root_cause=(
                    "Backend client requests external URL supplied directly by client "
                    "without network allowlisting"
                ),
                recommendation=(
                    "Implement strict URL allowlisting, reject private IP ranges "
                    "(RFC 1918 / 169.254.169.254), and disable follow-redirects."
                ),
                code_diff="",
                fix_effort="medium",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                ],
            )

        cwe_str = ", ".join(finding.cwe) or "general vulnerability"
        return RemediationSpec(
            root_cause=f"Security weakness mapped to {cwe_str}",
            recommendation=(
                "Review the affected endpoint implementation, enforce strict input "
                "validation, and implement defensive boundary controls."
            ),
            code_diff="",
            fix_effort="medium",
            references=[],
        )
