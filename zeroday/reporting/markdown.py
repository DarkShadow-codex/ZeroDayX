"""Technical Markdown Report Generator for ZeroDay v2.0."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from zeroday.findings.models import Finding


logger = logging.getLogger(__name__)


class TechnicalReportGenerator:
    """Generates detailed technical penetration test and continuous security validation reports."""

    @staticmethod
    def generate_report(
        *,
        scan_id: str,
        target: str,
        findings: list[Finding],
        scope_summary: dict[str, Any] | None = None,
        mitre_summary: dict[str, Any] | None = None,
        purple_team_summary: dict[str, Any] | None = None,
        _coverage_summary: dict[str, Any] | None = None,
    ) -> str:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        lines = [
            "# ZeroDay Penetration Test & Security Validation Report",
            f"**Scan ID**: `{scan_id}` | **Target**: `{target}`",
            f"**Generated**: {timestamp}",
            "",
            "---",
            "",
            "## 1. Scope & Rules of Engagement",
            f"- **Primary Target**: `{target}`",
            "- **Execution Plane**: Sandboxed Kali Linux Runtime with strict scope policy",
        ]
        if scope_summary:
            allowed_domains = scope_summary.get("allowed_domains", [])
            lines.append(f"- **Authorized Domains**: {', '.join(allowed_domains) or 'None'}")
            lines.append(
                f"- **Max Rate Limit**: {scope_summary.get('max_requests_per_minute', 300)} req/min"
            )

        lines.extend(
            [
                "",
                "## 2. Assessment Methodology",
                "Testing was conducted following ZeroDay's autonomous validation lifecycle:",
                (
                    "`Discover` ➔ `Model` ➔ `Plan` ➔ `Test` ➔ `Observe` ➔ `Reason` "
                    "➔ `Validate` ➔ `Correlate` ➔ `Score` ➔ `Detect` ➔ `Remediate` ➔ `Retest`"
                ),
                "",
                "## 3. Findings Summary",
            ]
        )

        if not findings:
            lines.append("No security vulnerabilities were confirmed during this assessment.")
        else:
            lines.extend(
                [
                    "| ID | Title | Severity | CVSS | CWE | OWASP | Status |",
                    "|---|---|---|---|---|---|---|",
                ]
            )
            for f in findings:
                cwe_str = ", ".join(f.cwe) if f.cwe else "N/A"
                owasp_str = ", ".join(f.owasp) if f.owasp else "N/A"
                lines.append(
                    f"| `{f.finding_id}` | {f.title} | **{f.severity.value}** | "
                    f"{f.cvss} | {cwe_str} | {owasp_str} | `{f.status.value}` |"
                )

            lines.extend(
                [
                    "",
                    "## 4. Detailed Vulnerability Analyses",
                ]
            )

            for f in findings:
                cwe_text = ", ".join(f.cwe) or "None"
                owasp_text = ", ".join(f.owasp) or "None"
                attack_text = ", ".join(f.attack) or "None"
                lines.extend(
                    [
                        f"### {f.finding_id}: {f.title}",
                        f"- **Severity**: {f.severity.value} (CVSS: {f.cvss})",
                        f"- **Confidence**: {int(f.confidence * 100)}%",
                        f"- **Endpoint**: `{f.method} {f.endpoint}`",
                        f"- **CWE**: {cwe_text} | **OWASP**: {owasp_text}",
                        f"- **ATT&CK**: {attack_text}",
                        "",
                        "#### Description",
                        f.description or "No detailed description provided.",
                        "",
                        "#### Impact",
                        f.impact
                        or "Exploitation allows unauthorized system access or data compromise.",
                        "",
                        "#### Proof of Concept & Evidence",
                    ]
                )
                if f.poc.request_content:
                    lines.extend(
                        [
                            "```http",
                            f.poc.request_content.strip(),
                            "```",
                        ]
                    )
                if f.poc.steps:
                    lines.append("**Reproduction Steps**:")
                    lines.extend(f"1. {s}" for s in f.poc.steps)

                lines.extend(
                    [
                        "",
                        "#### Remediation",
                        f.remediation.recommendation or "Review and sanitize input parameters.",
                        "",
                    ]
                )

        if mitre_summary:
            t_tested = mitre_summary.get("tested_techniques", 0)
            t_total = mitre_summary.get("total_techniques", 0)
            lines.extend(
                [
                    "## 5. MITRE ATT&CK Framework Coverage",
                    f"- **Total Techniques Evaluated**: {t_tested} / {t_total}",
                    f"- **Coverage Percentage**: {mitre_summary.get('coverage_percent', 0.0)}%",
                    f"- **Detection Gaps Identified**: {mitre_summary.get('detection_gaps', 0)}",
                    "",
                ]
            )

        if purple_team_summary:
            d_rate = purple_team_summary.get("detection_rate", 0.0)
            lines.extend(
                [
                    "## 6. Purple Team & Detection Engineering",
                    f"- **Total Attack Probes**: {purple_team_summary.get('total_evaluations', 0)}",
                    f"- **Blue Team Detection Rate**: {d_rate}%",
                    f"- **Detection Failures**: {purple_team_summary.get('detection_failures', 0)}",
                    "",
                ]
            )

        lines.extend(
            [
                "---",
                "*Report generated by ZeroDay v2.0 Autonomous AI Red Team Platform.*",
            ]
        )
        return "\n".join(lines)
