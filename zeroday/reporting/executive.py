"""Executive Security Report Generator for ZeroDay v2.0."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from zeroday.findings.models import Finding
    from zeroday.risk.scoring import SecurityScoreReport


logger = logging.getLogger(__name__)


class ExecutiveReportGenerator:
    """Generates high-level executive security posture summaries."""

    @staticmethod
    def generate_report(
        project_name: str,
        target_name: str,
        findings: list[Finding],
        posture_score: SecurityScoreReport,
        top_attack_paths: list[dict[str, Any]] | None = None,
    ) -> str:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        delta_str = (
            f"(+{posture_score.score_delta})"
            if posture_score.score_delta > 0
            else f"({posture_score.score_delta})"
        )
        if posture_score.score_delta == 0:
            delta_str = "(unchanged)"

        lines = [
            "# ZeroDay Executive Security Posture Assessment",
            f"**Project**: {project_name} | **Target**: {target_name}",
            f"**Date**: {timestamp}",
            "",
            "---",
            "",
            "## Executive Summary",
            (
                f"ZeroDay completed an autonomous security validation of `{target_name}`. "
                "The assessment evaluates real-world attack surfaces, validates exploitability "
                "with empirical evidence, maps threat paths to critical assets, and measures "
                "defensive detection coverage."
            ),
            "",
            "### ZeroDay Security Score",
            f"# **{posture_score.current_score} / 100** {delta_str}",
            "",
            f"- **Detection Coverage**: {posture_score.detection_coverage_percent}%",
            f"- **Open Findings**: {posture_score.open_findings_count}",
            f"  - **Critical**: {posture_score.critical_count}",
            f"  - **High**: {posture_score.high_count}",
            f"  - **Medium**: {posture_score.medium_count}",
            f"  - **Low**: {posture_score.low_count}",
            "",
            "---",
            "",
            "## Critical Vulnerabilities Requiring Immediate Remediation",
        ]

        crit_findings = [f for f in findings if f.severity.value in ("CRITICAL", "HIGH")]
        if not crit_findings:
            lines.append("No Critical or High severity vulnerabilities were identified.")
        else:
            for f in crit_findings:
                impact = f.impact or "Unauthorized access / security control compromise."
                rec = (
                    f.remediation.recommendation
                    or "Apply strict server-side authorization and parameter validation."
                )
                lines.extend(
                    [
                        f"### [{f.severity.value}] {f.title} (`{f.finding_id}`)",
                        f"- **CVSS Score**: {f.cvss} | **Confidence**: {int(f.confidence * 100)}%",
                        f"- **Endpoint**: `{f.method} {f.endpoint}`",
                        f"- **Impact**: {impact}",
                        f"- **Recommended Fix**: {rec}",
                        "",
                    ]
                )

        if top_attack_paths:
            lines.extend(
                [
                    "---",
                    "",
                    "## High-Impact Exploit Paths Identified",
                ]
            )
            for path in top_attack_paths:
                path_str = " ➔ ".join(path.get("labels", []))
                lines.append(f"- **Path {path.get('path_id')}**: {path_str}")
                conf_pct = int(path.get("confidence", 1.0) * 100)
                lines.append(f"  - *Cost*: {path.get('total_cost')} | *Confidence*: {conf_pct}%")

        lines.extend(
            [
                "",
                "---",
                "*Generated automatically by ZeroDay Autonomous AI Red Team & "
                "Security Validation Platform.*",
            ]
        )

        return "\n".join(lines)
