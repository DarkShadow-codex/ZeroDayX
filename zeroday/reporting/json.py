"""Structured JSON Report Generator for ZeroDay v2.0."""

from __future__ import annotations

import json
from typing import Any

from zeroday.findings.models import Finding


class JsonReportGenerator:
    """Produces comprehensive machine-readable scan records."""

    @staticmethod
    def generate_json(
        *,
        scan_id: str,
        target: str,
        findings: list[Finding],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        data = {
            "version": "2.0.0",
            "platform": "ZeroDay Autonomous AI Red Team",
            "scan_id": scan_id,
            "target": target,
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "metadata": metadata or {},
        }
        return json.dumps(data, indent=2)
