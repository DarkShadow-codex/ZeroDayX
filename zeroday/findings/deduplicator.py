"""Finding Deduplication Engine for ZeroDay v2.0."""

from __future__ import annotations

import hashlib
import logging

from zeroday.findings.models import Finding, FindingStatus


logger = logging.getLogger(__name__)


class FindingDeduplicator:
    """Deduplicates findings based on target endpoint, parameter, CWE, and root cause."""

    def __init__(self) -> None:
        self._seen_signatures: dict[str, Finding] = {}

    @staticmethod
    def compute_signature(finding: Finding) -> str:
        """Derive a canonical deduplication signature for a finding."""
        cwe_str = ",".join(sorted(finding.cwe)) if finding.cwe else ""
        norm_endpoint = finding.endpoint.lower().strip()
        norm_title = finding.title.lower().strip()

        key = f"{norm_endpoint}|{cwe_str}|{norm_title}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Filter duplicate findings, keeping the highest confidence or most severe entry."""
        unique_findings: dict[str, Finding] = {}

        for finding in findings:
            sig = self.compute_signature(finding)
            if sig not in unique_findings:
                unique_findings[sig] = finding
            else:
                existing = unique_findings[sig]
                # Keep the one with higher confidence or cvss
                if (finding.confidence, finding.cvss) > (existing.confidence, existing.cvss):
                    unique_findings[sig] = finding
                    logger.info(
                        "Replaced duplicate finding %s with higher-confidence %s",
                        existing.finding_id,
                        finding.finding_id,
                    )
                else:
                    logger.info("Deduplicated redundant finding %s", finding.finding_id)

        deduped = list(unique_findings.values())
        for f in deduped:
            if f.status == FindingStatus.CONFIRMED:
                f.status = FindingStatus.DEDUPLICATED
        return deduped
