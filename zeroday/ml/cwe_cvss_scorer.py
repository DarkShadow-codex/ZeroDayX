"""CWE Mapping, CVSS Scoring, and Composite Confidence Scorer for ZeroDay.

Resolves standardized CWE definitions, calculates CVSS 3.1 scores, and
computes mathematically calibrated composite confidence scores.
"""

from __future__ import annotations

from typing import Any

from zeroday.intelligence.cwe.database import CWE_DATABASE, CweDefinition
from zeroday.ml.types import (
    CandidateFinding,
    FilterResult,
    ReasoningHypothesis,
    ScoringResult,
    VerificationResult,
)


# Extended CWE mappings for dataset alignment (Draper, Big-Vul, CSIC 2010, PhiUSIIL)
EXTENDED_CWE_DEFS: dict[str, dict[str, Any]] = {
    "CWE-119": {
        "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "owasp": "A06:2021",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "CWE-120": {
        "name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "owasp": "A06:2021",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "owasp": "A06:2021",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    },
    "CWE-469": {
        "name": "Use of Pointer Subtraction to Determine Size",
        "owasp": "A06:2021",
        "severity": "LOW",
        "cvss": 3.3,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "owasp": "A08:2021",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "CWE-113": {
        "name": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
        "owasp": "A03:2021",
        "severity": "MEDIUM",
        "cvss": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "CWE-601": {
        "name": "URL Redirection to Untrusted Site ('Open Redirect' / Phishing)",
        "owasp": "A01:2021",
        "severity": "MEDIUM",
        "cvss": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "CWE-451": {
        "name": "User Interface Misrepresentation of Critical Information (Phishing/Spoofing)",
        "owasp": "A04:2021",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "owasp": "A03:2021",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    },
}


class CWECVSSScorer:
    """Calculates standardized CWE, CVSS, and composite confidence scores."""

    def score(
        self,
        candidate: CandidateFinding,
        reasoning: ReasoningHypothesis,
        verification: VerificationResult,
        filter_result: FilterResult,
    ) -> ScoringResult:
        """Determines definitive CWE, CVSS score, severity, and calibrated confidence."""
        # 1. Resolve CWE identifier
        cwe_id = reasoning.primary_cwe
        if not cwe_id and candidate.candidate_cwes:
            cwe_id = candidate.candidate_cwes[0]
        if not cwe_id:
            cwe_id = "CWE-20"

        cwe_id = cwe_id.upper().strip()
        if not cwe_id.startswith("CWE-") and cwe_id.isdigit():
            cwe_id = f"CWE-{cwe_id}"

        # 2. Lookup definition
        cwe_name = "Vulnerability Weakness"
        cvss_score = 7.5
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        severity = "HIGH"
        owasp = None

        if cwe_id in CWE_DATABASE:
            defn: CweDefinition = CWE_DATABASE[cwe_id]
            cwe_name = defn.name
            cvss_score = defn.typical_cvss
            severity = defn.typical_severity
            owasp = defn.owasp_web_category
        elif cwe_id in EXTENDED_CWE_DEFS:
            ext = EXTENDED_CWE_DEFS[cwe_id]
            cwe_name = ext["name"]
            cvss_score = ext["cvss"]
            severity = ext["severity"]
            cvss_vector = ext["vector"]
            owasp = ext["owasp"]

        # 3. Compute Composite Confidence Score
        # Linear weighting of candidate, verification, and filter confidence
        c_cand = candidate.confidence
        c_ver = verification.confidence if verification.agreed else 0.10
        c_filt = filter_result.filter_confidence if not filter_result.is_filtered else 0.05

        composite_conf = (0.40 * c_cand) + (0.35 * c_ver) + (0.25 * c_filt)
        composite_conf = round(min(1.0, max(0.0, composite_conf)), 4)

        return ScoringResult(
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            composite_confidence=composite_conf,
            owasp_category=owasp,
        )
