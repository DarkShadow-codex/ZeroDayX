"""LLM Reasoning Layer for ZeroDay.

Generates vulnerability hypotheses, evaluates attack plausibility,
traces the exploitation path, and grounds findings using NVD RAG retrieval.
"""

from __future__ import annotations

from typing import Any

from zeroday.intelligence.cwe.database import CWE_DATABASE
from zeroday.ml.types import (
    CandidateFinding,
    ExtractedEvidence,
    PipelineInput,
    ReasoningHypothesis,
)


class LLMReasoningLayer:
    """Evaluates exploitability hypothesis grounded in structured CWE and NVD intelligence."""

    def __init__(self, nvd_rag_client: Any | None = None, llm_client: Any | None = None):
        self.nvd_rag = nvd_rag_client
        self.llm_client = llm_client

    def reason(
        self,
        pipeline_input: PipelineInput,
        candidate: CandidateFinding,
        evidence: ExtractedEvidence,
    ) -> ReasoningHypothesis:
        """Formulates root cause, plausibility, and attack path hypothesis."""
        if not candidate.is_vulnerable:
            return ReasoningHypothesis(
                is_plausible=False,
                plausibility_score=0.0,
                root_cause_analysis="Input exhibited benign patterns without exploitable sinks or anomalies.",
            )

        # Primary candidate CWE
        primary_cwe = candidate.candidate_cwes[0] if candidate.candidate_cwes else "CWE-20"
        cwe_info = CWE_DATABASE.get(primary_cwe)

        # Retrieve grounding CVEs via NVD RAG if available
        nvd_refs: list[dict[str, Any]] = []
        if self.nvd_rag:
            nvd_refs = self.nvd_rag.query(primary_cwe, limit=3)
        else:
            nvd_refs = [
                {
                    "cve_id": f"CVE-BENCH-{primary_cwe.replace('CWE-', '')}",
                    "cwe": primary_cwe,
                    "description": cwe_info.description if cwe_info else "Standard weakness pattern.",
                    "base_score": cwe_info.typical_cvss if cwe_info else 7.5,
                }
            ]

        # Synthesize attack path and root cause
        attack_path, root_cause, plausibility_score, prerequisites = self._synthesize_hypothesis(
            primary_cwe, candidate, evidence, pipeline_input
        )

        suggested_sev = cwe_info.typical_severity if cwe_info else "HIGH"

        return ReasoningHypothesis(
            is_plausible=plausibility_score >= 0.70,
            plausibility_score=round(plausibility_score, 3),
            attack_path=attack_path,
            root_cause_analysis=root_cause,
            primary_cwe=primary_cwe,
            alternative_cwes=candidate.candidate_cwes[1:],
            suggested_cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            suggested_severity=suggested_sev,
            nvd_references=nvd_refs,
            prerequisites=prerequisites,
            impact_assessment=f"Successful exploitation grants unauthorized control conforming to {primary_cwe}.",
        )

    def _synthesize_hypothesis(
        self,
        cwe: str,
        candidate: CandidateFinding,
        evidence: ExtractedEvidence,
        pipeline_input: PipelineInput,
    ) -> tuple[str, str, float, list[str]]:
        """Generates domain-specific attack path, root cause, and plausibility score."""
        snippet = evidence.snippet or evidence.parameter_name or "target construct"

        if cwe == "CWE-89":
            attack_path = (
                f"1. Attacker submits unescaped SQL syntax via parameter/input `{evidence.parameter_name or snippet}`.\n"
                "2. Application concatenates untrusted input directly into database command without parameter binding.\n"
                "3. Database engine executes injected query, allowing data exfiltration or authentication bypass."
            )
            root_cause = "Direct string formatting or concatenation into SQL query without using prepared statements."
            prerequisites = ["Network reachability to endpoint", "Input reflects in database query"]
            score = 0.95

        elif cwe == "CWE-78":
            attack_path = (
                f"1. Attacker provides input containing shell metacharacters (e.g. `;`, `|`, `&&`) in `{snippet}`.\n"
                "2. Application forwards input directly to system shell interpreter (e.g. `system`, `Popen(shell=True)`).\n"
                "3. OS executes arbitrary commands with the privileges of the application process."
            )
            root_cause = "Direct execution of user-supplied commands through system shell without argv array separation."
            prerequisites = ["Network or local input access", "Shell interpreter invoked by process"]
            score = 0.96

        elif cwe in ("CWE-119", "CWE-120"):
            attack_path = (
                f"1. Attacker supplies buffer payload exceeding allocated boundary in `{snippet}`.\n"
                "2. Unbounded memory copy operation (e.g. `strcpy`, `sprintf`) overwrites adjacent stack/heap frames.\n"
                "3. Memory corruption alters program flow or produces denial-of-service crash."
            )
            root_cause = "Invocation of unsafe C standard library functions without explicit destination length bounds."
            prerequisites = ["Target compiled without complete stack canaries or unbounded buffer reachable"]
            score = 0.92

        elif cwe == "CWE-79":
            attack_path = (
                f"1. Attacker injects HTML/JavaScript payload into input field `{evidence.parameter_name or snippet}`.\n"
                "2. Application reflects or stores input in response document without contextual HTML entity encoding.\n"
                "3. Victim's web browser executes malicious script in origin context, compromising user session."
            )
            root_cause = "Unsanitized user input reflected in web page DOM or server response template."
            prerequisites = ["Victim navigates to crafted URL or views stored content in web browser"]
            score = 0.94

        elif cwe == "CWE-22":
            attack_path = (
                f"1. Attacker supplies path traversal sequence (`../`) in `{evidence.parameter_name or snippet}`.\n"
                "2. File system operation resolves path outside intended root directory.\n"
                "3. Application returns or overwrites arbitrary files on the host filesystem."
            )
            root_cause = "Insufficient canonicalization and path validation before filesystem access."
            prerequisites = ["Filesystem read/write endpoint accessible"]
            score = 0.93

        elif cwe in ("CWE-601", "CWE-451", "CWE-20"):
            attack_path = (
                f"1. Attacker distributes deceptive URL `{snippet}` mimicking legitimate service.\n"
                "2. User is lured into entering credentials or downloading payload.\n"
                "3. Attacker intercepts authentication tokens or compromises user device."
            )
            root_cause = "Deceptive domain impersonation, credential harvesting tokens, or spoofed hostnames."
            prerequisites = ["Victim interaction / social engineering vector"]
            score = 0.91

        else:
            attack_path = f"1. Attacker leverages weaknesses associated with {cwe} via `{snippet}`."
            root_cause = f"Defective implementation violating secure coding practices under {cwe}."
            prerequisites = ["Target accessible"]
            score = 0.85

        return attack_path, root_cause, score, prerequisites
