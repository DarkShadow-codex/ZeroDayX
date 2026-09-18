"""Structured Report Generator Module for ZeroDay.

Converts confirmed pipeline findings into standardized Finding records
(adhering to Section 17 schema in zeroday/findings/models.py) with
reproduction steps (PoCSpec) and actionable remediation diffs (RemediationSpec).
"""

from __future__ import annotations

import uuid
from typing import Any

from zeroday.findings.models import (
    Finding,
    FindingSeverity,
    FindingStatus,
    PoCSpec,
    RemediationSpec,
)
from zeroday.ml.types import (
    CandidateFinding,
    ExtractedEvidence,
    FilterResult,
    InputType,
    PipelineInput,
    ReasoningHypothesis,
    ScoringResult,
    VerificationResult,
)


class ReportGenerator:
    """Generates comprehensive, audit-ready structured findings and reports."""

    def generate(
        self,
        pipeline_input: PipelineInput,
        candidate: CandidateFinding,
        evidence: ExtractedEvidence,
        reasoning: ReasoningHypothesis,
        verification: VerificationResult,
        filter_result: FilterResult,
        scoring: ScoringResult,
    ) -> Finding:
        """Constructs a standardized Finding object adhering to ZeroDay architecture."""
        finding_id = f"ZD-F-{uuid.uuid4().hex[:6].upper()}"

        # Map string severity to FindingSeverity enum
        sev_str = scoring.severity.upper()
        if sev_str == "CRITICAL":
            sev_enum = FindingSeverity.CRITICAL
        elif sev_str == "HIGH":
            sev_enum = FindingSeverity.HIGH
        elif sev_str == "MEDIUM":
            sev_enum = FindingSeverity.MEDIUM
        elif sev_str == "LOW":
            sev_enum = FindingSeverity.LOW
        else:
            sev_enum = FindingSeverity.INFO

        # Evidence dictionary
        evidence_dict: dict[str, Any] = {
            "type": "code_snippet" if pipeline_input.input_type == InputType.CODE else "payload_capture",
            "snippet": evidence.snippet,
            "start_line": evidence.start_line,
            "end_line": evidence.end_line,
            "parameter": evidence.parameter_name,
            "decoded_payload": evidence.decoded_payload,
            "matched_patterns": evidence.matched_patterns,
            "verification_method": verification.verifier_method,
            "verification_confidence": verification.confidence,
        }

        # Build Proof of Concept (PoCSpec)
        poc = self._build_poc(pipeline_input, evidence, scoring)

        # Build Remediation & Patch Diff (RemediationSpec)
        remediation = self._build_remediation(pipeline_input, evidence, scoring, reasoning)

        owasp_list = [scoring.owasp_category] if scoring.owasp_category else []

        return Finding(
            finding_id=finding_id,
            title=f"{scoring.cwe_name} ({scoring.cwe_id})",
            severity=sev_enum,
            confidence=scoring.composite_confidence,
            cvss=scoring.cvss_score,
            cwe=[scoring.cwe_id],
            owasp=owasp_list,
            asset_id=pipeline_input.target_id,
            endpoint=pipeline_input.filepath or evidence.parameter_name or "in-scope",
            description=reasoning.root_cause_analysis,
            impact=reasoning.impact_assessment,
            evidence=[evidence_dict],
            poc=poc,
            reproduction=poc.steps,
            remediation=remediation,
            status=FindingStatus.CONFIRMED if not filter_result.is_filtered else FindingStatus.POTENTIAL,
        )

    def _build_poc(
        self,
        pipeline_input: PipelineInput,
        evidence: ExtractedEvidence,
        scoring: ScoringResult,
    ) -> PoCSpec:
        """Constructs reproducible PoC steps for testing and validation."""
        if pipeline_input.input_type == InputType.HTTP_TRAFFIC:
            param = evidence.parameter_name or "param"
            payload = evidence.decoded_payload or "' OR 1=1--"
            steps = [
                f"1. Target endpoint receives crafted HTTP request with payload in '{param}'.",
                f"2. Send test payload: {payload}",
                "3. Observe response reflection, database error syntax, or delay confirming vulnerability.",
            ]
            req_content = f"POST /api/v1/resource HTTP/1.1\nHost: target.local\nContent-Type: application/x-www-form-urlencoded\n\n{param}={payload}"
            return PoCSpec(
                type="http_request",
                steps=steps,
                request_content=req_content,
                expected_response="HTTP/1.1 200 OK or 500 containing internal database error/reflected payload.",
            )

        if pipeline_input.input_type == InputType.URL:
            steps = [
                f"1. Open the suspicious target URL: {pipeline_input.content}",
                "2. Inspect network redirection headers and landing page form fields.",
                "3. Verify absence of official SSL certificates and presence of deceptive credential inputs.",
            ]
            return PoCSpec(
                type="manual",
                steps=steps,
                request_content=f"curl -I '{pipeline_input.content}'",
                expected_response="HTTP 302 Found redirecting to unauthorized credential harvester.",
            )

        # CODE
        line = evidence.start_line or 1
        snippet = evidence.snippet
        steps = [
            f"1. Inspect source file `{pipeline_input.filepath or 'target_code'}` at line {line}.",
            f"2. Note unvalidated sink: `{snippet}`",
            "3. Trace input dataflow from external entrypoint into this statement without sanitization.",
        ]
        return PoCSpec(
            type="python_script",
            steps=steps,
            request_content=f"# Vulnerable construct at line {line}:\n{snippet}",
            expected_response="Sink executes untrusted input without restriction.",
        )

    def _build_remediation(
        self,
        pipeline_input: PipelineInput,
        evidence: ExtractedEvidence,
        scoring: ScoringResult,
        reasoning: ReasoningHypothesis,
    ) -> RemediationSpec:
        """Constructs actionable remediation recommendation and patch diff."""
        cwe = scoring.cwe_id
        diff = ""
        snippet = evidence.snippet

        if cwe == "CWE-89":
            rec = "Use parameterized prepared statements with bind variables. Never construct dynamic SQL strings."
            diff = (
                f"- cursor.execute(f'SELECT * FROM users WHERE id = {snippet}')\n"
                f"+ cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            )
        elif cwe == "CWE-78":
            rec = "Pass arguments as an argument list (argv array) without invoking the system shell (shell=False)."
            diff = (
                f"- subprocess.Popen(f'ping -c 1 {snippet}', shell=True)\n"
                f"+ subprocess.Popen(['ping', '-c', '1', user_input], shell=False)"
            )
        elif cwe in ("CWE-119", "CWE-120"):
            rec = "Replace unsafe bounded string functions with safe alternatives (e.g. strncpy, snprintf, std::string)."
            diff = (
                "- strcpy(dest, src);\n"
                "+ strncpy(dest, src, sizeof(dest) - 1);\n"
                "+ dest[sizeof(dest) - 1] = '\\0';"
            )
        elif cwe == "CWE-79":
            rec = "Apply contextual output encoding (e.g. HTML entity encoding) before reflecting user input into templates."
            diff = (
                f"- return render_template_string(f'Hello {snippet}')\n"
                f"+ return render_template_string('Hello {{ name }}', name=user_input)"
            )
        elif cwe == "CWE-22":
            rec = "Canonicalize the path and verify it is strictly within the allowed base directory using secure_filename."
            diff = (
                "- filepath = os.path.join(BASE_DIR, user_input)\n"
                "+ filename = secure_filename(user_input)\n"
                "+ filepath = os.path.abspath(os.path.join(BASE_DIR, filename))\n"
                "+ if not filepath.startswith(BASE_DIR): raise PermissionError()"
            )
        else:
            rec = f"Remediate according to security guidelines for {cwe}."
            diff = f"# Apply input validation and safe sinks around:\n# {snippet}"

        return RemediationSpec(
            recommendation=rec,
            root_cause=reasoning.root_cause_analysis,
            code_diff=diff,
            fix_effort="low" if cwe in ("CWE-89", "CWE-79") else "medium",
            references=[f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"],
        )
