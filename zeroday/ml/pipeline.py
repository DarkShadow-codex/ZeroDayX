"""End-to-End ZeroDay Vulnerability Detection Pipeline.

Orchestrates the entire multi-stage detection process:
Input -> Candidate Detector -> Evidence Extraction -> LLM Reasoning
      -> Independent Verification -> False-Positive Filter -> CWE/CVSS Scoring
      -> Structured Report Generation
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from zeroday.findings.models import Finding

from zeroday.ml.candidate_detector import CandidateDetector
from zeroday.ml.cwe_cvss_scorer import CWECVSSScorer
from zeroday.ml.evidence_extractor import EvidenceExtractor
from zeroday.ml.false_positive_filter import FalsePositiveFilter
from zeroday.ml.independent_verifier import IndependentVerifier
from zeroday.ml.reasoning_layer import LLMReasoningLayer
from zeroday.ml.report_generator import ReportGenerator
from zeroday.ml.types import (
    CandidateFinding,
    ExtractedEvidence,
    FilterResult,
    PipelineInput,
    PipelineReport,
    ReasoningHypothesis,
    ScoringResult,
    VerificationResult,
)


class ZeroDayPipeline:
    """The unified autonomous vulnerability-detection pipeline."""

    def __init__(
        self,
        candidate_detector: CandidateDetector | None = None,
        evidence_extractor: EvidenceExtractor | None = None,
        reasoning_layer: LLMReasoningLayer | None = None,
        independent_verifier: IndependentVerifier | None = None,
        fp_filter: FalsePositiveFilter | None = None,
        cwe_scorer: CWECVSSScorer | None = None,
        report_generator: ReportGenerator | None = None,
        nvd_rag_client: Any | None = None,
    ):
        self.candidate_detector = candidate_detector or CandidateDetector()
        self.evidence_extractor = evidence_extractor or EvidenceExtractor()
        self.reasoning_layer = reasoning_layer or LLMReasoningLayer(nvd_rag_client=nvd_rag_client)
        self.independent_verifier = independent_verifier or IndependentVerifier()
        self.fp_filter = fp_filter or FalsePositiveFilter()
        self.cwe_scorer = cwe_scorer or CWECVSSScorer()
        self.report_generator = report_generator or ReportGenerator()

    def process(self, pipeline_input: PipelineInput) -> PipelineReport:
        """Executes the complete detection pipeline against a single input."""
        start_time = time.perf_counter()

        # Step 1: Candidate Detection
        candidate: CandidateFinding = self.candidate_detector.detect(pipeline_input)

        if not candidate.is_vulnerable:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return PipelineReport(
                target_id=pipeline_input.target_id,
                input_type=pipeline_input.input_type,
                is_vulnerable=False,
                status="CLEAN",
                candidate=candidate,
                evidence=ExtractedEvidence(snippet="No vulnerable pattern detected."),
                reasoning=ReasoningHypothesis(is_plausible=False, plausibility_score=0.0),
                verification=VerificationResult(agreed=True, verifier_method="clean_consensus", confidence=1.0),
                filter_result=FilterResult(is_filtered=False, filter_confidence=1.0),
                scoring=None,
                finding_record=None,
                processing_time_ms=round(elapsed_ms, 2),
            )

        # Step 2: Evidence Extraction
        evidence: ExtractedEvidence = self.evidence_extractor.extract(pipeline_input, candidate)

        # Step 3: LLM Reasoning Layer (Grounded in NVD RAG)
        reasoning: ReasoningHypothesis = self.reasoning_layer.reason(
            pipeline_input, candidate, evidence
        )

        # Step 4: Independent Verification (Dual-Method Consensus Engine)
        verification: VerificationResult = self.independent_verifier.verify(
            pipeline_input, candidate, evidence
        )

        # Step 5: False-Positive Filtering (Sanitizers, Context, Dead Code, Whitelists)
        filter_res: FilterResult = self.fp_filter.filter(
            pipeline_input, candidate, evidence, verification
        )

        # Determine if finding is confirmed or rejected
        is_confirmed = (
            candidate.is_vulnerable
            and verification.agreed
            and not filter_res.is_filtered
            and reasoning.is_plausible
        )

        # Step 6: CWE Mapping & CVSS Scoring
        scoring: ScoringResult = self.cwe_scorer.score(
            candidate, reasoning, verification, filter_res
        )

        # Step 7: Final Structured Report Generation
        finding_record: Finding | None = None
        if is_confirmed:
            finding_record = self.report_generator.generate(
                pipeline_input, candidate, evidence, reasoning, verification, filter_res, scoring
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        status = "CONFIRMED" if is_confirmed else (
            "REJECTED_VERIFICATION" if not verification.agreed else "REJECTED_FILTER"
        )

        return PipelineReport(
            target_id=pipeline_input.target_id,
            input_type=pipeline_input.input_type,
            is_vulnerable=is_confirmed,
            status=status,
            candidate=candidate,
            evidence=evidence,
            reasoning=reasoning,
            verification=verification,
            filter_result=filter_res,
            scoring=scoring,
            finding_record=finding_record.to_dict() if finding_record else None,
            processing_time_ms=round(elapsed_ms, 2),
        )

    def scan_batch(self, inputs: list[PipelineInput]) -> list[PipelineReport]:
        """Processes a batch of inputs sequentially or in parallel."""
        return [self.process(inp) for inp in inputs]
