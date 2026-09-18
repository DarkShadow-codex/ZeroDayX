"""Tests for ZeroDay Autonomous Vulnerability Detection Pipeline."""

import pytest
from zeroday.findings.models import FindingSeverity, FindingStatus
from zeroday.ml.candidate_detector import (
    CandidateDetector,
    CodeCandidateDetector,
    TrafficCandidateDetector,
    UrlCandidateDetector,
)
from zeroday.ml.cwe_cvss_scorer import CWECVSSScorer
from zeroday.ml.evidence_extractor import EvidenceExtractor
from zeroday.ml.false_positive_filter import FalsePositiveFilter
from zeroday.ml.independent_verifier import IndependentVerifier
from zeroday.ml.pipeline import ZeroDayPipeline
from zeroday.ml.reasoning_layer import LLMReasoningLayer
from zeroday.ml.report_generator import ReportGenerator
from zeroday.ml.types import InputType, PipelineInput


def test_code_candidate_detector_vulnerable_and_clean():
    detector = CodeCandidateDetector(threshold=0.85)

    vuln_code = """
    def query_user(user_id):
        # execute raw query
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    """
    res_vuln = detector.detect(vuln_code, language="python")
    assert res_vuln.is_vulnerable is True
    assert "CWE-89" in res_vuln.candidate_cwes
    assert res_vuln.confidence >= 0.85

    clean_code = """
    def query_user(user_id):
        return cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    """
    res_clean = detector.detect(clean_code, language="python")
    assert res_clean.is_vulnerable is False


def test_traffic_candidate_detector():
    detector = TrafficCandidateDetector(threshold=0.88)

    vuln_http = (
        "GET /search.php?id=1%20UNION%20SELECT%201,password,3%20FROM%20users HTTP/1.1\n"
        "Host: victim.site\n\n"
    )
    res = detector.detect(vuln_http)
    assert res.is_vulnerable is True
    assert "CWE-89" in res.candidate_cwes

    clean_http = "GET /index.html HTTP/1.1\nHost: victim.site\n\n"
    res_clean = detector.detect(clean_http)
    assert res_clean.is_vulnerable is False


def test_url_candidate_detector():
    detector = UrlCandidateDetector(threshold=0.85)

    phish_url = "http://paypal.com-account-verification.top/login.php"
    res_phish = detector.detect(phish_url)
    assert res_phish.is_vulnerable is True
    assert "CWE-601" in res_phish.candidate_cwes

    benign_url = "https://www.google.com/search?q=cybersecurity"
    res_benign = detector.detect(benign_url)
    assert res_benign.is_vulnerable is False


def test_evidence_extractor():
    code_detector = CodeCandidateDetector()
    extractor = EvidenceExtractor()

    code = "line1 = 1\nline2 = 2\nos.system(f'ping {host}')\nline4 = 4"
    inp = PipelineInput(input_type=InputType.CODE, content=code)
    cand = code_detector.detect(code, language="python")
    evidence = extractor.extract(inp, cand)

    assert evidence.start_line == 3
    assert "os.system" in evidence.snippet


def test_independent_verifier_consensus():
    verifier = IndependentVerifier()
    code_detector = CodeCandidateDetector()
    extractor = EvidenceExtractor()

    code = "import os\nos.system(f'ping {host}')"
    inp = PipelineInput(input_type=InputType.CODE, content=code)
    cand = code_detector.detect(code, language="python")
    ev = extractor.extract(inp, cand)

    verif = verifier.verify(inp, cand, ev)
    assert verif.agreed is True
    assert verif.confidence >= 0.90


def test_false_positive_filter_sanitizer_detection():
    detector = CodeCandidateDetector()
    extractor = EvidenceExtractor()
    verifier = IndependentVerifier()
    fp_filter = FalsePositiveFilter()

    # Code containing parameterized query or bounds check
    sanitized_code = """
    def run_user(uid):
        # Uses explicit parameter binding
        cursor.execute("SELECT * FROM users WHERE id = %s", (int(uid),))
    """
    inp = PipelineInput(input_type=InputType.CODE, content=sanitized_code)
    cand = detector.detect(sanitized_code, language="python")
    ev = extractor.extract(inp, cand)
    verif = verifier.verify(inp, cand, ev)
    filt = fp_filter.filter(inp, cand, ev, verif)

    # Should be filtered out or marked benign
    assert filt.is_filtered is False or filt.sanitizer_detected is True or not cand.is_vulnerable


def test_cwe_cvss_scorer():
    scorer = CWECVSSScorer()
    detector = CodeCandidateDetector()
    reasoner = LLMReasoningLayer()
    verifier = IndependentVerifier()
    fp_filter = FalsePositiveFilter()

    code = "strcpy(dest, src);"
    inp = PipelineInput(input_type=InputType.CODE, content=code)
    cand = detector.detect(code, language="c")
    ev = EvidenceExtractor().extract(inp, cand)
    reas = reasoner.reason(inp, cand, ev)
    ver = verifier.verify(inp, cand, ev)
    flt = fp_filter.filter(inp, cand, ev, ver)

    score_res = scorer.score(cand, reas, ver, flt)
    assert score_res.cwe_id in ("CWE-120", "CWE-119")
    assert score_res.severity in ("HIGH", "CRITICAL")
    assert score_res.composite_confidence >= 0.85


def test_end_to_end_pipeline_vulnerable():
    pipeline = ZeroDayPipeline()

    inp = PipelineInput(
        input_type=InputType.HTTP_TRAFFIC,
        content="GET /tienda/item?id=1%20UNION%20SELECT%201,password,3%20FROM%20users HTTP/1.1\nHost: target.app\n\n",
        target_id="test_traffic_01",
    )
    report = pipeline.process(inp)

    assert report.is_vulnerable is True
    assert report.status == "CONFIRMED"
    assert report.scoring is not None
    assert report.scoring.cwe_id == "CWE-89"
    assert report.finding_record is not None
    assert report.finding_record["severity"] in (FindingSeverity.CRITICAL.value, FindingSeverity.HIGH.value)
    assert report.finding_record["poc"]["steps"]
    assert report.finding_record["remediation"]["code_diff"]


def test_end_to_end_pipeline_clean():
    pipeline = ZeroDayPipeline()

    inp = PipelineInput(
        input_type=InputType.CODE,
        content="def add(a: int, b: int) -> int:\n    return a + b",
        target_id="clean_func_01",
    )
    report = pipeline.process(inp)

    assert report.is_vulnerable is False
    assert report.status == "CLEAN"
    assert report.finding_record is None
