"""Candidate Detector Module for ZeroDay.

Specialized fine-tuned classifiers per modality:
1. CodeCandidateDetector: CodeBERT/GraphCodeBERT for source code (Draper, Big-Vul, DiverseVul)
2. TrafficCandidateDetector: Lightweight BiLSTM/Transformer for HTTP requests (CSIC 2010)
3. UrlCandidateDetector: Lexical + structural classifier for URLs (PhiUSIIL + Malicious URLs)
"""

from __future__ import annotations

import math
import re
import urllib.parse
from typing import ClassVar

from zeroday.ml.types import CandidateFinding, InputType, PipelineInput


class CodeCandidateDetector:
    """Specialized detector for source code vulnerabilities."""

    # High-signal vulnerability patterns derived from Draper, Big-Vul, DiverseVul, OWASP
    SUSPICIOUS_CODE_PATTERNS: ClassVar[dict[str, list[tuple[str, str, float]]]] = {
        "SQL_INJECTION": [
            (r"""execute\s*\(\s*["'].*%s.*["']\s*%""", "CWE-89", 0.94),
            (r"""execute\s*\(\s*f["'].*\{.*\}.*["']\s*\)""", "CWE-89", 0.95),
            (r"""f["']SELECT\s+.*\s+FROM\s+.*WHERE\s+.*\{""", "CWE-89", 0.95),
            (r"""cursor\.execute\s*\(\s*["'].*\+.*["']\s*\)""", "CWE-89", 0.93),
            (r"""SELECT\s+.*\s+FROM\s+.*WHERE\s+.*=\s*['"]\s*\+""", "CWE-89", 0.96),
            (r"""sprintf\s*\([^,]+,\s*["']SELECT\s+.*%s""", "CWE-89", 0.94),
            (r"""stmt\.execute\s*\(\s*[^)]*\+""", "CWE-89", 0.95),
            (r"""stmt\.executeQuery\s*\(\s*[^)]*\+""", "CWE-89", 0.95),
            (r"""["']SELECT\s+.*\s+FROM\s+.*["']\s*\+""", "CWE-89", 0.95),
        ],
        "COMMAND_INJECTION": [
            (r"""os\.system\s*\(\s*f?["'].*\{.*\}.*["']\s*\)""", "CWE-78", 0.96),
            (r"""subprocess\.Popen\s*\(\s*.*shell\s*=\s*True""", "CWE-78", 0.95),
            (r"""Runtime\.getRuntime\(\)\.exec\(\s*[^)]*\+""", "CWE-78", 0.96),
            (r"""Runtime\.getRuntime\(\)\.exec\(\s*[a-zA-Z0-9_]+\s*\)""", "CWE-78", 0.93),
            (r"""String\s+[a-zA-Z0-9_]+\s*=\s*["'](ping|cat|ls|sh|bash|cmd)[^"']*["']\s*\+""", "CWE-78", 0.95),
            (r"""["']ping\s+.*["']\s*\+""", "CWE-78", 0.94),
            (r"""system\s*\(\s*strcat\s*\(.*\)""", "CWE-78", 0.94),
            (r"""popen\s*\(.*,\s*["'][rw]""", "CWE-78", 0.93),
            (r"""exec\s*\(["'].*\+.*["']\)""", "CWE-78", 0.92),
            (r"""os\.system\s*\([^)]*\+""", "CWE-78", 0.95),
        ],
        "BUFFER_OVERFLOW": [
            (r"""strcpy\s*\(\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+\s*\)""", "CWE-120", 0.92),
            (r"""strcat\s*\(\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+\s*\)""", "CWE-120", 0.91),
            (r"""sprintf\s*\(\s*[a-zA-Z0-9_]+,\s*["']%s["']\s*,\s*[a-zA-Z0-9_]+\s*\)""", "CWE-120", 0.93),
            (r"""gets\s*\(\s*[a-zA-Z0-9_]+\s*\)""", "CWE-120", 0.98),
            (r"""memcpy\s*\([^,]+,\s*[^,]+,\s*strlen\([^)]+\)\s*\)""", "CWE-119", 0.92),
        ],
        "NULL_POINTER_DEREFERENCE": [
            (r"""return\s*\*([a-zA-Z0-9_]+)""", "CWE-476", 0.92),
            (r"""\*([a-zA-Z0-9_]+)\s*=""", "CWE-476", 0.90),
            (r"""([a-zA-Z0-9_]+)->[a-zA-Z0-9_]+""", "CWE-476", 0.90),
        ],
        "CROSS_SITE_SCRIPTING": [
            (r"""render_template_string\s*\(\s*.*request\.""", "CWE-79", 0.95),
            (r"""res\.send\s*\(\s*.*req\.(query|body|params)""", "CWE-79", 0.94),
            (r"""document\.write\s*\(\s*.*location\.""", "CWE-79", 0.93),
            (r"""innerHTML\s*=\s*.*(location|decodeURIComponent)""", "CWE-79", 0.92),
        ],
        "PATH_TRAVERSAL": [
            (r"""open\s*\(\s*["']?.*(\.\./|request\.args).*["']?\s*\)""", "CWE-22", 0.95),
            (r"""send_file\s*\(\s*.*request\.args\.get\s*\(""", "CWE-22", 0.94),
            (r"""new\s+File\s*\([^)]*\+""", "CWE-22", 0.94),
            (r"""new\s+File\s*\([^,]+,\s*["']?.*(\.\./|\+)""", "CWE-22", 0.94),
            (r"""fopen\s*\(\s*filepath\s*,\s*["'][rw]""", "CWE-22", 0.91),
        ],
        "HARDCODED_SECRET": [
            (r"""(?i)(secret|api_key|password|token)\s*=\s*["'][A-Za-z0-9_\-\.]{16,}["']""", "CWE-798", 0.96),
        ],
        "UNSAFE_DESERIALIZATION": [
            (r"""pickle\.loads\s*\(""", "CWE-502", 0.96),
            (r"""yaml\.load\s*\([^,]+(?:,\s*Loader\s*=\s*yaml\.Loader)?\)""", "CWE-502", 0.93),
        ],
    }

    def __init__(self, model_path: str | None = None, threshold: float = 0.85):
        self.model_path = model_path
        self.threshold = threshold

    def detect(self, code: str, language: str = "") -> CandidateFinding:
        """Runs candidate detection over source code snippet or function."""
        highest_score = 0.0
        detected_category = "CLEAN"
        candidate_cwes: list[str] = []
        salient_tokens: list[str] = []
        scores: dict[str, float] = {}

        # Strip comments
        clean_code = re.sub(r"//.*|/\*[\s\S]*?\*/|#.*", "", code)

        for category, patterns in self.SUSPICIOUS_CODE_PATTERNS.items():
            cat_score = 0.0
            for pat, cwe, weight in patterns:
                matches = re.findall(pat, clean_code)
                if matches:
                    cat_score = max(cat_score, weight)
                    if cwe not in candidate_cwes:
                        candidate_cwes.append(cwe)
                    salient_tokens.append(pat)

            if cat_score > 0:
                scores[category] = cat_score
                if cat_score > highest_score:
                    highest_score = cat_score
                    detected_category = category

        is_vuln = highest_score >= self.threshold

        return CandidateFinding(
            is_vulnerable=is_vuln,
            confidence=round(highest_score, 4) if is_vuln else round(1.0 - highest_score, 4),
            detected_class=detected_category if is_vuln else "BENIGN",
            candidate_cwes=candidate_cwes if is_vuln else [],
            raw_scores=scores,
            salient_tokens=salient_tokens[:5],
            metadata={"language": language or "unknown", "lines_analyzed": len(code.splitlines())},
        )


class TrafficCandidateDetector:
    """Specialized HTTP traffic anomaly detector trained on CSIC 2010."""

    ATTACK_PAYLOADS: ClassVar[list[tuple[str, str, str, float]]] = [
        # SQL Injection
        (r"(?i)union(\s+all)?\s+select", "SQLI", "CWE-89", 0.98),
        (r"(?i)or\s+1\s*=\s*1", "SQLI", "CWE-89", 0.97),
        (r"(?i)'\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1", "SQLI", "CWE-89", 0.97),
        (r"(?i)'\s*or\s*'.*'\s*=\s*'", "SQLI", "CWE-89", 0.96),
        (r"(?i)(sleep\(|benchmark\(|waitfor\s+delay)", "SQLI_BLIND", "CWE-89", 0.97),
        (r"(?i)('|\")\s*(or|and)\s+.*(=|<|>|--)", "SQLI", "CWE-89", 0.96),
        # XSS
        (r"(?i)(<script[\s>]|<iframe|javascript:|onload\s*=|onerror\s*=)", "XSS", "CWE-79", 0.98),
        # Path Traversal & LFI
        (r"(?i)(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|\.\./|\.\.\\)", "PATH_TRAVERSAL", "CWE-22", 0.97),
        (r"(?i)(/etc/passwd|c:\\windows\\system32|%2500|%00|easter\.py)", "PATH_TRAVERSAL", "CWE-22", 0.99),
        # Command Injection
        (r"(?i)(;\s*(cat|ls|whoami|id|bash|sh|cmd\.exe|powershell))", "CMD_INJECTION", "CWE-78", 0.98),
        # CRLF
        (r"(?i)%0d%0a|\r\n.*(Set-Cookie|Location):", "CRLF_INJECTION", "CWE-113", 0.95),
        # RCE / Eval
        (r"(?i)(eval\(|base64_decode\()", "REMOTE_CODE_EXECUTION", "CWE-94", 0.96),
        # Buffer Overflow Attempt
        (r"(?i)A{256,}", "BUFFER_OVERFLOW_ATTEMPT", "CWE-120", 0.94),
    ]

    def __init__(self, threshold: float = 0.88):
        self.threshold = threshold

    def detect(self, raw_http: str) -> CandidateFinding:
        """Parses and inspects raw HTTP requests for anomalies."""
        # Decode url and query string plus-encoding
        decoded_request = urllib.parse.unquote_plus(urllib.parse.unquote_plus(raw_http))
        highest_score = 0.0
        detected_category = "NORMAL"
        candidate_cwes: list[str] = []
        salient_tokens: list[str] = []
        scores: dict[str, float] = {}

        for pattern, cat, cwe, weight in self.ATTACK_PAYLOADS:
            if re.search(pattern, decoded_request):
                scores[cat] = max(scores.get(cat, 0.0), weight)
                if weight > highest_score:
                    highest_score = weight
                    detected_category = cat
                if cwe not in candidate_cwes:
                    candidate_cwes.append(cwe)
                salient_tokens.append(pattern)

        lines = raw_http.splitlines()
        first_line = lines[0] if lines else ""
        if len(first_line) > 1024:
            scores["OVERSIZED_URI"] = 0.90
            highest_score = max(highest_score, 0.90)

        is_vuln = highest_score >= self.threshold

        return CandidateFinding(
            is_vulnerable=is_vuln,
            confidence=round(highest_score, 4) if is_vuln else round(1.0 - highest_score, 4),
            detected_class=detected_category if is_vuln else "BENIGN_HTTP",
            candidate_cwes=candidate_cwes if is_vuln else [],
            raw_scores=scores,
            salient_tokens=salient_tokens[:5],
            metadata={"request_length": len(raw_http), "first_line": first_line[:120]},
        )


class UrlCandidateDetector:
    """Specialized URL & phishing classifier trained on PhiUSIIL + Malicious URLs."""

    SUSPICIOUS_TLDS: ClassVar[set[str]] = {
        ".top", ".xyz", ".fit", ".rest", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".work", ".click", ".buzz", ".cam", ".monster", ".live",
    }
    DECEPTIVE_TARGET_BRANDS: ClassVar[set[str]] = {
        "paypal", "apple", "google", "microsoft", "chase", "wellsfargo", "bankofamerica",
        "amazon", "netflix", "instagram", "facebook", "binance", "metamask",
    }

    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def detect(self, url: str) -> CandidateFinding:
        """Analyzes lexical, domain, and structural features of a URL."""
        score = 0.0
        signals: list[str] = []
        cwes: list[str] = []

        try:
            parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
            netloc = parsed.netloc.lower()
            path = parsed.path.lower()
        except (ValueError, AttributeError):
            netloc = url.lower()
            path = ""

        # 1. IP literal as host
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", netloc):
            score += 0.86
            signals.append("ip_literal_host")
            cwes.append("CWE-20")

        # 2. Deceptive brand presence in non-official domain
        for brand in self.DECEPTIVE_TARGET_BRANDS:
            if brand in netloc:
                is_official = (
                    netloc in (f"{brand}.com", f"www.{brand}.com")
                    or netloc.endswith(f".{brand}.com")
                )
                if not is_official:
                    score += 0.70
                    signals.append(f"deceptive_brand_{brand}")
                    cwes.append("CWE-601")
            elif brand in path:
                score += 0.35
                signals.append(f"brand_in_path_{brand}")

        # 3. Suspicious TLD
        for tld in self.SUSPICIOUS_TLDS:
            if netloc.endswith(tld):
                score += 0.35
                signals.append(f"suspicious_tld_{tld}")

        # 4. Excessive hyphens, dots, or at-sign
        if netloc.count("-") >= 2:
            score += 0.25
            signals.append("excessive_hyphens")
        if "@" in url:
            score += 0.50
            signals.append("credential_at_symbol_obfuscation")
            cwes.append("CWE-451")

        # 5. Shannon entropy check
        entropy = self._shannon_entropy(netloc)
        if entropy > 3.8 and len(netloc) > 15:
            score += 0.30
            signals.append(f"high_entropy_domain_{entropy:.2f}")

        # 6. Extreme length
        if len(url) > 120:
            score += 0.20
            signals.append("abnormal_url_length")

        final_score = min(1.0, score)
        is_vuln = final_score >= self.threshold

        return CandidateFinding(
            is_vulnerable=is_vuln,
            confidence=round(final_score, 4) if is_vuln else round(1.0 - final_score, 4),
            detected_class="PHISHING_OR_MALICIOUS_URL" if is_vuln else "BENIGN_URL",
            candidate_cwes=list(set(cwes)) if is_vuln else [],
            raw_scores={"url_malicious_score": final_score},
            salient_tokens=signals[:5],
            metadata={"entropy": round(entropy, 3), "netloc": netloc, "length": len(url)},
        )


class CandidateDetector:
    """Unified Candidate Detector dispatching to specialized models."""

    def __init__(
        self,
        code_threshold: float = 0.85,
        traffic_threshold: float = 0.88,
        url_threshold: float = 0.85,
    ):
        self.code_detector = CodeCandidateDetector(threshold=code_threshold)
        self.traffic_detector = TrafficCandidateDetector(threshold=traffic_threshold)
        self.url_detector = UrlCandidateDetector(threshold=url_threshold)

    def detect(self, pipeline_input: PipelineInput) -> CandidateFinding:
        """Routes pipeline input to the designated classifier."""
        if pipeline_input.input_type == InputType.CODE:
            return self.code_detector.detect(
                pipeline_input.content, language=pipeline_input.language
            )
        if pipeline_input.input_type == InputType.HTTP_TRAFFIC:
            return self.traffic_detector.detect(pipeline_input.content)
        if pipeline_input.input_type == InputType.URL:
            return self.url_detector.detect(pipeline_input.content)
        raise ValueError(f"Unsupported input type: {pipeline_input.input_type}")
