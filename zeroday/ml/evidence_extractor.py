"""Evidence Extraction Module for ZeroDay.

Pinpoints the exact lines of code, HTTP parameters/headers, or URL tokens
that triggered candidate detection.
"""

from __future__ import annotations

import re
import urllib.parse

from zeroday.ml.types import CandidateFinding, ExtractedEvidence, InputType, PipelineInput


class EvidenceExtractor:
    """Surfaces precise, localized, reproducible evidence for findings."""

    def extract(
        self,
        pipeline_input: PipelineInput,
        candidate: CandidateFinding,
    ) -> ExtractedEvidence:
        """Extracts structured evidence based on input modality."""
        if not candidate.is_vulnerable:
            return ExtractedEvidence(snippet="No vulnerability detected.")

        if pipeline_input.input_type == InputType.CODE:
            return self._extract_code_evidence(pipeline_input.content, candidate)
        if pipeline_input.input_type == InputType.HTTP_TRAFFIC:
            return self._extract_traffic_evidence(pipeline_input.content, candidate)
        if pipeline_input.input_type == InputType.URL:
            return self._extract_url_evidence(pipeline_input.content, candidate)
        return ExtractedEvidence(snippet=pipeline_input.content[:200])

    def _extract_code_evidence(
        self, code: str, candidate: CandidateFinding
    ) -> ExtractedEvidence:
        """Surfaces line numbers, exact vulnerable statement, and context."""
        lines = code.splitlines()
        matched_line_idx: int | None = None
        matched_line_str = ""
        matched_patterns: list[str] = []

        # Find line matching salient patterns or suspicious functions
        for pattern in candidate.salient_tokens:
            for idx, line in enumerate(lines):
                if re.search(pattern, line):
                    matched_line_idx = idx
                    matched_line_str = line.strip()
                    matched_patterns.append(pattern)
                    break
            if matched_line_idx is not None:
                break

        # Fallback search if salient pattern was generalized
        if matched_line_idx is None:
            keywords = ["execute", "eval", "system", "strcpy", "gets", "render_template", "Popen", "open"]
            for idx, line in enumerate(lines):
                if any(kw in line for kw in keywords):
                    matched_line_idx = idx
                    matched_line_str = line.strip()
                    break

        if matched_line_idx is None:
            matched_line_idx = 0
            matched_line_str = lines[0] if lines else ""

        start_line = max(1, matched_line_idx + 1 - 2)
        end_line = min(len(lines), matched_line_idx + 1 + 2)

        context_lines = [(l_no, lines[l_no - 1]) for l_no in range(start_line, end_line + 1)]

        return ExtractedEvidence(
            snippet=matched_line_str,
            start_line=matched_line_idx + 1,
            end_line=matched_line_idx + 1,
            matched_patterns=matched_patterns,
            context_lines=context_lines,
        )

    def _extract_traffic_evidence(
        self, raw_http: str, candidate: CandidateFinding
    ) -> ExtractedEvidence:
        """Isolates vulnerable HTTP parameter, header, or body element."""
        lines = raw_http.splitlines()
        first_line = lines[0] if lines else ""
        parts = first_line.split(" ")
        path_and_query = parts[1] if len(parts) > 1 else ""

        parsed_url = urllib.parse.urlsplit(path_and_query)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Inspect headers and body
        headers: dict[str, str] = {}
        body = ""
        in_body = False
        for line in lines[1:]:
            if in_body:
                body += line + "\n"
            elif line.strip() == "":
                in_body = True
            elif ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # Check query parameters
        for p_name, p_vals in query_params.items():
            for val in p_vals:
                decoded = urllib.parse.unquote(val)
                for pattern in candidate.salient_tokens:
                    if re.search(pattern, decoded):
                        return ExtractedEvidence(
                            snippet=f"{p_name}={val}",
                            parameter_name=p_name,
                            http_component="query",
                            decoded_payload=decoded,
                            matched_patterns=[pattern],
                        )

        # Check body parameters (form-encoded and json)
        if body:
            decoded_body = urllib.parse.unquote_plus(body)
            body_params = urllib.parse.parse_qs(body.strip())
            for p_name, p_vals in body_params.items():
                for val in p_vals:
                    decoded = urllib.parse.unquote_plus(val)
                    for pattern in candidate.salient_tokens:
                        if re.search(pattern, decoded):
                            return ExtractedEvidence(
                                snippet=f"{p_name}={val}",
                                parameter_name=p_name,
                                http_component="body",
                                decoded_payload=decoded,
                                matched_patterns=[pattern],
                            )
            for pattern in candidate.salient_tokens:
                if re.search(pattern, decoded_body):
                    return ExtractedEvidence(
                        snippet=body.strip()[:120],
                        parameter_name="JSON_BODY",
                        http_component="body",
                        decoded_payload=decoded_body,
                        matched_patterns=[pattern],
                    )

        # Check path itself
        decoded_path = urllib.parse.unquote_plus(path_and_query)
        for pattern in candidate.salient_tokens:
            if re.search(pattern, decoded_path):
                return ExtractedEvidence(
                    snippet=path_and_query,
                    parameter_name="REQUEST_URI",
                    http_component="path",
                    decoded_payload=decoded_path,
                    matched_patterns=[pattern],
                )

        return ExtractedEvidence(
            snippet=first_line,
            http_component="request_line",
            decoded_payload=urllib.parse.unquote(first_line),
        )

    def _extract_url_evidence(
        self, url: str, candidate: CandidateFinding
    ) -> ExtractedEvidence:
        """Isolates suspicious lexical components of a URL."""
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        netloc = parsed.netloc

        tokens: list[str] = []
        # Extract subdomains, brand mentions, weird symbols
        if "@" in url:
            tokens.append(f"embedded_auth: {url.split('@', maxsplit=1)[0]}")
        if "-" in netloc:
            tokens.append(f"hyphenated_host: {netloc}")

        entropy = candidate.metadata.get("entropy")

        return ExtractedEvidence(
            snippet=url,
            parameter_name=netloc,
            entropy_score=entropy,
            structural_tokens=tokens or candidate.salient_tokens,
            matched_patterns=candidate.salient_tokens,
        )
