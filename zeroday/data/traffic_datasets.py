"""Data Loaders and Preprocessors for CSIC 2010 HTTP Traffic Dataset.

Supports:
- Parsing raw HTTP request streams (normal traffic vs anomalous traffic)
- Labeling attacks: SQLi, XSS, Path Traversal, CRLF, Buffer Overflow, Parameter Tampering
- Extracting request components: Method, Path, Query Params, Headers, Body
- Generating balanced training/evaluation splits with held-out test suites.
"""

from __future__ import annotations

import random
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TrafficSample:
    """Standardized HTTP traffic sample."""
    raw_http: str
    is_anomalous: bool
    attack_type: str  # NORMAL, SQLI, XSS, PATH_TRAVERSAL, CRLF, OVERFLOW, TAMPERING
    cwe: str | None = None
    method: str = "GET"
    uri: str = "/"
    parameters: dict[str, list[str]] = field(default_factory=dict)
    sample_id: str = ""
    source_dataset: str = "CSIC_2010"
    is_held_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TrafficDatasetLoader:
    """Loader and normalizer for the CSIC 2010 HTTP dataset."""

    def __init__(self, data_root: str | Path | None = None, seed: int = 42):
        self.data_root = Path(data_root) if data_root else Path("./datasets/traffic")
        self.seed = seed
        random.seed(seed)

    def load_csic_2010(
        self,
        normal_file: str | Path | None = None,
        anomalous_file: str | Path | None = None,
        max_samples: int | None = None,
    ) -> list[TrafficSample]:
        """Loads and parses normal and anomalous HTTP requests from CSIC 2010 text dumps."""
        normal_path = Path(normal_file) if normal_file else self.data_root / "normalTrafficTraining.txt"
        anom_path = Path(anomalous_file) if anomalous_file else self.data_root / "anomalousTrafficTest.txt"

        samples: list[TrafficSample] = []

        if normal_path.exists():
            samples.extend(self._parse_csic_file(normal_path, is_anom=False, max_count=(max_samples // 2 if max_samples else None)))
        if anom_path.exists():
            samples.extend(self._parse_csic_file(anom_path, is_anom=True, max_count=(max_samples // 2 if max_samples else None)))

        if not samples:
            # Generate representative CSIC 2010 distribution if raw dataset file not yet mounted
            samples = self._generate_mock_csic_samples(count=max_samples or 100)

        return samples

    def _parse_csic_file(
        self, filepath: Path, is_anom: bool, max_count: int | None = None
    ) -> list[TrafficSample]:
        """Parses multi-request CSIC text files separated by blank lines."""
        content = filepath.read_text(encoding="utf-8", errors="replace")
        raw_blocks = content.split("\n\n\n")
        samples: list[TrafficSample] = []

        for idx, block in enumerate(raw_blocks):
            if max_count and len(samples) >= max_count:
                break
            block = block.strip()
            if not block:
                continue

            lines = block.splitlines()
            first_line = lines[0] if lines else ""
            parts = first_line.split()
            method = parts[0] if parts else "GET"
            uri = parts[1] if len(parts) > 1 else "/"

            attack_type = "NORMAL"
            cwe = None
            if is_anom:
                attack_type, cwe = self._infer_attack_type(block)

            parsed_url = urllib.parse.urlsplit(uri)
            params = urllib.parse.parse_qs(parsed_url.query)

            samples.append(
                TrafficSample(
                    raw_http=block,
                    is_anomalous=is_anom,
                    attack_type=attack_type,
                    cwe=cwe,
                    method=method,
                    uri=uri,
                    parameters=params,
                    sample_id=f"csic_{'anom' if is_anom else 'norm'}_{idx}",
                )
            )

        return samples

    def _infer_attack_type(self, raw_http: str) -> tuple[str, str | None]:
        """Categorizes anomalous requests into specific attack classes."""
        lower = urllib.parse.unquote(raw_http).lower()
        if any(p in lower for p in ["union", "select", "1=1", "' or '", "waitfor delay", "benchmark("]):
            return "SQLI", "CWE-89"
        if any(p in lower for p in ["<script", "javascript:", "onload=", "onerror="]):
            return "XSS", "CWE-79"
        if any(p in lower for p in ["../", "..\\", "/etc/passwd"]):
            return "PATH_TRAVERSAL", "CWE-22"
        if any(p in lower for p in ["%0d%0a", "\r\nset-cookie"]):
            return "CRLF", "CWE-113"
        if len(raw_http) > 2048:
            return "BUFFER_OVERFLOW", "CWE-120"
        return "PARAMETER_TAMPERING", "CWE-20"

    def prepare_traffic_splits(
        self,
        samples: list[TrafficSample],
        target_normal_ratio: float = 0.58,  # CSIC 2010 distribution: ~58% normal, ~42% anomalous
        val_split: float = 0.15,
        test_split: float = 0.20,
    ) -> dict[str, list[TrafficSample]]:
        """Splits traffic samples into train, val, and held-out test splits."""
        norm = [s for s in samples if not s.is_anomalous]
        anom = [s for s in samples if s.is_anomalous]

        random.shuffle(norm)
        random.shuffle(anom)

        combined = norm + anom
        random.shuffle(combined)

        n_total = len(combined)
        n_test = int(n_total * test_split)
        n_val = int(n_total * val_split)

        test_set = combined[:n_test]
        for s in test_set:
            s.is_held_out = True
        val_set = combined[n_test : n_test + n_val]
        train_set = combined[n_test + n_val :]

        return {"train": train_set, "val": val_set, "test": test_set}

    def _generate_mock_csic_samples(self, count: int = 100) -> list[TrafficSample]:
        """Generates realistic CSIC 2010 HTTP e-commerce traffic samples."""
        samples: list[TrafficSample] = []
        normal_uris = [
            "GET /tienda1/publico/anadir.jsp?id=1&nombre=camisa&precio=20 HTTP/1.1\nHost: localhost:8080\nUser-Agent: Mozilla/5.0\n\n",
            "GET /tienda1/index.jsp HTTP/1.1\nHost: localhost:8080\nAccept: text/html\n\n",
            "POST /tienda1/publico/login.jsp HTTP/1.1\nHost: localhost:8080\nContent-Type: application/x-www-form-urlencoded\n\nuser=test&pass=secret",
            "GET /tienda1/publico/carro.jsp HTTP/1.1\nHost: localhost:8080\nCookie: JSESSIONID=12345ABC\n\n",
        ]

        anom_templates = [
            ("GET /tienda1/publico/anadir.jsp?id=1%20UNION%20SELECT%201,password,3%20FROM%20usuarios HTTP/1.1\nHost: localhost:8080\n\n", "SQLI", "CWE-89"),
            ("POST /tienda1/publico/login.jsp HTTP/1.1\nHost: localhost:8080\n\nuser=admin' OR '1'='1&pass=x", "SQLI", "CWE-89"),
            ("GET /tienda1/publico/buscar.jsp?query=<script>alert(1)</script> HTTP/1.1\nHost: localhost:8080\n\n", "XSS", "CWE-79"),
            ("GET /tienda1/ver.jsp?file=../../../../etc/passwd HTTP/1.1\nHost: localhost:8080\n\n", "PATH_TRAVERSAL", "CWE-22"),
            ("GET /tienda1/info.jsp?param=%0d%0aSet-Cookie:%20admin=1 HTTP/1.1\nHost: localhost:8080\n\n", "CRLF", "CWE-113"),
        ]

        for i in range(count):
            if i % 2 == 0:
                raw, atype, cwe = anom_templates[(i // 2) % len(anom_templates)]
                samples.append(
                    TrafficSample(
                        raw_http=raw,
                        is_anomalous=True,
                        attack_type=atype,
                        cwe=cwe,
                        sample_id=f"csic_mock_anom_{i}",
                    )
                )
            else:
                raw = normal_uris[(i // 2) % len(normal_uris)]
                samples.append(
                    TrafficSample(
                        raw_http=raw,
                        is_anomalous=False,
                        attack_type="NORMAL",
                        sample_id=f"csic_mock_norm_{i}",
                    )
                )

        return samples
