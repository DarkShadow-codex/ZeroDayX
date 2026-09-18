"""Data Loaders and Feature Extractors for Malicious URL and Phishing Datasets.

Supports:
1. PhiUSIIL Phishing URL Dataset (134k legit + 100k phishing, structural & source features)
2. Malicious URLs Dataset (ISCX-URL-2016, PhishTank, PhishStorm, Malware domains)
3. Suspicious URLs Lexical Analysis Dataset (80 lexical features, 4 categories: spam, malware, phishing, defacement)
4. Lexical and Shannon Entropy feature extraction pipeline.
"""

from __future__ import annotations

import csv
import math
import random
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class UrlSample:
    """Standardized representation of a URL security sample."""
    url: str
    is_malicious: bool
    category: str  # BENIGN, PHISHING, MALWARE, DEFACEMENT, SPAM
    cwe: str = "CWE-601"
    features: dict[str, float] = field(default_factory=dict)
    source_dataset: str = ""
    sample_id: str = ""
    is_held_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class UrlDatasetLoader:
    """Loads and extracts standardized lexical features from URL datasets."""

    def __init__(self, data_root: str | Path | None = None, seed: int = 42):
        self.data_root = Path(data_root) if data_root else Path("./datasets/url")
        self.seed = seed
        random.seed(seed)

    @staticmethod
    def extract_lexical_features(url: str) -> dict[str, float]:
        """Extracts numerical lexical features for lightweight ML models."""
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()

        # Shannon entropy
        prob = [float(netloc.count(c)) / len(netloc) for c in dict.fromkeys(netloc)] if netloc else [0.0]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)

        return {
            "url_length": float(len(url)),
            "host_length": float(len(netloc)),
            "path_length": float(len(path)),
            "count_dots": float(url.count(".")),
            "count_hyphens": float(url.count("-")),
            "count_at": float(url.count("@")),
            "count_slash": float(url.count("/")),
            "count_digits": float(sum(c.isdigit() for c in url)),
            "entropy": float(entropy),
            "is_ip": 1.0 if netloc.replace(".", "").isdigit() else 0.0,
            "has_https": 1.0 if url.startswith("https://") else 0.0,
        }

    # -------------------------------------------------------------------------
    # 1. PhiUSIIL Phishing URL Dataset Loader
    # -------------------------------------------------------------------------
    def load_phiusiil(
        self, filepath: str | Path | None = None, max_samples: int | None = None
    ) -> list[UrlSample]:
        """Loads PhiUSIIL dataset CSV."""
        path = Path(filepath) if filepath else self.data_root / "PhiUSIIL_Phishing_URL_Dataset.csv"
        samples: list[UrlSample] = []

        if path.exists():
            with open(path, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    if max_samples and len(samples) >= max_samples:
                        break
                    raw_url = row.get("URL", row.get("url", ""))
                    label = row.get("label", "0")  # 1: phishing, 0: legitimate
                    is_phish = label == "1"

                    feats = self.extract_lexical_features(raw_url)
                    samples.append(
                        UrlSample(
                            url=raw_url,
                            is_malicious=is_phish,
                            category="PHISHING" if is_phish else "BENIGN",
                            cwe="CWE-601" if is_phish else "CWE-20",
                            features=feats,
                            source_dataset="PhiUSIIL",
                            sample_id=f"phiusiil_{idx}",
                        )
                    )
        else:
            samples = self._generate_mock_url_samples(
                dataset="PhiUSIIL", count=max_samples or 80
            )

        return samples

    # -------------------------------------------------------------------------
    # 2. Malicious URLs Dataset (ISCX, PhishTank, PhishStorm)
    # -------------------------------------------------------------------------
    def load_malicious_urls(
        self, filepath: str | Path | None = None, max_samples: int | None = None
    ) -> list[UrlSample]:
        """Loads Kaggle Malicious URLs Dataset CSV."""
        path = Path(filepath) if filepath else self.data_root / "malicious_phish.csv"
        samples: list[UrlSample] = []

        if path.exists():
            with open(path, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    if max_samples and len(samples) >= max_samples:
                        break
                    raw_url = row.get("url", "")
                    cat = row.get("type", "benign").upper()
                    is_mal = cat != "BENIGN"

                    feats = self.extract_lexical_features(raw_url)
                    samples.append(
                        UrlSample(
                            url=raw_url,
                            is_malicious=is_mal,
                            category=cat,
                            features=feats,
                            source_dataset="Malicious_URLs",
                            sample_id=f"malurls_{idx}",
                        )
                    )
        else:
            samples = self._generate_mock_url_samples(
                dataset="Malicious_URLs", count=max_samples or 80
            )

        return samples

    # -------------------------------------------------------------------------
    # 3. Suspicious URLs Lexical Analysis Dataset Loader
    # -------------------------------------------------------------------------
    def load_suspicious_lexical(
        self, filepath: str | Path | None = None, max_samples: int | None = None
    ) -> list[UrlSample]:
        """Loads Suspicious URLs Lexical Analysis dataset."""
        path = Path(filepath) if filepath else self.data_root / "suspicious_urls_lexical.csv"
        samples: list[UrlSample] = []

        if path.exists():
            with open(path, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    if max_samples and len(samples) >= max_samples:
                        break
                    raw_url = row.get("url", "")
                    cat = row.get("category", "benign").upper()
                    is_mal = cat != "BENIGN"

                    feats = self.extract_lexical_features(raw_url)
                    samples.append(
                        UrlSample(
                            url=raw_url,
                            is_malicious=is_mal,
                            category=cat,
                            features=feats,
                            source_dataset="Suspicious_Lexical",
                            sample_id=f"lexical_{idx}",
                        )
                    )
        else:
            samples = self._generate_mock_url_samples(
                dataset="Suspicious_Lexical", count=max_samples or 80
            )

        return samples

    def prepare_url_splits(
        self,
        samples: list[UrlSample],
        target_benign_ratio: float = 0.50,
        val_split: float = 0.15,
        test_split: float = 0.15,
    ) -> dict[str, list[UrlSample]]:
        """Prepares train, validation, and held-out test splits."""
        benign = [s for s in samples if not s.is_malicious]
        malicious = [s for s in samples if s.is_malicious]

        random.shuffle(benign)
        random.shuffle(malicious)

        combined = benign + malicious
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

    def _generate_mock_url_samples(self, dataset: str, count: int = 80) -> list[UrlSample]:
        """Generates representative benign and phishing URLs."""
        benign_urls = [
            "https://www.google.com/search?q=cybersecurity+research",
            "https://github.com/usezeroday/zeroday",
            "https://en.wikipedia.org/wiki/Penetration_test",
            "https://aws.amazon.com/security/",
            "https://www.paypal.com/signin",
            "https://netflix.com/browse",
        ]

        phish_urls = [
            "http://paypal-security-update.account-verification.top/login.php",
            "http://192.168.1.100:8080/secure-update/chase-banking",
            "https://accounts-google-verify.security-check.xyz/auth",
            "http://apple-support-id-check.cam/recovery@verify.php",
            "http://netflix-billing-issue-alert.fit/signin.html",
            "http://login.microsoftonline.com.account-suspension.click/portal",
        ]

        samples: list[UrlSample] = []
        for i in range(count):
            if i % 2 == 0:
                u = phish_urls[(i // 2) % len(phish_urls)]
                samples.append(
                    UrlSample(
                        url=u,
                        is_malicious=True,
                        category="PHISHING",
                        cwe="CWE-601",
                        features=self.extract_lexical_features(u),
                        source_dataset=dataset,
                        sample_id=f"{dataset}_mock_mal_{i}",
                    )
                )
            else:
                u = benign_urls[(i // 2) % len(benign_urls)]
                samples.append(
                    UrlSample(
                        url=u,
                        is_malicious=False,
                        category="BENIGN",
                        cwe="CWE-20",
                        features=self.extract_lexical_features(u),
                        source_dataset=dataset,
                        sample_id=f"{dataset}_mock_ben_{i}",
                    )
                )

        return samples
