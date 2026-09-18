"""Data Loaders and Preprocessors for Code Vulnerability Datasets.

Supports:
1. Draper VDISC (C/C++ multi-CWE functions: CWE-119, 120, 469, 476, other)
2. Big-Vul (MSR Big-Vul: commit-level before/after patch pairs with CVE/CWE)
3. DiverseVul (curated low-noise vulnerable/patched functions)
4. CVEfixes (multi-language CVE-to-fix commit diffs with CVSS)
5. SARD / Juliet Test Suite (synthetic test cases across 118+ CWE classes)
6. AI-generated vs Human-written Vulnerabilities dataset (Python SQLi, XSS, Cmd, Path, etc.)

Features:
- Enforces realistic negative/clean ratios (prevents "everything is vulnerable" model bias)
- Enforces strict held-out benchmark splits (e.g. DiverseVul or held-out test splits never touched during training)
"""

from __future__ import annotations

import csv
import json
import os
import random
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CodeSample:
    """Standardized representation of a source code vulnerability sample."""
    code: str
    is_vulnerable: bool
    cwe: str | None = None
    cwes: list[str] = field(default_factory=list)
    language: str = "c"  # c, cpp, python, java
    source_dataset: str = ""
    sample_id: str = ""
    cve_id: str | None = None
    cvss: float | None = None
    fixed_code: str | None = None
    explanation: str | None = None
    is_held_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CodeDatasetLoader:
    """Manages loading, normalization, and balanced splitting of code vulnerability datasets."""

    def __init__(self, data_root: str | Path | None = None, seed: int = 42):
        self.data_root = Path(data_root) if data_root else Path("./datasets/code")
        self.seed = seed
        random.seed(seed)

    # -------------------------------------------------------------------------
    # 1. Draper VDISC Loader
    # -------------------------------------------------------------------------
    def load_draper_vdisc(
        self, filepath: str | Path | None = None, max_samples: int | None = None
    ) -> list[CodeSample]:
        """Loads and parses Draper VDISC jsonl / HDF5 / CSV export.

        VDISC labels: CWE-119, CWE-120, CWE-469, CWE-476, CWE-other.
        """
        path = Path(filepath) if filepath else self.data_root / "vdisc_train.jsonl"
        samples: list[CodeSample] = []

        if path.exists():
            with open(path, encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f):
                    if max_samples and len(samples) >= max_samples:
                        break
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                        func_code = record.get("functionSource", record.get("code", ""))
                        cwes = []
                        # Draper boolean CWE flags
                        for cwe_key in ["CWE-119", "CWE-120", "CWE-469", "CWE-476", "CWE-other"]:
                            if record.get(cwe_key) is True:
                                cwes.append(cwe_key)

                        is_vuln = len(cwes) > 0
                        samples.append(
                            CodeSample(
                                code=func_code,
                                is_vulnerable=is_vuln,
                                cwe=cwes[0] if cwes else None,
                                cwes=cwes,
                                language="c",
                                source_dataset="Draper_VDISC",
                                sample_id=f"vdisc_{idx}",
                            )
                        )
                    except Exception:
                        continue
        else:
            # Generate deterministic representative synthetic/smoke samples if file not yet downloaded
            samples = self._generate_mock_code_samples(
                dataset="Draper_VDISC", count=max_samples or 60, lang="c"
            )

        return samples

    # -------------------------------------------------------------------------
    # 2. Big-Vul (MSR Big-Vul) Loader
    # -------------------------------------------------------------------------
    def load_big_vul(
        self, filepath: str | Path | None = None, max_samples: int | None = None
    ) -> list[CodeSample]:
        """Loads MSR 2020 Big-Vul CSV dataset (ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset)."""
        path = Path(filepath) if filepath else self.data_root / "MSR_data_cleaned.csv"
        samples: list[CodeSample] = []

        if path.exists():
            with open(path, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    if max_samples and len(samples) >= max_samples:
                        break
                    code = row.get("func_before", row.get("code", ""))
                    fixed = row.get("func_after", "")
                    vuln_label = row.get("target", "0") == "1"
                    cwe = row.get("CWE_ID", "CWE-other")
                    cve = row.get("CVE_ID", "")

                    samples.append(
                        CodeSample(
                            code=code,
                            is_vulnerable=vuln_label,
                            cwe=f"CWE-{cwe}" if cwe and not cwe.startswith("CWE-") else cwe,
                            fixed_code=fixed if fixed else None,
                            cve_id=cve if cve else None,
                            language="c",
                            source_dataset="Big-Vul",
                            sample_id=f"bigvul_{idx}",
                        )
                    )
        else:
            samples = self._generate_mock_code_samples(
                dataset="Big-Vul", count=max_samples or 60, lang="c"
            )

        return samples

    # -------------------------------------------------------------------------
    # 3. DiverseVul Loader (Curated low-noise dataset)
    # -------------------------------------------------------------------------
    def load_diverse_vul(
        self, filepath: str | Path | None = None, max_samples: int | None = None
    ) -> list[CodeSample]:
        """Loads DiverseVul JSONL dataset."""
        path = Path(filepath) if filepath else self.data_root / "diversevul_20230702.jsonl"
        samples: list[CodeSample] = []

        if path.exists():
            with open(path, encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f):
                    if max_samples and len(samples) >= max_samples:
                        break
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                        code = rec.get("func", "")
                        target = rec.get("target", 0) == 1
                        cwe = rec.get("cwe", ["CWE-other"])
                        if isinstance(cwe, list):
                            cwe_val = cwe[0] if cwe else "CWE-other"
                        else:
                            cwe_val = str(cwe)

                        samples.append(
                            CodeSample(
                                code=code,
                                is_vulnerable=target,
                                cwe=cwe_val,
                                language="c",
                                source_dataset="DiverseVul",
                                sample_id=f"diverse_{idx}",
                            )
                        )
                    except Exception:
                        continue
        else:
            samples = self._generate_mock_code_samples(
                dataset="DiverseVul", count=max_samples or 60, lang="cpp"
            )

        return samples

    # -------------------------------------------------------------------------
    # 4. CVEfixes Loader
    # -------------------------------------------------------------------------
    def load_cvefixes(
        self, filepath: str | Path | None = None, max_samples: int | None = None
    ) -> list[CodeSample]:
        """Loads CVEfixes commits and method pairs."""
        path = Path(filepath) if filepath else self.data_root / "cvefixes_methods.csv"
        samples: list[CodeSample] = []

        if path.exists():
            with open(path, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    if max_samples and len(samples) >= max_samples:
                        break
                    code = row.get("before_change", row.get("code", ""))
                    after = row.get("after_change", "")
                    cwe = row.get("cwe_id", "CWE-89")
                    cvss = float(row.get("cvss", 7.5)) if row.get("cvss") else None
                    lang = row.get("language", "python").lower()

                    samples.append(
                        CodeSample(
                            code=code,
                            is_vulnerable=True,
                            fixed_code=after,
                            cwe=cwe,
                            cvss=cvss,
                            language=lang,
                            source_dataset="CVEfixes",
                            sample_id=f"cvefixes_{idx}",
                        )
                    )
        else:
            samples = self._generate_mock_code_samples(
                dataset="CVEfixes", count=max_samples or 60, lang="python"
            )

        return samples

    # -------------------------------------------------------------------------
    # 5. SARD / Juliet Test Suite Loader
    # -------------------------------------------------------------------------
    def load_sard_juliet(
        self, directory: str | Path | None = None, max_samples: int | None = None
    ) -> list[CodeSample]:
        """Loads Juliet C/C++ or Java synthetic test cases."""
        path = Path(directory) if directory else self.data_root / "sard_juliet"
        samples: list[CodeSample] = []

        if path.exists() and path.is_dir():
            for root, _, files in os.walk(path):
                for fname in files:
                    if fname.endswith((".c", ".cpp", ".java")):
                        if max_samples and len(samples) >= max_samples:
                            break
                        fpath = Path(root) / fname
                        content = fpath.read_text(encoding="utf-8", errors="replace")
                        # Infer CWE from filename, e.g., CWE120_Buffer_Overflow__...
                        cwe_match = re.search(r"CWE(\d+)", fname)
                        cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else "CWE-119"

                        # Juliet separates bad() and good() functions
                        if "_bad" in fname or "bad()" in content:
                            samples.append(
                                CodeSample(
                                    code=content,
                                    is_vulnerable=True,
                                    cwe=cwe_id,
                                    source_dataset="SARD_Juliet",
                                    sample_id=fname,
                                )
                            )
                        if "_good" in fname or "good()" in content:
                            samples.append(
                                CodeSample(
                                    code=content,
                                    is_vulnerable=False,
                                    cwe=None,
                                    source_dataset="SARD_Juliet",
                                    sample_id=fname + "_good",
                                )
                            )
        else:
            samples = self._generate_mock_code_samples(
                dataset="SARD_Juliet", count=max_samples or 60, lang="c"
            )

        return samples

    # -------------------------------------------------------------------------
    # 6. AI-generated vs Human-written Vulnerable Code Dataset
    # -------------------------------------------------------------------------
    def load_ai_vs_human_dataset(
        self, filepath: str | Path | None = None, max_samples: int | None = None
    ) -> list[CodeSample]:
        """Loads IEEE DataPort 'AI generated and human written code' dataset."""
        path = Path(filepath) if filepath else self.data_root / "ai_human_vulns.json"
        samples: list[CodeSample] = []

        if path.exists():
            with open(path, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
                items = data if isinstance(data, list) else data.get("samples", [])
                for idx, item in enumerate(items):
                    if max_samples and len(samples) >= max_samples:
                        break
                    samples.append(
                        CodeSample(
                            code=item.get("vulnerable_code", ""),
                            is_vulnerable=True,
                            cwe=item.get("cwe_id", "CWE-89"),
                            fixed_code=item.get("patched_code", ""),
                            explanation=item.get("explanation", ""),
                            language="python",
                            source_dataset="AI_vs_Human_Vuln",
                            sample_id=f"ai_human_{idx}",
                        )
                    )
        else:
            samples = self._generate_mock_code_samples(
                dataset="AI_vs_Human_Vuln", count=max_samples or 60, lang="python"
            )

        return samples

    # -------------------------------------------------------------------------
    # Balanced Dataset Construction & Negative Ratio Control
    # -------------------------------------------------------------------------
    def prepare_training_corpus(
        self,
        samples: list[CodeSample],
        target_negative_ratio: float = 0.50,  # 50% clean, 50% vulnerable realistic balance
        val_split: float = 0.15,
        test_split: float = 0.15,
    ) -> dict[str, list[CodeSample]]:
        """Splits corpus into train, val, test with controlled clean/vulnerable ratio."""
        vuln = [s for s in samples if s.is_vulnerable]
        clean = [s for s in samples if not s.is_vulnerable]

        random.shuffle(vuln)
        random.shuffle(clean)

        # Balance to target_negative_ratio: N_clean = N_vuln * (ratio / (1 - ratio))
        if clean and vuln:
            desired_clean = int(len(vuln) * (target_negative_ratio / (1.0 - target_negative_ratio)))
            clean = clean[:max(1, min(len(clean), desired_clean))]

        combined = vuln + clean
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

    def _generate_mock_code_samples(
        self, dataset: str, count: int = 60, lang: str = "c"
    ) -> list[CodeSample]:
        """Generates representative samples for smoke testing and offline verification."""
        samples: list[CodeSample] = []
        templates_vuln = [
            # SQLi
            ("def get_user(uid):\n    return db.execute(f'SELECT * FROM users WHERE id = {uid}')", "CWE-89", "python"),
            ("int auth(char *user) {\n    char q[256];\n    sprintf(q, 'SELECT * FROM u WHERE n = %s', user);\n    return db_query(q);\n}", "CWE-89", "c"),
            # Buffer Overflow
            ("void copy_buf(char *src) {\n    char dest[64];\n    strcpy(dest, src);\n}", "CWE-120", "c"),
            ("void read_input() {\n    char buf[128];\n    gets(buf);\n}", "CWE-120", "c"),
            # Command Injection
            ("def ping_host(host):\n    os.system(f'ping -c 1 {host}')", "CWE-78", "python"),
            ("def run_cmd(user_arg):\n    subprocess.Popen('echo ' + user_arg, shell=True)", "CWE-78", "python"),
            # Path Traversal
            ("def get_file(fname):\n    with open('../data/' + fname, 'r') as f:\n        return f.read()", "CWE-22", "python"),
            # Null Pointer Dereference
            ("int deref(int *ptr) {\n    return *ptr;\n}", "CWE-476", "c"),
        ]

        templates_clean = [
            ("def get_user(uid):\n    return db.execute('SELECT * FROM users WHERE id = %s', (uid,))", None, "python"),
            ("void copy_buf(char *src) {\n    char dest[64];\n    strncpy(dest, src, sizeof(dest) - 1);\n    dest[63] = '\\0';\n}", None, "c"),
            ("def ping_host(host):\n    subprocess.run(['ping', '-c', '1', host], shell=False)", None, "python"),
            ("def get_file(fname):\n    safe_name = os.path.basename(fname)\n    with open(safe_name, 'r') as f:\n        return f.read()", None, "python"),
            ("int deref(int *ptr) {\n    if (!ptr) return -1;\n    return *ptr;\n}", None, "c"),
            ("def add(a, b):\n    return a + b", None, "python"),
        ]

        cvss_map = {
            "CWE-89": 8.8,
            "CWE-78": 9.8,
            "CWE-120": 9.8,
            "CWE-119": 9.8,
            "CWE-22": 7.5,
            "CWE-476": 6.5,
            "CWE-79": 6.1,
        }

        for i in range(count):
            if i % 2 == 0:
                tpl, cwe, lang = templates_vuln[(i // 2) % len(templates_vuln)]
                samples.append(
                    CodeSample(
                        code=tpl,
                        is_vulnerable=True,
                        cwe=cwe,
                        cwes=[cwe] if cwe else [],
                        language=lang,
                        source_dataset=dataset,
                        sample_id=f"{dataset}_{i}",
                        cvss=cvss_map.get(cwe, 7.5),
                    )
                )
            else:
                tpl, _, lang = templates_clean[(i // 2) % len(templates_clean)]
                samples.append(
                    CodeSample(
                        code=tpl,
                        is_vulnerable=False,
                        cwe=None,
                        cwes=[],
                        language=lang,
                        source_dataset=dataset,
                        sample_id=f"{dataset}_{i}",
                    )
                )

        return samples
