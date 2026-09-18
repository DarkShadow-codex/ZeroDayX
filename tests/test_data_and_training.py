"""Tests for ZeroDay Data Loaders, Preprocessing, and Training Scripts."""

import subprocess
import sys
from pathlib import Path

import pytest
from zeroday.data.code_datasets import CodeDatasetLoader
from zeroday.data.nvd_rag import CveRecord, NvdRagIndex
from zeroday.data.traffic_datasets import TrafficDatasetLoader
from zeroday.data.url_datasets import UrlDatasetLoader


def test_code_dataset_loader():
    loader = CodeDatasetLoader()
    vdisc = loader.load_draper_vdisc(max_samples=20)
    assert len(vdisc) == 20
    assert any(s.is_vulnerable for s in vdisc)
    assert any(not s.is_vulnerable for s in vdisc)

    bigvul = loader.load_big_vul(max_samples=20)
    assert len(bigvul) == 20

    diverse = loader.load_diverse_vul(max_samples=20)
    assert len(diverse) == 20

    juliet = loader.load_sard_juliet(max_samples=20)
    assert len(juliet) == 20

    ai_vs_human = loader.load_ai_vs_human_dataset(max_samples=20)
    assert len(ai_vs_human) == 20

    splits = loader.prepare_training_corpus(vdisc, target_negative_ratio=0.5)
    assert "train" in splits
    assert "val" in splits
    assert "test" in splits


def test_traffic_dataset_loader():
    loader = TrafficDatasetLoader()
    samples = loader.load_csic_2010(max_samples=30)
    assert len(samples) == 30
    assert any(s.is_anomalous for s in samples)
    assert any(not s.is_anomalous for s in samples)

    splits = loader.prepare_traffic_splits(samples)
    assert len(splits["train"]) > 0
    assert len(splits["test"]) > 0


def test_url_dataset_loader():
    loader = UrlDatasetLoader()
    phiusiil = loader.load_phiusiil(max_samples=30)
    assert len(phiusiil) == 30

    malurl = loader.load_malicious_urls(max_samples=30)
    assert len(malurl) == 30

    lexical = loader.load_suspicious_lexical(max_samples=30)
    assert len(lexical) == 30

    splits = loader.prepare_url_splits(phiusiil)
    assert len(splits["train"]) > 0
    assert len(splits["test"]) > 0


def test_nvd_rag_index():
    index = NvdRagIndex()
    res = index.query("CWE-89")
    assert len(res) > 0
    assert any("CWE-89" in r["cwe"] for r in res)

    res_kw = index.query("Log4j")
    assert len(res_kw) > 0


def test_training_scripts_dry_run():
    # Run train_code_classifier dry-run
    cmd_code = [sys.executable, "scripts/training/train_code_classifier.py", "--dry-run", "--max-samples", "20", "--epochs", "1"]
    res_code = subprocess.run(cmd_code, capture_output=True, text=True)
    assert res_code.returncode == 0, res_code.stderr

    # Run train_traffic_classifier dry-run
    cmd_traffic = [sys.executable, "scripts/training/train_traffic_classifier.py", "--dry-run", "--max-samples", "20", "--epochs", "1"]
    res_traffic = subprocess.run(cmd_traffic, capture_output=True, text=True)
    assert res_traffic.returncode == 0, res_traffic.stderr

    # Run train_url_classifier dry-run
    cmd_url = [sys.executable, "scripts/training/train_url_classifier.py", "--dry-run", "--max-samples", "20", "--epochs", "1"]
    res_url = subprocess.run(cmd_url, capture_output=True, text=True)
    assert res_url.returncode == 0, res_url.stderr
