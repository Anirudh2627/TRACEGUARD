"""Unit tests for TraceGuard evaluation harness.

Module 7 — Evaluation + Provenance Ablation.
Member 2: Data & Interpretability Lead.
"""

import json
from pathlib import Path
import pytest

from traceguard.experiments.evaluation import Evaluator


def test_evaluator_load_episodes_split_separation(tmp_path):
    """Verify clean separation between DEV and TEST splits."""
    evaluator = Evaluator()

    # Load dev
    dev_attack, dev_benign = evaluator.load_episodes(split="dev")
    assert len(dev_attack) == 15
    assert len(dev_benign) == 15
    assert all(e.split == "dev" for e in dev_attack)
    assert all(e.split == "dev" for e in dev_benign)

    # Load test
    test_attack, test_benign = evaluator.load_episodes(split="test")
    assert len(test_attack) == 15
    assert len(test_benign) == 15
    assert all(e.split == "test" for e in test_attack)
    assert all(e.split == "test" for e in test_benign)

    # Confirm template disjointness between dev and test attack episodes
    dev_templates = {e.template_id for e in dev_attack}
    test_templates = {e.template_id for e in test_attack}
    assert dev_templates.isdisjoint(test_templates)


def test_evaluator_e3_stub_handling():
    """E3 must report status 'unavailable' and not falsely claim calibrated weights."""
    evaluator = Evaluator()
    metrics, logs = evaluator.evaluate_configuration(configuration="E3", split="test")

    assert metrics.configuration == "E3"
    assert metrics.status == "unavailable"
    assert "stub only" in (metrics.notes or "")
    assert len(logs) == 0


def test_evaluator_e0_vs_e2b_evaluation():
    """Verify E0 baseline allows attacks while E2b blocks attacks."""
    evaluator = Evaluator()

    # Evaluate E0 (baseline)
    metrics_e0, logs_e0 = evaluator.evaluate_configuration(
        configuration="E0", split="test"
    )
    assert metrics_e0.configuration == "E0"
    assert metrics_e0.attack_metrics.prohibited_action_rate.rate > 0.0

    # Evaluate E2b (persistent gateway)
    metrics_e2b, logs_e2b = evaluator.evaluate_configuration(
        configuration="E2b", split="test"
    )
    assert metrics_e2b.configuration == "E2b"
    assert metrics_e2b.attack_metrics.attack_block_rate.rate == 1.0
    assert metrics_e2b.benign_metrics.benign_task_completion_rate.rate == 1.0


def test_evaluator_evaluate_all_generates_artifacts(tmp_path):
    """Verify evaluate_all creates all required files and valid summary.json."""
    evaluator = Evaluator()
    summary = evaluator.evaluate_all(split="test", out_dir=tmp_path)

    # Check generated files
    expected_files = [
        "e0_results.jsonl",
        "e1_results.jsonl",
        "e2a_results.jsonl",
        "e2b_results.jsonl",
        "e3_results.jsonl",
        "e4_results.jsonl",
        "summary.json",
    ]
    for fn in expected_files:
        p = tmp_path / fn
        assert p.exists(), f"Missing required evaluation output file: {fn}"
        assert p.stat().st_size > 0, f"File is empty: {fn}"

    # Verify summary contents
    assert summary["split"] == "test"
    assert summary["episodes_per_configuration"] == 30
    assert "comparison" in summary
    assert "research_question_conclusion" in summary
    assert "YES" in summary["research_question_conclusion"]["answer"]

    # Verify E3 stub in summary
    assert summary["configurations"]["E3"]["status"] == "unavailable"


def test_deterministic_repeated_evaluation():
    """Confirm repeated evaluations under deterministic simulation yield identical metrics."""
    evaluator = Evaluator()
    m1, _ = evaluator.evaluate_configuration(configuration="E2b", split="test")
    m2, _ = evaluator.evaluate_configuration(configuration="E2b", split="test")

    assert m1.to_dict() == m2.to_dict()
