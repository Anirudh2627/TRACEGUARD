"""Tests for CuratorKIT DEV/TEST split hygiene, template isolation, and leakage prevention."""

import pytest

from traceguard.data.curator.ingestion import DatasetIngester
from traceguard.data.curator.quality_gates import QualityGateRunner
from traceguard.data.schema import CanarySpec, Episode, Turn


def test_split_template_disjointness_on_disk():
    ingester = DatasetIngester()
    dataset_map = {
        "attack_dev": "episodes_attack_dev.jsonl",
        "attack_test": "episodes_attack_test.jsonl",
        "benign_dev": "episodes_benign_dev.jsonl",
        "benign_test": "episodes_benign_test.jsonl",
    }
    episodes_dict, _ = ingester.ingest_collection("traceguard/data", dataset_map)

    dev_templates = {ep.template_id for ep in episodes_dict["attack_dev"]}
    test_templates = {ep.template_id for ep in episodes_dict["attack_test"]}

    overlap = dev_templates.intersection(test_templates)
    assert len(overlap) == 0, f"Template leakage detected between attack DEV and TEST: {overlap}"


def test_canary_disjointness_across_splits():
    ingester = DatasetIngester()
    dataset_map = {
        "attack_dev": "episodes_attack_dev.jsonl",
        "attack_test": "episodes_attack_test.jsonl",
    }
    episodes_dict, _ = ingester.ingest_collection("traceguard/data", dataset_map)

    dev_canaries = {c.value for ep in episodes_dict["attack_dev"] for c in ep.synthetic_canaries}
    test_canaries = {c.value for ep in episodes_dict["attack_test"] for c in ep.synthetic_canaries}

    overlap = dev_canaries.intersection(test_canaries)
    assert len(overlap) == 0, f"Canary overlap detected between DEV and TEST: {overlap}"
    assert len(dev_canaries) == 15
    assert len(test_canaries) == 15


def test_simulated_split_leakage_triggers_quality_gate_failure():
    # Artificially create attack dev and test with a shared template
    ep_dev = Episode(
        episode_id="ep_dev_leak",
        template_id="SHARED_TEMPLATE_LEAK",
        split="dev",
        initial_user_task="Task",
        is_attack=True,
        attack_family="family_a",
        turns=[Turn(turn_id=1, user_message="Msg")],
        synthetic_canaries=[CanarySpec(value="CANARY_DEV_LEAK")],
        expected_safe_behavior="Behavior",
        expected_prohibited_actions=["bash"],
    )
    ep_test = Episode(
        episode_id="ep_test_leak",
        template_id="SHARED_TEMPLATE_LEAK",  # Overlap!
        split="test",
        initial_user_task="Task",
        is_attack=True,
        attack_family="family_a",
        turns=[Turn(turn_id=1, user_message="Msg")],
        synthetic_canaries=[CanarySpec(value="CANARY_TEST_LEAK")],
        expected_safe_behavior="Behavior",
        expected_prohibited_actions=["bash"],
    )

    runner = QualityGateRunner()
    fake_collection = {
        "attack_dev": [ep_dev],
        "attack_test": [ep_test],
    }
    report = runner.evaluate_collection(fake_collection)

    assert report.passed is False
    assert any(v.check_name == "attack_template_disjointness" for v in report.violations)
