"""Tests for CuratorKIT quality gate enforcement."""

import pytest

from traceguard.data.curator.ingestion import DatasetIngester
from traceguard.data.curator.quality_gates import QualityGateRunner
from traceguard.data.schema import CanarySpec, Episode, Turn


def test_quality_gate_passes_valid_episodes():
    runner = QualityGateRunner()
    ep_attack = Episode(
        episode_id="ep_atk_01",
        template_id="tpl_atk_01",
        split="dev",
        initial_user_task="Read doc",
        is_attack=True,
        attack_family="family_a",
        turns=[Turn(turn_id=1, user_message="Message")],
        synthetic_canaries=[CanarySpec(value="CANARY_01")],
        expected_safe_behavior="Ignore injection",
        expected_prohibited_actions=["send_email"],
    )
    violations = runner.evaluate_episode(ep_attack)
    assert len(violations) == 0


def test_quality_gate_fails_attack_without_canaries():
    runner = QualityGateRunner()
    ep_bad_attack = Episode(
        episode_id="ep_atk_nocanary",
        template_id="tpl_01",
        split="dev",
        initial_user_task="Task",
        is_attack=True,
        attack_family="family_a",
        turns=[Turn(turn_id=1, user_message="Message")],
        synthetic_canaries=[],  # Missing canary
        expected_safe_behavior="Behavior",
        expected_prohibited_actions=["bash"],
    )
    violations = runner.evaluate_episode(ep_bad_attack)
    assert any(v.check_name == "canaries_present" for v in violations)


def test_quality_gate_fails_benign_with_canaries():
    runner = QualityGateRunner()
    ep_bad_benign = Episode(
        episode_id="ep_ben_canary",
        template_id="tpl_02",
        split="dev",
        initial_user_task="Benign task",
        is_attack=False,
        attack_family="benign",
        turns=[Turn(turn_id=1, user_message="Message")],
        synthetic_canaries=[CanarySpec(value="CANARY_LEAKED_INTO_BENIGN")],
    )
    violations = runner.evaluate_episode(ep_bad_benign)
    assert any(v.check_name == "no_canaries_in_benign" for v in violations)


def test_quality_gate_fails_invalid_attack_family():
    runner = QualityGateRunner()
    ep_bad_family = Episode(
        episode_id="ep_bad_fam",
        template_id="tpl_03",
        split="dev",
        initial_user_task="Task",
        is_attack=True,
        attack_family="family_z",  # Invalid
        turns=[Turn(turn_id=1, user_message="Message")],
        synthetic_canaries=[CanarySpec(value="CANARY_03")],
        expected_safe_behavior="Behavior",
        expected_prohibited_actions=["bash"],
    )
    violations = runner.evaluate_episode(ep_bad_family)
    assert any(v.check_name == "valid_attack_family" for v in violations)


def test_quality_gate_on_real_datasets():
    ingester = DatasetIngester()
    dataset_map = {
        "attack_dev": "episodes_attack_dev.jsonl",
        "attack_test": "episodes_attack_test.jsonl",
        "benign_dev": "episodes_benign_dev.jsonl",
        "benign_test": "episodes_benign_test.jsonl",
    }
    episodes_dict, _ = ingester.ingest_collection("traceguard/data", dataset_map)

    runner = QualityGateRunner()
    report = runner.evaluate_collection(episodes_dict)

    assert report.passed is True
    assert report.failed_checks_count == 0
    assert report.metrics["total_episodes"] == 60
    assert report.metrics["unique_canaries_count"] == 30
    assert report.metrics["template_overlap_count"] == 0
