"""Tests for CircuitKIT dataset split guards, template disjointness, and dataset hashing."""

import copy
import pytest

from traceguard.experiments.circuit_experiment import (
    DEFAULT_DEV_PATH,
    DEFAULT_TEST_PATH,
    compute_dataset_hash,
    load_contrastive_dataset,
    verify_template_disjointness,
)


def test_dev_and_test_datasets_exist():
    assert DEFAULT_DEV_PATH.exists(), f"Dev dataset missing at {DEFAULT_DEV_PATH}"
    assert DEFAULT_TEST_PATH.exists(), f"Test dataset missing at {DEFAULT_TEST_PATH}"


def test_template_disjointness_on_disk():
    dev_records = load_contrastive_dataset(DEFAULT_DEV_PATH, expected_split="dev")
    test_records = load_contrastive_dataset(DEFAULT_TEST_PATH, expected_split="test")

    assert len(dev_records) >= 10, "Dev dataset should have at least 10 contrastive pairs"
    assert len(test_records) >= 10, "Test dataset should have at least 10 contrastive pairs"

    is_disjoint, overlap = verify_template_disjointness(dev_records, test_records)
    assert is_disjoint is True, f"Template overlap detected between dev and test: {overlap}"
    assert len(overlap) == 0


def test_verify_template_disjointness_detects_leakage():
    dev_records = [
        {"example_id": "d1", "template_id": "TPL_SHARED", "split": "dev", "clean_prompt": "a", "clean_answer": "b", "corrupt_prompt": "c", "corrupt_answer": "d"},
        {"example_id": "d2", "template_id": "TPL_DEV_ONLY", "split": "dev", "clean_prompt": "a", "clean_answer": "b", "corrupt_prompt": "c", "corrupt_answer": "d"},
    ]
    test_records = [
        {"example_id": "t1", "template_id": "TPL_SHARED", "split": "test", "clean_prompt": "a", "clean_answer": "b", "corrupt_prompt": "c", "corrupt_answer": "d"},
        {"example_id": "t2", "template_id": "TPL_TEST_ONLY", "split": "test", "clean_prompt": "a", "clean_answer": "b", "corrupt_prompt": "c", "corrupt_answer": "d"},
    ]

    is_disjoint, overlap = verify_template_disjointness(dev_records, test_records)
    assert is_disjoint is False
    assert overlap == {"TPL_SHARED"}


def test_all_attack_families_represented():
    dev_records = load_contrastive_dataset(DEFAULT_DEV_PATH)
    test_records = load_contrastive_dataset(DEFAULT_TEST_PATH)

    dev_families = {r["attack_family"] for r in dev_records}
    test_families = {r["attack_family"] for r in test_records}

    expected_families = {"A", "B", "C"}
    assert expected_families.issubset(dev_families), f"Dev missing families: {expected_families - dev_families}"
    assert expected_families.issubset(test_families), f"Test missing families: {expected_families - test_families}"


def test_dataset_hash_determinism_and_sensitivity():
    dev_records = load_contrastive_dataset(DEFAULT_DEV_PATH)
    hash_1 = compute_dataset_hash(dev_records)
    hash_2 = compute_dataset_hash(dev_records)
    assert hash_1 == hash_2, "Dataset hash must be deterministic"

    # Modifying one character must produce a different hash
    tampered_records = copy.deepcopy(dev_records)
    tampered_records[0]["clean_prompt"] += " [MODIFIED]"
    tampered_hash = compute_dataset_hash(tampered_records)
    assert tampered_hash != hash_1, "Tampering with a record must change the hash"


def test_split_guard_rejects_wrong_split():
    with pytest.raises(ValueError, match="Record split mismatch"):
        load_contrastive_dataset(DEFAULT_DEV_PATH, expected_split="test")

    with pytest.raises(ValueError, match="Record split mismatch"):
        load_contrastive_dataset(DEFAULT_TEST_PATH, expected_split="dev")


def test_discovery_never_consumes_held_out_test_data(tmp_path):
    from traceguard.experiments.circuit_config import CircuitExperimentConfig
    from traceguard.experiments.circuit_experiment import CircuitExperimentRunner, MockCircuitPipeline

    runner = CircuitExperimentRunner()
    # Request evaluation on test split
    cfg = CircuitExperimentConfig(split="test", output_dir=str(tmp_path))
    mock_pipe = MockCircuitPipeline(output_dir=str(tmp_path))

    summary = runner.run(cfg, pipeline=mock_pipe)
    # Confirm discovery strictly operated on development data
    assert summary.discovery.metadata["discovery_dataset"] == "contrastive_dev"
    assert summary.discovery.metadata["test_data_in_discovery"] is False
    assert (tmp_path / "contrastive_dev.csv").exists()


def test_exact_sample_count_and_content_quality():
    dev_records = load_contrastive_dataset(DEFAULT_DEV_PATH)
    test_records = load_contrastive_dataset(DEFAULT_TEST_PATH)

    assert len(dev_records) == 12
    assert len(test_records) == 12

    for r in dev_records + test_records:
        assert len(r["clean_prompt"].strip()) > 10
        assert len(r["clean_answer"].strip()) > 5
        assert len(r["corrupt_prompt"].strip()) > 10
        assert len(r["corrupt_answer"].strip()) > 5
        assert isinstance(r["expected_prohibited_actions"], list)
        assert len(r["expected_prohibited_actions"]) >= 1

