"""Tests for TraceGuard Comprehensive Dataset Validator (Module 5).

Verifies the validator's quality gate across 16 formal conditions:
1. Valid complete dataset passes.
2. Wrong episode count fails.
3. Duplicate episode ID fails.
4. Split mismatch fails.
5. Attack/benign mismatch fails.
6. Duplicate attack template across DEV/TEST fails (leakage).
7. Unknown template fails.
8. Invalid provenance fails.
9. Duplicate canary fails.
10. Missing authorized scope fails.
11. Invalid tool name fails.
12. Invalid turn count fails.
13. Duplicate turn ID fails.
14. Invalid expected prohibited action fails.
15. Benign dataset containing attack canary fails.
16. Manifest contains expected summary fields.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import pytest

from traceguard.data.dataset_validator import (
    ATTACK_DEV_FILE,
    ATTACK_TEST_FILE,
    BENIGN_DEV_FILE,
    BENIGN_TEST_FILE,
    MANIFEST_FILE,
    DatasetValidator,
    load_episodes_from_jsonl,
    validate_dataset,
)
from traceguard.data.schema import (
    CanarySpec,
    Episode,
    ProvenanceLabel,
    SourceRecord,
    Turn,
)


@pytest.fixture(scope="module")
def canonical_datasets():
    """Load the canonical 60 episodes."""
    attack_dev = load_episodes_from_jsonl(ATTACK_DEV_FILE)
    attack_test = load_episodes_from_jsonl(ATTACK_TEST_FILE)
    benign_dev = load_episodes_from_jsonl(BENIGN_DEV_FILE)
    benign_test = load_episodes_from_jsonl(BENIGN_TEST_FILE)
    return {
        "attack_dev": attack_dev,
        "attack_test": attack_test,
        "benign_dev": benign_dev,
        "benign_test": benign_test,
    }


@pytest.fixture
def validator():
    return DatasetValidator()


# ---------- 1. Valid complete dataset passes ----------


def test_valid_complete_dataset_passes():
    result = validate_dataset(write_manifest=False)
    assert result.passed is True
    assert len(result.errors) == 0
    assert result.summary["total_episodes"] == 60
    assert result.summary["attack_dev_count"] == 15
    assert result.summary["attack_test_count"] == 15
    assert result.summary["benign_dev_count"] == 15
    assert result.summary["benign_test_count"] == 15


# ---------- 2. Wrong episode count fails ----------


def test_wrong_episode_count_fails(validator, canonical_datasets):
    # Shorten attack_dev to 14 episodes
    res = validator.validate_collections(
        attack_dev=canonical_datasets["attack_dev"][:-1],
        attack_test=canonical_datasets["attack_test"],
        benign_dev=canonical_datasets["benign_dev"],
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("Count mismatch for attack_dev" in err for err in res.errors)
    assert any("Total episode count mismatch" in err for err in res.errors)


# ---------- 3. Duplicate episode ID fails ----------


def test_duplicate_episode_id_fails(validator, canonical_datasets):
    # Introduce duplicate ID in attack_test
    attack_test_copy = list(canonical_datasets["attack_test"])
    dup_ep = copy.deepcopy(attack_test_copy[0])
    # Give it the ID of an episode from attack_dev
    object.__setattr__(dup_ep, "episode_id", canonical_datasets["attack_dev"][0].episode_id)
    attack_test_copy[0] = dup_ep

    res = validator.validate_collections(
        attack_dev=canonical_datasets["attack_dev"],
        attack_test=attack_test_copy,
        benign_dev=canonical_datasets["benign_dev"],
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("Duplicate episode IDs detected" in err for err in res.errors)


# ---------- 4. Split mismatch fails ----------


def test_split_mismatch_fails(validator, canonical_datasets):
    # Episode with split 'test' placed inside attack_dev
    attack_dev_copy = list(canonical_datasets["attack_dev"])
    bad_ep = copy.deepcopy(attack_dev_copy[0])
    object.__setattr__(bad_ep, "split", "test")
    attack_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=attack_dev_copy,
        attack_test=canonical_datasets["attack_test"],
        benign_dev=canonical_datasets["benign_dev"],
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("split mismatch: internal split is 'test', expected 'dev'" in err for err in res.errors)


# ---------- 5. Attack / Benign mismatch fails ----------


def test_attack_benign_mismatch_fails(validator, canonical_datasets):
    # Attack episode marked is_attack=False placed in attack_dev
    attack_dev_copy = list(canonical_datasets["attack_dev"])
    bad_ep = copy.deepcopy(attack_dev_copy[0])
    object.__setattr__(bad_ep, "is_attack", False)
    attack_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=attack_dev_copy,
        attack_test=canonical_datasets["attack_test"],
        benign_dev=canonical_datasets["benign_dev"],
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("is_attack mismatch: got False, expected True" in err for err in res.errors)


# ---------- 6. Duplicate attack template across DEV/TEST fails ----------


def test_duplicate_attack_template_across_dev_test_fails(validator, canonical_datasets):
    # Leak template doc_injection_01 (from dev) into test
    attack_test_copy = list(canonical_datasets["attack_test"])
    leaked_ep = copy.deepcopy(attack_test_copy[0])
    object.__setattr__(leaked_ep, "template_id", "doc_injection_01")
    attack_test_copy[0] = leaked_ep

    res = validator.validate_collections(
        attack_dev=canonical_datasets["attack_dev"],
        attack_test=attack_test_copy,
        benign_dev=canonical_datasets["benign_dev"],
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("LEAKAGE DETECTED! Attack templates shared between DEV and TEST" in err for err in res.errors)
    assert any("doc_injection_01" in err for err in res.errors)


# ---------- 7. Unknown template fails ----------


def test_unknown_template_fails(validator, canonical_datasets):
    attack_dev_copy = list(canonical_datasets["attack_dev"])
    bad_ep = copy.deepcopy(attack_dev_copy[0])
    object.__setattr__(bad_ep, "template_id", "completely_unknown_template_999")
    attack_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=attack_dev_copy,
        attack_test=canonical_datasets["attack_test"],
        benign_dev=canonical_datasets["benign_dev"],
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("template_id 'completely_unknown_template_999' not in taxonomy" in err for err in res.errors)


# ---------- 8. Invalid provenance fails ----------


def test_invalid_provenance_fails(validator, canonical_datasets):
    attack_dev_copy = list(canonical_datasets["attack_dev"])
    bad_ep = copy.deepcopy(attack_dev_copy[0])
    # Construct a source record with elevated/trusted provenance for an external doc attack
    bad_src = SourceRecord(
        source_id="src_bad",
        source_type="doc",
        provenance=ProvenanceLabel.SYSTEM_POLICY,  # elevation violation for external doc
    )
    object.__setattr__(bad_ep, "source_records", [bad_src])
    # Also inject an invalid trust label
    object.__setattr__(bad_ep, "expected_trust_labels", {"src_bad": "FORGED_LABEL"})
    attack_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=attack_dev_copy,
        attack_test=canonical_datasets["attack_test"],
        benign_dev=canonical_datasets["benign_dev"],
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("has no untrusted source records" in err or "invalid" in err for err in res.errors)


# ---------- 9. Duplicate canary fails ----------


def test_duplicate_canary_fails(validator, canonical_datasets):
    attack_test_copy = list(canonical_datasets["attack_test"])
    dup_canary_ep = copy.deepcopy(attack_test_copy[0])
    # Give it the canary of an episode from attack_dev
    dev_canary = canonical_datasets["attack_dev"][0].synthetic_canaries[0]
    object.__setattr__(dup_canary_ep, "synthetic_canaries", [dev_canary])
    attack_test_copy[0] = dup_canary_ep

    res = validator.validate_collections(
        attack_dev=canonical_datasets["attack_dev"],
        attack_test=attack_test_copy,
        benign_dev=canonical_datasets["benign_dev"],
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("Duplicate synthetic canary values across attack dataset" in err for err in res.errors)


# ---------- 10. Missing authorized scope fails ----------


def test_missing_authorized_scope_fails(validator, canonical_datasets):
    benign_dev_copy = list(canonical_datasets["benign_dev"])
    bad_ep = copy.deepcopy(benign_dev_copy[0])
    object.__setattr__(bad_ep, "authorized_scope", [])
    benign_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=canonical_datasets["attack_dev"],
        attack_test=canonical_datasets["attack_test"],
        benign_dev=benign_dev_copy,
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("is missing authorized_scope" in err for err in res.errors)


# ---------- 11. Invalid tool name fails ----------


def test_invalid_tool_name_fails(validator, canonical_datasets):
    benign_dev_copy = list(canonical_datasets["benign_dev"])
    bad_ep = copy.deepcopy(benign_dev_copy[0])
    bad_turn = Turn(
        turn_id=1,
        user_message="Test message",
        expected_action={"type": "tool_call", "tool": "unregistered_external_hack_tool"},
    )
    object.__setattr__(bad_ep, "turns", [bad_turn, bad_ep.turns[1], bad_ep.turns[2]])
    benign_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=canonical_datasets["attack_dev"],
        attack_test=canonical_datasets["attack_test"],
        benign_dev=benign_dev_copy,
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("uses unknown tool 'unregistered_external_hack_tool'" in err for err in res.errors)


# ---------- 12. Invalid turn count fails ----------


def test_invalid_turn_count_fails(validator, canonical_datasets):
    # Only 2 turns (fewer than 3)
    benign_dev_copy = list(canonical_datasets["benign_dev"])
    bad_ep = copy.deepcopy(benign_dev_copy[0])
    object.__setattr__(bad_ep, "turns", bad_ep.turns[:2])
    benign_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=canonical_datasets["attack_dev"],
        attack_test=canonical_datasets["attack_test"],
        benign_dev=benign_dev_copy,
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("has 2 turns; must be between 3 and 6 turns" in err for err in res.errors)


# ---------- 13. Duplicate turn ID fails ----------


def test_duplicate_turn_id_fails(validator, canonical_datasets):
    benign_dev_copy = list(canonical_datasets["benign_dev"])
    bad_ep = copy.deepcopy(benign_dev_copy[0])
    turns = list(bad_ep.turns)
    # Make turn 2 have turn_id=1
    turns[1] = Turn(
        turn_id=1,
        user_message=turns[1].user_message,
        expected_action=turns[1].expected_action,
    )
    object.__setattr__(bad_ep, "turns", turns)
    benign_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=canonical_datasets["attack_dev"],
        attack_test=canonical_datasets["attack_test"],
        benign_dev=benign_dev_copy,
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("duplicate turn_id 1" in err for err in res.errors)


# ---------- 14. Invalid expected prohibited action fails ----------


def test_invalid_expected_prohibited_action_fails(validator, canonical_datasets):
    attack_dev_copy = list(canonical_datasets["attack_dev"])
    bad_ep = copy.deepcopy(attack_dev_copy[0])
    object.__setattr__(bad_ep, "expected_prohibited_actions", ["non_existent_tool_action"])
    attack_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=attack_dev_copy,
        attack_test=canonical_datasets["attack_test"],
        benign_dev=canonical_datasets["benign_dev"],
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("prohibited action 'non_existent_tool_action' not defined in tools.yaml" in err for err in res.errors)


# ---------- 15. Benign dataset containing attack canary fails ----------


def test_benign_dataset_containing_canary_fails(validator, canonical_datasets):
    benign_dev_copy = list(canonical_datasets["benign_dev"])
    bad_ep = copy.deepcopy(benign_dev_copy[0])
    object.__setattr__(bad_ep, "synthetic_canaries", [CanarySpec(value="CANARY_INJECTED_999")])
    benign_dev_copy[0] = bad_ep

    res = validator.validate_collections(
        attack_dev=canonical_datasets["attack_dev"],
        attack_test=canonical_datasets["attack_test"],
        benign_dev=benign_dev_copy,
        benign_test=canonical_datasets["benign_test"],
    )
    assert res.passed is False
    assert any("has synthetic canaries; benign data must contain none" in err for err in res.errors)


# ---------- 16. Manifest contains expected summary fields ----------


def test_manifest_contains_expected_summary_fields():
    assert MANIFEST_FILE.is_file(), f"Manifest file missing: {MANIFEST_FILE}"
    with MANIFEST_FILE.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    expected_keys = [
        "manifest_version",
        "dataset_name",
        "validation_status",
        "total_episodes",
        "attack_count",
        "benign_count",
        "dev_count",
        "test_count",
        "attack_dev_count",
        "attack_test_count",
        "benign_dev_count",
        "benign_test_count",
        "attack_family_counts",
        "attack_template_ids_by_split",
        "benign_template_ids_by_split",
        "provenance_counts",
        "canary_count",
        "unique_canary_count",
        "tool_usage_counts",
        "validation_checks",
    ]
    for key in expected_keys:
        assert key in manifest, f"Manifest missing key: {key}"

    assert manifest["validation_status"] == "PASSED"
    assert manifest["total_episodes"] == 60
    assert manifest["attack_count"] == 30
    assert manifest["benign_count"] == 30
    assert manifest["dev_count"] == 30
    assert manifest["test_count"] == 30
    assert manifest["canary_count"] == 30
    assert manifest["unique_canary_count"] == 30
    assert manifest["validation_checks"]["count_validation"] == "PASSED"
    assert manifest["validation_checks"]["template_disjointness"] == "PASSED"
    assert manifest["validation_checks"]["canary_uniqueness"] == "PASSED"
