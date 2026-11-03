"""Tests for TraceGuard Attack Dataset (Module 3).

Validates:
- Exactly 15 dev and 15 test attack episodes (total 30).
- Template-disjoint partition between dev and test (DEV tmpls ∩ TEST tmpls = ∅).
- Full representation of all three threat families in both splits.
- 3 to 6 conversational turns per episode.
- Complete Module 1 schema compliance, roundtrip serialization, and valid provenance.
- Unique episode IDs, unique canaries, valid tools in prohibited actions.
- Human reviewability and valid JSON lines.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
import yaml

from traceguard.data.schema import (
    ALLOWED_SPLITS,
    PROVENANCE_LABELS,
    Episode,
    ProvenanceLabel,
    validate_provenance_label,
)
from traceguard.data.taxonomy import (
    AttackFamilyId,
    get_attack_families,
    get_taxonomy_catalog,
    normalize_family_id,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "traceguard" / "data"
CONFIGS_DIR = Path(__file__).resolve().parent.parent / "traceguard" / "configs"
DEV_FILE = DATA_DIR / "episodes_attack_dev.jsonl"
TEST_FILE = DATA_DIR / "episodes_attack_test.jsonl"
TOOLS_FILE = CONFIGS_DIR / "tools.yaml"


@pytest.fixture(scope="module")
def tools_registry() -> set[str]:
    """Load authorized tool names from tools.yaml."""
    assert TOOLS_FILE.exists(), f"Missing tools config at {TOOLS_FILE}"
    with TOOLS_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return set(data.get("tools", {}).keys())


@pytest.fixture(scope="module")
def raw_dev_lines() -> list[str]:
    assert DEV_FILE.exists(), f"Dev dataset missing: {DEV_FILE}"
    with DEV_FILE.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


@pytest.fixture(scope="module")
def raw_test_lines() -> list[str]:
    assert TEST_FILE.exists(), f"Test dataset missing: {TEST_FILE}"
    with TEST_FILE.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


@pytest.fixture(scope="module")
def dev_episodes(raw_dev_lines) -> list[Episode]:
    return [Episode.from_json(line) for line in raw_dev_lines]


@pytest.fixture(scope="module")
def test_episodes(raw_test_lines) -> list[Episode]:
    return [Episode.from_json(line) for line in raw_test_lines]


# ---------- 1. File existence and JSONL validity ----------


def test_dataset_files_exist():
    assert DEV_FILE.is_file(), f"{DEV_FILE} must exist"
    assert TEST_FILE.is_file(), f"{TEST_FILE} must exist"


def test_jsonl_validity(raw_dev_lines, raw_test_lines):
    for line in raw_dev_lines:
        parsed = json.loads(line)
        assert isinstance(parsed, dict)
    for line in raw_test_lines:
        parsed = json.loads(line)
        assert isinstance(parsed, dict)


# ---------- 2. Episode count: 15 dev, 15 test, 30 total ----------


def test_episode_counts(dev_episodes, test_episodes):
    assert len(dev_episodes) == 15, f"Expected 15 dev episodes, got {len(dev_episodes)}"
    assert len(test_episodes) == 15, f"Expected 15 test episodes, got {len(test_episodes)}"
    assert len(dev_episodes) + len(test_episodes) == 30


# ---------- 3. Template validity and strict template-disjoint split ----------


def test_all_template_ids_exist_in_taxonomy(dev_episodes, test_episodes):
    catalog = get_taxonomy_catalog()
    all_episodes = dev_episodes + test_episodes
    for ep in all_episodes:
        assert (
            ep.template_id in catalog
        ), f"Episode {ep.episode_id} uses unknown template_id {ep.template_id!r}"


def test_template_disjoint_split(dev_episodes, test_episodes):
    dev_templates = {ep.template_id for ep in dev_episodes}
    test_templates = {ep.template_id for ep in test_episodes}

    intersection = dev_templates.intersection(test_templates)
    assert (
        dev_templates.isdisjoint(test_templates)
    ), f"Template-disjoint rule violated! Overlapping templates: {intersection}"
    assert len(intersection) == 0


# ---------- 4. Family coverage across both splits ----------


def test_all_three_families_in_both_splits(dev_episodes, test_episodes):
    dev_families = {normalize_family_id(ep.attack_family) for ep in dev_episodes if ep.attack_family}
    test_families = {normalize_family_id(ep.attack_family) for ep in test_episodes if ep.attack_family}

    expected = {
        AttackFamilyId.FAMILY_A,
        AttackFamilyId.FAMILY_B,
        AttackFamilyId.FAMILY_C,
    }

    assert dev_families == expected, f"Dev split missing families: {expected - dev_families}"
    assert test_families == expected, f"Test split missing families: {expected - test_families}"


def test_template_family_alignment(dev_episodes, test_episodes):
    catalog = get_taxonomy_catalog()
    for ep in dev_episodes + test_episodes:
        expected_family = catalog[ep.template_id].family_id
        actual_family = normalize_family_id(ep.attack_family)
        assert (
            actual_family == expected_family
        ), f"Episode {ep.episode_id} family {actual_family} mismatch with template {expected_family}"


# ---------- 5. Turn count constraint: 3 to 6 turns ----------


def test_turn_counts_between_three_and_six(dev_episodes, test_episodes):
    for ep in dev_episodes + test_episodes:
        turn_count = len(ep.turns)
        assert (
            3 <= turn_count <= 6
        ), f"Episode {ep.episode_id} has {turn_count} turns; must be in [3, 6]"
        for i, turn in enumerate(ep.turns, 1):
            assert turn.turn_id == i, f"Episode {ep.episode_id} turn {turn.turn_id} != expected {i}"
            assert isinstance(turn.user_message, str) and turn.user_message.strip()


# ---------- 6. Episode ID and Canary Uniqueness ----------


def test_unique_episode_ids(dev_episodes, test_episodes):
    all_episodes = dev_episodes + test_episodes
    ids = [ep.episode_id for ep in all_episodes]
    assert len(ids) == len(set(ids)), f"Duplicate episode IDs: {[x for x in ids if ids.count(x) > 1]}"


def test_synthetic_canaries_unique_and_present(dev_episodes, test_episodes):
    all_episodes = dev_episodes + test_episodes
    all_canaries: list[str] = []
    for ep in all_episodes:
        assert len(ep.synthetic_canaries) >= 1, f"Episode {ep.episode_id} has no synthetic canaries"
        for canary in ep.synthetic_canaries:
            val = canary.value
            assert val.startswith("TRACEGUARD_CANARY_")
            assert len(val) >= 10
            all_canaries.append(val)

    assert len(all_canaries) == len(set(all_canaries)), "Duplicate synthetic canaries detected!"


# ---------- 7. Provenance integrity ----------


def test_provenance_labels_valid(dev_episodes, test_episodes):
    for ep in dev_episodes + test_episodes:
        for record in ep.source_records:
            assert isinstance(record.provenance, ProvenanceLabel)
            assert record.provenance.value in PROVENANCE_LABELS

        for sid, label in ep.expected_trust_labels.items():
            assert label in PROVENANCE_LABELS
            validate_provenance_label(label)


def test_family_expected_provenance_match(dev_episodes, test_episodes):
    catalog = get_taxonomy_catalog()
    for ep in dev_episodes + test_episodes:
        expected_prov = catalog[ep.template_id].expected_provenance
        # Main untrusted source record should match template expectation
        primary_sources = [
            s for s in ep.source_records if s.provenance in (
                ProvenanceLabel.UNTRUSTED_EXTERNAL,
                ProvenanceLabel.DERIVED_UNTRUSTED,
            )
        ]
        assert primary_sources, f"Episode {ep.episode_id} has no untrusted sources"
        assert any(
            s.provenance == expected_prov for s in primary_sources
        ), f"Episode {ep.episode_id} missing source with expected provenance {expected_prov}"


# ---------- 8. Schema completeness and roundtrip ----------


def test_required_fields_present_in_serialized_json(raw_dev_lines, raw_test_lines):
    required = [
        "episode_id",
        "template_id",
        "split",
        "attack_family",
        "initial_user_task",
        "turns",
        "source_records",
        "expected_trust_labels",
        "expected_safe_behavior",
        "authorized_scope",
        "synthetic_canaries",
        "expected_final_fields",
        "expected_prohibited_actions",
    ]
    for line in raw_dev_lines + raw_test_lines:
        data = json.loads(line)
        for req in required:
            assert req in data, f"Missing required key {req!r} in {data.get('episode_id')}"
            assert data[req], f"Empty required field {req!r} in {data.get('episode_id')}"


def test_episode_serialization_roundtrip(dev_episodes, test_episodes):
    for ep in dev_episodes + test_episodes:
        json_repr = ep.to_json()
        restored = Episode.from_json(json_repr)
        assert restored.episode_id == ep.episode_id
        assert restored.template_id == ep.template_id
        assert restored.split == ep.split
        assert restored.attack_family == ep.attack_family
        assert len(restored.turns) == len(ep.turns)
        assert len(restored.source_records) == len(ep.source_records)
        assert restored.expected_safe_behavior == ep.expected_safe_behavior
        assert restored.expected_final_fields == ep.expected_final_fields
        assert restored.expected_prohibited_actions == ep.expected_prohibited_actions


# ---------- 9. Prohibited actions and authorized scopes ----------


def test_prohibited_actions_are_valid_tools(dev_episodes, test_episodes, tools_registry):
    for ep in dev_episodes + test_episodes:
        for action in ep.expected_prohibited_actions:
            assert (
                action in tools_registry
            ), f"Episode {ep.episode_id} prohibited action {action!r} not in tools.yaml"


def test_expected_final_fields_are_structured(dev_episodes, test_episodes):
    for ep in dev_episodes + test_episodes:
        fields = ep.expected_final_fields
        assert isinstance(fields, dict)
        assert len(fields) >= 2, f"Episode {ep.episode_id} expected_final_fields has fewer than 2 keys"
