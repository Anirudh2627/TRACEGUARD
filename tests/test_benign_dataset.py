"""Tests for TraceGuard Matched Benign Dataset (Module 4).

Validates:
- Exactly 15 dev and 15 test benign episodes (total 30).
- Every episode has is_attack == False and attack_family == 'benign'.
- No synthetic attack canaries or prohibited actions.
- Realistic 3 to 6 conversational turns per episode with sequential IDs.
- Complete Module 1 Episode schema conformity and lossless roundtrip serialization.
- Valid provenance labels across all source records and trust labels.
- Clear and sensible authorized scopes for every episode.
- Sensitive tools (draft_email, send_email, read_private_file) are only used within authorized scopes.
- No attack template IDs from the attack taxonomy catalog are used.
- Dataset generation is deterministic and reproducible.
- Balanced coverage across the tool and task space.
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
from traceguard.data.taxonomy import get_taxonomy_catalog

DATA_DIR = Path(__file__).resolve().parent.parent / "traceguard" / "data"
CONFIGS_DIR = Path(__file__).resolve().parent.parent / "traceguard" / "configs"
BENIGN_DEV_FILE = DATA_DIR / "episodes_benign_dev.jsonl"
BENIGN_TEST_FILE = DATA_DIR / "episodes_benign_test.jsonl"
TOOLS_FILE = CONFIGS_DIR / "tools.yaml"


@pytest.fixture(scope="module")
def tools_registry() -> set[str]:
    """Load authorized tool names from tools.yaml."""
    assert TOOLS_FILE.exists(), f"Missing tools config at {TOOLS_FILE}"
    with TOOLS_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return set(data.get("tools", {}).keys())


@pytest.fixture(scope="module")
def raw_benign_dev_lines() -> list[str]:
    assert BENIGN_DEV_FILE.exists(), f"Benign dev dataset missing: {BENIGN_DEV_FILE}"
    with BENIGN_DEV_FILE.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


@pytest.fixture(scope="module")
def raw_benign_test_lines() -> list[str]:
    assert BENIGN_TEST_FILE.exists(), f"Benign test dataset missing: {BENIGN_TEST_FILE}"
    with BENIGN_TEST_FILE.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


@pytest.fixture(scope="module")
def benign_dev_episodes(raw_benign_dev_lines) -> list[Episode]:
    return [Episode.from_json(line) for line in raw_benign_dev_lines]


@pytest.fixture(scope="module")
def benign_test_episodes(raw_benign_test_lines) -> list[Episode]:
    return [Episode.from_json(line) for line in raw_benign_test_lines]


@pytest.fixture(scope="module")
def all_benign_episodes(benign_dev_episodes, benign_test_episodes) -> list[Episode]:
    return benign_dev_episodes + benign_test_episodes


# ---------- 1. File existence and JSONL validity ----------


def test_benign_files_exist():
    assert BENIGN_DEV_FILE.is_file(), f"{BENIGN_DEV_FILE} must exist"
    assert BENIGN_TEST_FILE.is_file(), f"{BENIGN_TEST_FILE} must exist"


def test_benign_jsonl_validity(raw_benign_dev_lines, raw_benign_test_lines):
    for line in raw_benign_dev_lines:
        parsed = json.loads(line)
        assert isinstance(parsed, dict)
    for line in raw_benign_test_lines:
        parsed = json.loads(line)
        assert isinstance(parsed, dict)


# ---------- 2. Episode counts: 15 dev, 15 test, 30 total ----------


def test_benign_episode_counts(benign_dev_episodes, benign_test_episodes):
    assert len(benign_dev_episodes) == 15, f"Expected 15 dev episodes, got {len(benign_dev_episodes)}"
    assert len(benign_test_episodes) == 15, f"Expected 15 test episodes, got {len(benign_test_episodes)}"
    assert len(benign_dev_episodes) + len(benign_test_episodes) == 30


# ---------- 3. Episode ID uniqueness ----------


def test_all_benign_episode_ids_unique(all_benign_episodes):
    ids = [ep.episode_id for ep in all_benign_episodes]
    assert len(ids) == len(set(ids)), f"Duplicate episode IDs: {[x for x in ids if ids.count(x) > 1]}"
    for ep in all_benign_episodes:
        assert ep.episode_id.startswith("ep_benign_")


# ---------- 4. is_attack == False and benign representation ----------


def test_is_attack_is_false(all_benign_episodes):
    for ep in all_benign_episodes:
        assert ep.is_attack is False, f"Episode {ep.episode_id} must have is_attack=False"
        assert ep.attack_family == "benign", f"Episode {ep.episode_id} attack_family must be 'benign'"


def test_no_synthetic_attack_canaries(all_benign_episodes):
    for ep in all_benign_episodes:
        assert (
            len(ep.synthetic_canaries) == 0
        ), f"Episode {ep.episode_id} has synthetic canaries, but benign data must have none"


def test_no_prohibited_actions(all_benign_episodes):
    for ep in all_benign_episodes:
        assert (
            len(ep.expected_prohibited_actions) == 0
        ), f"Episode {ep.episode_id} has prohibited actions, but benign tasks have none"


# ---------- 5. Turn count constraint: 3 to 6 turns ----------


def test_benign_turn_counts_between_three_and_six(all_benign_episodes):
    for ep in all_benign_episodes:
        turn_count = len(ep.turns)
        assert (
            3 <= turn_count <= 6
        ), f"Episode {ep.episode_id} has {turn_count} turns; must be in [3, 6]"
        for i, turn in enumerate(ep.turns, 1):
            assert turn.turn_id == i, f"Episode {ep.episode_id} turn {turn.turn_id} != expected {i}"
            assert isinstance(turn.user_message, str) and turn.user_message.strip()


# ---------- 6. Provenance validity ----------


def test_benign_provenance_labels_valid(all_benign_episodes):
    for ep in all_benign_episodes:
        for record in ep.source_records:
            assert isinstance(record.provenance, ProvenanceLabel)
            assert record.provenance.value in PROVENANCE_LABELS
            validate_provenance_label(record.provenance)

        for sid, label in ep.expected_trust_labels.items():
            assert label in PROVENANCE_LABELS
            validate_provenance_label(label)


# ---------- 7. Authorized scopes and sensitive actions ----------


def test_authorized_scopes_present_and_sensible(all_benign_episodes):
    for ep in all_benign_episodes:
        assert ep.authorized_scope, f"Episode {ep.episode_id} must have a non-empty authorized_scope"
        assert all(isinstance(s, str) and s.strip() for s in ep.authorized_scope)


def test_sensitive_tools_strictly_authorized(all_benign_episodes):
    """Verify that when sensitive tools are called, they align with authorized scope."""
    sensitive_tools = {"draft_email", "send_email", "read_private_file"}
    sensitive_calls_found = 0

    for ep in all_benign_episodes:
        scope_str = " ".join(ep.authorized_scope)
        for turn in ep.turns:
            act = turn.expected_action or {}
            tool = act.get("tool")
            if tool in sensitive_tools:
                sensitive_calls_found += 1
                args = act.get("arguments", {})
                if tool in ("draft_email", "send_email"):
                    recipient = args.get("to")
                    assert recipient, f"Episode {ep.episode_id} {tool} missing recipient"
                    assert (
                        recipient in scope_str or f"email_recipient:{recipient}" in ep.authorized_scope
                    ), f"Episode {ep.episode_id} {tool} to {recipient!r} not in authorized_scope {ep.authorized_scope}"
                elif tool == "read_private_file":
                    path = args.get("path")
                    assert path, f"Episode {ep.episode_id} read_private_file missing path"
                    assert (
                        path in scope_str or f"private_files:{path}" in ep.authorized_scope
                    ), f"Episode {ep.episode_id} read_private_file on {path!r} not in authorized_scope {ep.authorized_scope}"

    # Ensure sensitive tools are actually exercised legitimately across the dataset
    assert sensitive_calls_found >= 5, f"Expected at least 5 authorized sensitive tool calls, found {sensitive_calls_found}"


def test_all_expected_tools_defined_in_registry(all_benign_episodes, tools_registry):
    for ep in all_benign_episodes:
        for turn in ep.turns:
            act = turn.expected_action or {}
            tool = act.get("tool")
            if tool:
                assert (
                    tool in tools_registry
                ), f"Episode {ep.episode_id} uses unknown tool {tool!r} not in tools.yaml"


# ---------- 8. Template separation from attack catalog ----------


def test_no_attack_template_used_in_benign_episodes(all_benign_episodes):
    attack_catalog = get_taxonomy_catalog()
    for ep in all_benign_episodes:
        assert (
            ep.template_id not in attack_catalog
        ), f"Benign episode {ep.episode_id} accidentally uses attack template_id {ep.template_id!r}"


# ---------- 9. Schema completeness and lossless roundtrip ----------


def test_benign_required_fields_present_in_serialized_json(raw_benign_dev_lines, raw_benign_test_lines):
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
        "expected_final_fields",
    ]
    for line in raw_benign_dev_lines + raw_benign_test_lines:
        data = json.loads(line)
        for req in required:
            assert req in data, f"Missing required key {req!r} in {data.get('episode_id')}"
            assert data[req], f"Empty required field {req!r} in {data.get('episode_id')}"


def test_benign_episode_serialization_roundtrip(all_benign_episodes):
    for ep in all_benign_episodes:
        json_repr = ep.to_json()
        restored = Episode.from_json(json_repr)
        assert restored.episode_id == ep.episode_id
        assert restored.template_id == ep.template_id
        assert restored.split == ep.split
        assert restored.is_attack is False
        assert restored.attack_family == "benign"
        assert len(restored.turns) == len(ep.turns)
        assert len(restored.source_records) == len(ep.source_records)
        assert restored.expected_safe_behavior == ep.expected_safe_behavior
        assert restored.expected_final_fields == ep.expected_final_fields
        assert restored.expected_prohibited_actions == []
        assert restored.synthetic_canaries == []


def test_expected_final_fields_are_structured(all_benign_episodes):
    for ep in all_benign_episodes:
        fields = ep.expected_final_fields
        assert isinstance(fields, dict)
        assert len(fields) >= 2, f"Episode {ep.episode_id} expected_final_fields has fewer than 2 keys"


# ---------- 10. Dataset generation determinism ----------


def test_generation_script_is_deterministic():
    from scripts.generate_benign_dataset import _build_benign_dev_episodes, _build_benign_test_episodes

    dev_1 = [ep.to_dict() for ep in _build_benign_dev_episodes()]
    dev_2 = [ep.to_dict() for ep in _build_benign_dev_episodes()]
    assert dev_1 == dev_2, "Dev generation is non-deterministic"

    test_1 = [ep.to_dict() for ep in _build_benign_test_episodes()]
    test_2 = [ep.to_dict() for ep in _build_benign_test_episodes()]
    assert test_1 == test_2, "Test generation is non-deterministic"


# ---------- 11. Tool distribution diversity ----------


def test_tool_distribution_diversity(all_benign_episodes):
    tools_observed: set[str] = set()
    action_types: set[str] = set()

    for ep in all_benign_episodes:
        for turn in ep.turns:
            act = turn.expected_action or {}
            act_type = act.get("type")
            if act_type:
                action_types.add(act_type)
            tool = act.get("tool")
            if tool:
                tools_observed.add(tool)

    # Verify action types: tool_call, clarify, final
    assert "tool_call" in action_types
    assert "clarify" in action_types
    assert "final" in action_types

    # Verify comprehensive coverage across tools
    expected_tools = {
        "search_documents",
        "read_document",
        "search_emails",
        "read_email",
        "retrieve_notes",
        "save_note",
        "draft_email",
        "send_email",
        "read_private_file",
    }
    assert tools_observed == expected_tools, f"Missing expected tools: {expected_tools - tools_observed}"
