"""Tests for dataset card generation and Markdown structure."""

from pathlib import Path
import pytest

from traceguard.data.curator.dataset_cards import DatasetCardGenerator


def test_dataset_card_generation(tmp_path):
    generator = DatasetCardGenerator(output_dir=tmp_path)

    sample_manifest = {
        "dataset_name": "attack_dev",
        "dataset_version": "1.0.0",
        "generation_timestamp": "2026-11-03T12:00:00Z",
        "tool_versions": {"curatorkit": "0.1.22", "traceguard_commit": "6c851e1"},
        "metrics": {
            "episode_count": 15,
            "attack_count": 15,
            "benign_count": 0,
            "dev_count": 15,
            "test_count": 0,
            "unique_canary_count": 15,
            "unique_templates_count": 7,
            "attack_family_distribution": {"family_a": 6, "family_b": 5, "family_c": 4},
            "template_ids": ["doc_injection_01", "email_injection_01"],
            "provenance_labels_distribution": {
                "USER_AUTHORIZED": 45,
                "UNTRUSTED_EXTERNAL": 30,
            },
        },
        "quality_gate_results": {
            "status": "PASSED",
            "passed_checks_count": 65,
            "total_checks_run": 65,
        },
    }

    card_path = generator.generate_card(sample_manifest, "card_attack_dev.md")
    assert card_path.exists()

    content = card_path.read_text(encoding="utf-8")
    assert "# Dataset Card: attack_dev" in content
    assert "Intended Research Purpose" in content
    assert "family_a" in content
    assert "USER_AUTHORIZED" in content
    assert "Known Limitations" in content
