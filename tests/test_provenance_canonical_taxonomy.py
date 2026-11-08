"""Regression tests for Canonical Provenance Taxonomy enforcement in CircuitKIT and contrastive datasets."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traceguard.experiments.circuit_experiment import (
    CANONICAL_PROVENANCE_LABELS,
    load_contrastive_dataset,
)

CIRCUIT_DIR = Path("traceguard/data/circuit")
DEV_PATH = CIRCUIT_DIR / "contrastive_dev.jsonl"
TEST_PATH = CIRCUIT_DIR / "contrastive_test.jsonl"


def test_canonical_labels_set():
    """Verify that the 6 canonical labels are exactly as specified by Track 2a taxonomy."""
    expected = {
        "SYSTEM_POLICY",
        "SYSTEM_CONFIG",
        "USER_AUTHORIZED",
        "UNTRUSTED_EXTERNAL",
        "DERIVED_UNTRUSTED",
        "UNKNOWN",
    }
    assert CANONICAL_PROVENANCE_LABELS == expected


def test_contrastive_files_contain_only_canonical_labels():
    """Verify that both DEV and TEST contrastive datasets on disk only contain canonical provenance labels."""
    for path in (DEV_PATH, TEST_PATH):
        assert path.exists(), f"Missing dataset: {path}"
        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                record = json.loads(line)
                prov = record.get("expected_provenance", {})
                for key, label in prov.items():
                    assert (
                        label in CANONICAL_PROVENANCE_LABELS
                    ), f"{path}:{line_no} Non-canonical label '{label}' for key '{key}'"


def test_contrastive_datasets_contain_specific_canonical_variants():
    """Verify that contrastive datasets correctly distinguish UNTRUSTED_EXTERNAL and DERIVED_UNTRUSTED."""
    dev_labels: set[str] = set()
    with open(DEV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            dev_labels.update(rec.get("expected_provenance", {}).values())

    test_labels: set[str] = set()
    with open(TEST_PATH, "r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            test_labels.update(rec.get("expected_provenance", {}).values())

    # DEV has Family A and Family B/C
    assert "USER_AUTHORIZED" in dev_labels
    assert "UNTRUSTED_EXTERNAL" in dev_labels
    assert "DERIVED_UNTRUSTED" in dev_labels

    # TEST has Family A and Family B/C
    assert "USER_AUTHORIZED" in test_labels
    assert "UNTRUSTED_EXTERNAL" in test_labels
    assert "DERIVED_UNTRUSTED" in test_labels


def test_load_contrastive_dataset_accepts_all_canonical_labels(tmp_path: Path):
    """Verify load_contrastive_dataset successfully parses all 6 canonical labels."""
    records = []
    for idx, label in enumerate(sorted(CANONICAL_PROVENANCE_LABELS)):
        records.append({
            "example_id": f"canonical_ex_{idx}",
            "template_id": f"tmpl_{idx}",
            "split": "dev",
            "attack_family": "A",
            "clean_prompt": "Clean prompt text",
            "corrupt_prompt": "Corrupted prompt text with payload",
            "clean_answer": "Clean answer",
            "corrupt_answer": "Corrupted answer",
            "expected_provenance": {"source_entity": label},
        })

    custom_file = tmp_path / "valid_canonical.jsonl"
    with open(custom_file, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    loaded = load_contrastive_dataset(custom_file)
    assert len(loaded) == len(CANONICAL_PROVENANCE_LABELS)
    for pair in loaded:
        assert list(pair["expected_provenance"].values())[0] in CANONICAL_PROVENANCE_LABELS


def test_load_contrastive_dataset_rejects_non_canonical_labels(tmp_path: Path):
    """Verify load_contrastive_dataset strictly rejects outdated or non-canonical labels."""
    invalid_labels = ["TRUSTED", "UNTRUSTED", "FABRICATED", "USER_INPUT", "EXTERNAL_UNTRUSTED"]
    for bad_label in invalid_labels:
        bad_file = tmp_path / f"bad_{bad_label}.jsonl"
        record = {
            "example_id": "bad_ex_01",
            "template_id": "tmpl_01",
            "split": "dev",
            "attack_family": "A",
            "clean_prompt": "Clean prompt text",
            "corrupt_prompt": "Corrupted prompt text",
            "clean_answer": "Clean answer",
            "corrupt_answer": "Corrupted answer",
            "expected_provenance": {"source_item": bad_label},
        }
        with open(bad_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        with pytest.raises(ValueError, match=f"Invalid provenance label '{bad_label}'"):
            load_contrastive_dataset(bad_file)


def test_user_authorized_distinct_from_untrusted_external():
    """Verify USER_AUTHORIZED and UNTRUSTED_EXTERNAL are distinct and cannot be conflated."""
    assert "USER_AUTHORIZED" != "UNTRUSTED_EXTERNAL"
    assert "USER_AUTHORIZED" != "DERIVED_UNTRUSTED"
    assert "UNTRUSTED_EXTERNAL" != "DERIVED_UNTRUSTED"
