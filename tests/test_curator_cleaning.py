"""Tests for CuratorKIT episode cleaning, whitespace normalization, and provenance preservation."""

import pytest

from traceguard.data.curator.cleaning import EpisodeCleaner
from traceguard.data.schema import Episode, ProvenanceLabel, SourceRecord, Turn


def test_clean_episode_whitespace():
    ep = Episode(
        episode_id="ep_ws_01",
        template_id="tpl_ws",
        split="dev",
        initial_user_task="   Summarize document   ",
        turns=[Turn(turn_id=1, user_message="  Read this please.  \n")],
    )

    cleaner = EpisodeCleaner(normalize_whitespace=True)
    cleaned, transforms = cleaner.clean_episode(ep)

    assert cleaned.initial_user_task == "Summarize document"
    assert cleaned.turns[0].user_message == "Read this please."
    assert "normalize_initial_user_task_whitespace" in transforms
    assert "normalize_turn_whitespace" in transforms
    assert cleaned.metadata.get("curated_clean") is True


def test_clean_dataset_audit_report():
    ep1 = Episode(
        episode_id="ep1",
        template_id="t1",
        split="dev",
        initial_user_task=" Task with spaces  ",
        turns=[Turn(turn_id=1, user_message="Hello")],
    )
    ep2 = Episode(
        episode_id="ep2",
        template_id="t2",
        split="dev",
        initial_user_task="Clean task",
        turns=[Turn(turn_id=1, user_message="Hello")],
    )

    cleaner = EpisodeCleaner(normalize_whitespace=True)
    cleaned_list, report = cleaner.clean_dataset([ep1, ep2], dataset_name="test_ds")

    assert report.episodes_examined == 2
    assert report.episodes_modified == 1
    assert "normalize_initial_user_task_whitespace" in report.transformations_applied
    assert len(cleaned_list) == 2


def test_clean_preserves_provenance_labels():
    ep = Episode(
        episode_id="ep_prov",
        template_id="tpl_prov",
        split="dev",
        initial_user_task="Task",
        turns=[
            Turn(
                turn_id=1,
                user_message="Msg",
                source_records=[
                    SourceRecord(
                        source_id="src_1",
                        source_type="email",
                        provenance=ProvenanceLabel.UNTRUSTED_EXTERNAL,
                        content="Injected text",
                    )
                ],
            )
        ],
        source_records=[
            SourceRecord(
                source_id="src_sys",
                source_type="policy",
                provenance=ProvenanceLabel.SYSTEM_POLICY,
                content="System policy",
            )
        ],
    )

    cleaner = EpisodeCleaner()
    cleaned, _ = cleaner.clean_episode(ep)

    assert cleaned.turns[0].source_records[0].provenance == ProvenanceLabel.UNTRUSTED_EXTERNAL
    assert cleaned.source_records[0].provenance == ProvenanceLabel.SYSTEM_POLICY
