"""Tests for multi-level deduplication and near-duplicate similarity detection."""

import pytest

from traceguard.data.curator.deduplication import EpisodeDeduplicator
from traceguard.data.curator.ingestion import DatasetIngester
from traceguard.data.schema import Episode, Turn


def test_exact_id_duplicate_rejection():
    ep1 = Episode(
        episode_id="ep_dup_01",
        template_id="t1",
        split="dev",
        initial_user_task="Task A",
        turns=[Turn(turn_id=1, user_message="Message A")],
    )
    ep2 = Episode(
        episode_id="ep_dup_01",  # Same ID
        template_id="t2",
        split="dev",
        initial_user_task="Task B",
        turns=[Turn(turn_id=1, user_message="Message B")],
    )

    dedup = EpisodeDeduplicator()
    surviving, report = dedup.analyze([ep1, ep2], dataset_name="dup_test")

    assert len(surviving) == 1
    assert report.exact_id_duplicates_count == 1
    assert len(report.findings) == 1
    assert report.findings[0].level == "exact_id"
    assert report.findings[0].action_taken == "rejected_duplicate"


def test_exact_record_duplicate_rejection():
    ep1 = Episode(
        episode_id="ep_first",
        template_id="t1",
        split="dev",
        initial_user_task="Task A",
        turns=[Turn(turn_id=1, user_message="Message A")],
    )
    # Identical record except ID is different
    # If content is identical, let's test exact record content matching
    raw = ep1.to_dict()
    ep2 = Episode.from_dict(raw)

    dedup = EpisodeDeduplicator()
    surviving, report = dedup.analyze([ep1, ep2], dataset_name="rec_dup_test")

    assert len(surviving) == 1
    assert (report.exact_id_duplicates_count + report.exact_record_duplicates_count) == 1


def test_near_duplicate_similarity_flagged_without_deletion():
    ep1 = Episode(
        episode_id="ep_near_01",
        template_id="t1",
        split="dev",
        initial_user_task="Please summarize the quarterly revenue and expenses report for corporate finance",
        turns=[Turn(turn_id=1, user_message="Find all quarterly revenue figures and EBITDA")],
    )
    # Very similar wording
    ep2 = Episode(
        episode_id="ep_near_02",
        template_id="t2",
        split="dev",
        initial_user_task="Please summarize the quarterly revenue and expenses report for corporate finance team",
        turns=[Turn(turn_id=1, user_message="Find all quarterly revenue figures and EBITDA metrics")],
    )

    dedup = EpisodeDeduplicator(similarity_threshold=0.75)
    surviving, report = dedup.analyze([ep1, ep2], dataset_name="near_test")

    # Near duplicates must be flagged for warning but NOT deleted
    assert len(surviving) == 2
    assert report.near_duplicate_warnings_count >= 1
    assert report.findings[0].level == "near_duplicate"
    assert report.findings[0].action_taken == "flagged_warning_preserved"


def test_real_dataset_has_zero_exact_duplicates():
    ingester = DatasetIngester()
    dataset_map = {
        "attack_dev": "episodes_attack_dev.jsonl",
        "attack_test": "episodes_attack_test.jsonl",
        "benign_dev": "episodes_benign_dev.jsonl",
        "benign_test": "episodes_benign_test.jsonl",
    }
    episodes_dict, _ = ingester.ingest_collection("traceguard/data", dataset_map)

    dedup = EpisodeDeduplicator()
    all_episodes = []
    for eps in episodes_dict.values():
        all_episodes.extend(eps)

    surviving, report = dedup.analyze(all_episodes, dataset_name="full_collection")
    assert len(surviving) == 60
    assert report.exact_id_duplicates_count == 0
    assert report.exact_record_duplicates_count == 0
