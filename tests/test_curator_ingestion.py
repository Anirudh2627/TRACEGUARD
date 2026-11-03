"""Tests for CuratorKIT dataset ingestion, error handling, and DataSample conversion."""

import json
from pathlib import Path
import pytest

from traceguard.data.curator.ingestion import (
    DatasetIngester,
    curatorkit_sample_to_episode,
    episode_to_curatorkit_sample,
)
from traceguard.data.schema import Episode, Turn


def test_ingest_valid_episode(tmp_path):
    ep = Episode(
        episode_id="ep_test_01",
        template_id="tpl_01",
        split="dev",
        initial_user_task="Read report",
        turns=[Turn(turn_id=1, user_message="Hello")],
    )
    file_path = tmp_path / "valid.jsonl"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(ep.to_json() + "\n")

    ingester = DatasetIngester()
    episodes, report = ingester.ingest_file(file_path)

    assert len(episodes) == 1
    assert episodes[0].episode_id == "ep_test_01"
    assert report.total_lines == 1
    assert report.valid_count == 1
    assert report.rejected_count == 0


def test_ingest_malformed_json_graceful(tmp_path):
    file_path = tmp_path / "corrupt.jsonl"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write('{"episode_id": "ep_good", "template_id": "t1", "split": "dev", "initial_user_task": "task", "turns": [{"turn_id": 1, "user_message": "hi"}]}\n')
        f.write('{"episode_id": "bad_json", INVALID_JSON_HERE\n')
        f.write('{"episode_id": "ep_good_2", "template_id": "t2", "split": "dev", "initial_user_task": "task2", "turns": [{"turn_id": 1, "user_message": "hi2"}]}\n')

    ingester = DatasetIngester(fail_fast=False)
    episodes, report = ingester.ingest_file(file_path)

    assert len(episodes) == 2
    assert report.total_lines == 3
    assert report.valid_count == 2
    assert report.rejected_count == 1
    assert report.malformed_json_count == 1
    assert len(report.rejected_records) == 1
    assert report.rejected_records[0]["line_number"] == 2


def test_ingest_missing_fields_graceful(tmp_path):
    file_path = tmp_path / "missing.jsonl"
    with open(file_path, "w", encoding="utf-8") as f:
        # Missing template_id and turns
        f.write('{"episode_id": "ep_incomplete", "split": "dev"}\n')

    ingester = DatasetIngester(fail_fast=False)
    episodes, report = ingester.ingest_file(file_path)

    assert len(episodes) == 0
    assert report.rejected_count == 1
    assert report.schema_violation_count == 1


def test_datasample_conversion_roundtrip():
    ep = Episode(
        episode_id="ep_roundtrip",
        template_id="tpl_rt",
        split="dev",
        initial_user_task="Summarize user notes",
        turns=[Turn(turn_id=1, user_message="Please summarize notes.")],
    )
    sample = episode_to_curatorkit_sample(ep)
    assert sample.id == "ep_roundtrip"
    assert sample.instruction == "Summarize user notes"
    assert sample.task_type == "attack"

    reconstructed = curatorkit_sample_to_episode(sample)
    assert reconstructed.episode_id == ep.episode_id
    assert reconstructed.template_id == ep.template_id
    assert reconstructed.initial_user_task == ep.initial_user_task


def test_ingest_real_datasets():
    ingester = DatasetIngester(fail_fast=True)
    dataset_map = {
        "attack_dev": "episodes_attack_dev.jsonl",
        "attack_test": "episodes_attack_test.jsonl",
        "benign_dev": "episodes_benign_dev.jsonl",
        "benign_test": "episodes_benign_test.jsonl",
    }
    episodes_dict, reports_dict = ingester.ingest_collection("traceguard/data", dataset_map)

    for name in dataset_map:
        assert len(episodes_dict[name]) == 15, f"{name} should contain 15 episodes"
        assert reports_dict[name].rejected_count == 0, f"{name} should have 0 rejections"
