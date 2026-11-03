"""Tests for the end-to-end CuratorPipeline orchestrator."""

from pathlib import Path
import pytest

from traceguard.data.curator.curator_config import CuratorPipelineConfig
from traceguard.data.curator.curator_pipeline import CuratorPipeline


def test_pipeline_dry_run(tmp_path):
    cfg = CuratorPipelineConfig(
        input_dir="traceguard/data",
        output_dir=str(tmp_path / "curated"),
        dry_run=True,
    )
    pipeline = CuratorPipeline(config=cfg)
    summary = pipeline.run()

    assert summary.status == "PASSED"
    assert summary.total_episodes_ingested == 60
    assert summary.total_episodes_curated == 60
    assert summary.total_episodes_rejected == 0
    # Dry-run should not write curated files
    assert len(summary.curated_file_paths) == 0


def test_pipeline_validation_only(tmp_path):
    cfg = CuratorPipelineConfig(
        input_dir="traceguard/data",
        output_dir=str(tmp_path / "curated"),
        validation_only=True,
    )
    pipeline = CuratorPipeline(config=cfg)
    summary = pipeline.run()

    assert summary.status == "PASSED"
    assert summary.quality_gate_report["status"] == "PASSED"


def test_pipeline_single_dataset(tmp_path):
    cfg = CuratorPipelineConfig(
        input_dir="traceguard/data",
        output_dir=str(tmp_path / "curated"),
        target_datasets=["attack_dev"],
    )
    pipeline = CuratorPipeline(config=cfg)
    summary = pipeline.run()

    assert summary.status == "PASSED"
    assert summary.total_episodes_ingested == 15
    assert summary.total_episodes_curated == 15
    assert (tmp_path / "curated" / "attack_dev.jsonl").exists()
    assert (tmp_path / "curated" / "manifests" / "manifest_attack_dev.json").exists()


def test_pipeline_full_run(tmp_path):
    cfg = CuratorPipelineConfig(
        input_dir="traceguard/data",
        output_dir=str(tmp_path / "curated"),
    )
    pipeline = CuratorPipeline(config=cfg)
    summary = pipeline.run()

    assert summary.status == "PASSED"
    assert summary.total_episodes_ingested == 60
    assert summary.total_episodes_curated == 60
    assert summary.total_episodes_rejected == 0
    assert len(summary.manifest_paths) == 5
    assert len(summary.dataset_card_paths) == 5
    assert (tmp_path / "curated" / "checksums.txt").exists()
