"""Tests for CuratorKIT provenance manifest generation and SHA-256 auditing."""

import json
from pathlib import Path
import pytest

from traceguard.data.curator.manifests import ManifestBuilder, compute_sha256
from traceguard.data.schema import Episode, Turn


def test_manifest_builder_structure(tmp_path):
    builder = ManifestBuilder(output_dir=tmp_path / "manifests")

    ep = Episode(
        episode_id="ep_man_01",
        template_id="tpl_01",
        split="dev",
        initial_user_task="Task",
        turns=[Turn(turn_id=1, user_message="Message")],
    )

    src_file = tmp_path / "src.jsonl"
    with open(src_file, "w", encoding="utf-8") as f:
        f.write(ep.to_json() + "\n")

    cur_file = tmp_path / "cur.jsonl"
    with open(cur_file, "w", encoding="utf-8") as f:
        f.write(ep.to_json() + "\n")

    manifest = builder.build_dataset_manifest(
        dataset_name="test_manifest_ds",
        episodes=[ep],
        source_path=src_file,
        curated_path=cur_file,
    )

    assert manifest["dataset_name"] == "test_manifest_ds"
    assert "metrics" in manifest
    assert manifest["metrics"]["episode_count"] == 1
    assert "tool_versions" in manifest
    assert "curatorkit" in manifest["tool_versions"]
    assert "source_files" in manifest
    assert manifest["source_files"][0]["sha256"] != "NOT_FOUND"

    out_path = builder.write_manifest(manifest, "test_man.json")
    assert out_path.exists()

    with open(out_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["dataset_name"] == "test_manifest_ds"


def test_checksums_writing(tmp_path):
    builder = ManifestBuilder(output_dir=tmp_path)
    f1 = tmp_path / "file1.txt"
    f2 = tmp_path / "file2.txt"

    f1.write_text("Hello World", encoding="utf-8")
    f2.write_text("TraceGuard 2026", encoding="utf-8")

    out_checksums = tmp_path / "checksums.txt"
    builder.write_checksums([f1, f2], out_checksums)

    assert out_checksums.exists()
    lines = out_checksums.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert "file1.txt" in lines[0] or "file1.txt" in lines[1]
    assert "file2.txt" in lines[0] or "file2.txt" in lines[1]
