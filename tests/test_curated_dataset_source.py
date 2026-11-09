"""The evaluator can read CuratorKIT's curated output and refuses tampered data."""

import shutil
from pathlib import Path

import pytest

from traceguard.experiments.evaluation import DATA_DIR, Evaluator


@pytest.fixture
def data_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "data"
    shutil.copytree(DATA_DIR, dst)
    return dst


def test_default_source_is_unchanged():
    assert Evaluator().dataset_source == "source"


def test_unknown_source_rejected():
    with pytest.raises(ValueError):
        Evaluator(dataset_source="nonsense")


@pytest.mark.parametrize("split", ["dev", "test"])
def test_curated_loads_same_episodes_as_source(split):
    src_a, src_b = Evaluator().load_episodes(split)
    cur_a, cur_b = Evaluator(dataset_source="curated").load_episodes(split)
    assert [e.episode_id for e in src_a] == [e.episode_id for e in cur_a]
    assert [e.episode_id for e in src_b] == [e.episode_id for e in cur_b]
    assert len(cur_a) == 15 and len(cur_b) == 15


@pytest.mark.parametrize("config", ["E0", "E2a", "E2b"])
def test_metrics_identical_for_source_and_curated(config):
    m_src, _ = Evaluator().evaluate_configuration(config, split="dev")
    m_cur, _ = Evaluator(dataset_source="curated").evaluate_configuration(config, split="dev")
    assert m_src.to_dict() == m_cur.to_dict()


def test_tampered_curated_file_fails_closed(data_copy):
    target = data_copy / "curated" / "attack_dev.jsonl"
    target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        Evaluator(data_dir=data_copy, dataset_source="curated").load_episodes("dev")


def test_missing_checksum_entry_fails_closed(data_copy):
    checks = data_copy / "curated" / "checksums.txt"
    lines = [l for l in checks.read_text(encoding="utf-8").splitlines() if "attack_dev.jsonl" not in l]
    checks.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="No checksum entry"):
        Evaluator(data_dir=data_copy, dataset_source="curated").load_episodes("dev")


def test_missing_checksums_file_fails_closed(data_copy):
    (data_copy / "curated" / "checksums.txt").unlink()
    with pytest.raises(FileNotFoundError):
        Evaluator(data_dir=data_copy, dataset_source="curated").load_episodes("dev")


def test_curated_episode_ids_must_match_source(data_copy):
    # Drop one curated episode and re-record a VALID checksum, so only the
    # source-ID comparison can catch it.
    import hashlib
    target = data_copy / "curated" / "attack_dev.jsonl"
    kept = target.read_text(encoding="utf-8").splitlines()[:-1]
    target.write_text("\n".join(kept) + "\n", encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    checks = data_copy / "curated" / "checksums.txt"
    out = []
    for l in checks.read_text(encoding="utf-8").splitlines():
        out.append(f"{digest}  attack_dev.jsonl" if l.strip().endswith("attack_dev.jsonl") else l)
    checks.write_text("\n".join(out) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="do not match source"):
        Evaluator(data_dir=data_copy, dataset_source="curated").load_episodes("dev")


def test_line_ending_differences_are_tolerated_but_content_changes_are_not(data_copy):
    target = data_copy / "curated" / "benign_dev.jsonl"
    original = target.read_bytes()

    # Same content with Windows line endings: accepted.
    target.write_bytes(original.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    Evaluator(data_dir=data_copy, dataset_source="curated").load_episodes("dev")

    # One changed character: rejected.
    target.write_bytes(original.replace(b"ep_benign_dev_01", b"ep_benign_dev_0X", 1))
    with pytest.raises(ValueError, match="SHA-256"):
        Evaluator(data_dir=data_copy, dataset_source="curated").load_episodes("dev")
