"""Comprehensive regression and integration tests for Member 2 CircuitKIT fixes.

Covers:
1. TEST evaluation routing and DEV/TEST split separation.
2. Model ID and exact revision propagation to model-loading operations.
3. Hardware-aware precision resolution (Ampere BF16, T4 FP16, CPU FP32, error guards).
4. CLI overrides, artifact integrity, and anti-fabrication enforcement.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest
import torch

from traceguard.experiments.circuit_config import (
    DEFAULT_MODEL_NAME,
    DEFAULT_MODEL_REVISION,
    CircuitExperimentConfig,
)
from traceguard.experiments.circuit_experiment import (
    DEFAULT_DEV_PATH,
    DEFAULT_TEST_PATH,
    CircuitExperimentRunner,
    CircuitKITAdapter,
    MockCircuitPipeline,
    compute_dataset_hash,
    load_contrastive_dataset,
    resolve_circuit_precision,
)
from traceguard.experiments.circuit_results import CircuitStatus


# ==============================================================================
# 1. TEST EVALUATION ROUTING & SPLIT SEPARATION TESTS
# ==============================================================================

def test_test_evaluation_receives_actual_test_records_and_discovers_on_dev(tmp_path):
    """Verify that when split='test', the evaluator consumes held-out TEST records (12 examples),
    while circuit discovery strictly consumes DEV records.
    """
    runner = CircuitExperimentRunner()
    cfg = CircuitExperimentConfig(
        split="test",
        output_dir=str(tmp_path),
    )
    mock_pipe = MockCircuitPipeline(output_dir=str(tmp_path))

    summary = runner.run(cfg, pipeline=mock_pipe)

    # 1. Verify summary status and hashes
    assert summary.status == CircuitStatus.SUCCESS.value
    test_records = load_contrastive_dataset(DEFAULT_TEST_PATH, expected_split="test")
    test_hash = compute_dataset_hash(test_records)
    dev_records = load_contrastive_dataset(DEFAULT_DEV_PATH, expected_split="dev")
    dev_hash = compute_dataset_hash(dev_records)

    assert summary.dataset_hash == test_hash
    assert summary.n_examples == 12
    assert summary.n_examples == len(test_records)

    # 2. Verify discovery operated strictly on DEV data
    assert summary.discovery.metadata["discovery_dataset"] == "contrastive_dev"
    assert summary.discovery.metadata["discovery_hash"] == dev_hash
    assert summary.discovery.metadata["test_data_in_discovery"] is False
    assert (tmp_path / "contrastive_dev.csv").exists()

    # 3. Verify evaluator consumed TEST records
    assert (tmp_path / "contrastive_test.csv").exists()
    assert mock_pipe.evaluated_split == "test"
    assert len(mock_pipe.evaluated_records) == 12
    assert compute_dataset_hash(mock_pipe.evaluated_records) == test_hash

    # 4. Verify faithfulness report records TEST split metadata
    assert summary.faithfulness.pillar_details["evaluated_split"] == "test"
    assert summary.faithfulness.pillar_details["evaluated_dataset_hash"] == test_hash
    assert summary.faithfulness.pillar_details["n_evaluated"] == 12


def test_test_evaluation_fails_when_test_dataset_missing(tmp_path):
    """Verify that evaluation fails explicitly when the held-out TEST dataset is missing."""
    missing_path = tmp_path / "non_existent_test.jsonl"
    runner = CircuitExperimentRunner(test_dataset_path=missing_path)
    cfg = CircuitExperimentConfig(split="test", output_dir=str(tmp_path))
    mock_pipe = MockCircuitPipeline(output_dir=str(tmp_path))

    with pytest.raises(FileNotFoundError, match="not found at"):
        runner.run(cfg, pipeline=mock_pipe)


def test_test_evaluation_fails_when_test_dataset_empty(tmp_path):
    """Verify that evaluation fails explicitly when the held-out TEST dataset has zero records."""
    empty_file = tmp_path / "empty_test.jsonl"
    empty_file.write_text("", encoding="utf-8")

    runner = CircuitExperimentRunner(test_dataset_path=empty_file)
    cfg = CircuitExperimentConfig(split="test", output_dir=str(tmp_path))
    mock_pipe = MockCircuitPipeline(output_dir=str(tmp_path))

    with pytest.raises(ValueError):
        runner.run(cfg, pipeline=mock_pipe)


def test_mock_evaluation_derives_distinct_scores_for_test_vs_dev(tmp_path):
    """Verify that MockCircuitPipeline produces distinct, input-dependent scores
    between DEV and TEST splits rather than identical hardcoded constants.
    """
    runner = CircuitExperimentRunner()

    # Run on DEV
    cfg_dev = CircuitExperimentConfig(split="dev", output_dir=str(tmp_path / "dev"))
    mock_pipe_dev = MockCircuitPipeline(output_dir=str(tmp_path / "dev"))
    summary_dev = runner.run(cfg_dev, pipeline=mock_pipe_dev)

    # Run on TEST
    cfg_test = CircuitExperimentConfig(split="test", output_dir=str(tmp_path / "test"))
    mock_pipe_test = MockCircuitPipeline(output_dir=str(tmp_path / "test"))
    summary_test = runner.run(cfg_test, pipeline=mock_pipe_test)

    # Scores must differ reflecting the held-out TEST evaluation
    assert summary_dev.faithfulness.patching_score != summary_test.faithfulness.patching_score
    assert summary_dev.faithfulness.ablation_score != summary_test.faithfulness.ablation_score
    assert summary_dev.dataset_hash != summary_test.dataset_hash

    # DEV baseline matches known reference
    assert summary_dev.faithfulness.patching_score == pytest.approx(0.8842)
    assert summary_dev.faithfulness.ablation_score == pytest.approx(0.8215)


# ==============================================================================
# 2. MODEL CONFIGURATION & REVISION PINNING TESTS
# ==============================================================================

def test_model_config_defaults():
    """Verify default model ID and exact pinned revision."""
    cfg = CircuitExperimentConfig()
    assert cfg.model_name == DEFAULT_MODEL_NAME
    assert cfg.model_name == "CohereLabs/aya-expanse-8b"
    assert cfg.model_revision == DEFAULT_MODEL_REVISION
    assert cfg.model_revision == "5062468bf9bc0c6035fd64e06274333ec127d980"
    assert cfg.precision == "auto"


def test_model_config_rejects_missing_or_empty_revision():
    """Verify that specifying a model without a pinned revision raises a ValueError."""
    with pytest.raises(ValueError, match="model_revision is required"):
        CircuitExperimentConfig(model_name="CohereLabs/aya-expanse-8b", model_revision=None)

    with pytest.raises(ValueError, match="model_revision is required"):
        CircuitExperimentConfig(model_name="CohereLabs/aya-expanse-8b", model_revision="   ")


def test_model_revision_propagated_to_model_loading_operation(tmp_path, monkeypatch):
    """Verify that CircuitKITAdapter propagates model_revision directly into quick.load_model."""
    from circuitkit import quick

    mock_load_model = MagicMock(return_value=MagicMock())
    monkeypatch.setattr(quick, "load_model", mock_load_model)

    records = load_contrastive_dataset(DEFAULT_DEV_PATH, expected_split="dev")
    csv_path = tmp_path / "contrastive_dev.csv"
    from traceguard.experiments.circuit_experiment import export_contrastive_to_csv
    export_contrastive_to_csv(records, csv_path)

    pipe = CircuitKITAdapter.build_pipeline_from_csv(
        model_name="CohereLabs/aya-expanse-8b",
        csv_path=csv_path,
        output_dir=str(tmp_path),
        model_revision="5062468bf9bc0c6035fd64e06274333ec127d980",
    )

    assert pipe.model_revision == "5062468bf9bc0c6035fd64e06274333ec127d980"

    # Trigger lazy model loading via the adapter's pinned ensure_model
    pipe._ensure_model()

    assert mock_load_model.called
    _args, kwargs = mock_load_model.call_args
    assert kwargs.get("revision") == "5062468bf9bc0c6035fd64e06274333ec127d980"


# ==============================================================================
# 3. HARDWARE-AWARE GPU PRECISION RESOLUTION TESTS
# ==============================================================================

def test_precision_resolution_on_ampere_selects_bf16(monkeypatch):
    """Ampere (capability >= 8.0) natively supports BF16 -> 'auto' resolves to 'bfloat16'."""
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    monkeypatch.setattr(torch.cuda, "get_device_capability", lambda *a, **k: (8, 0))
    monkeypatch.setattr(torch.cuda, "get_device_name", lambda *a, **k: "NVIDIA A100-SXM4-80GB")

    dev, prec, info = resolve_circuit_precision("auto", device="cuda")
    assert dev == "cuda"
    assert prec == "bfloat16"
    assert info["cuda_supports_bf16"] is True
    assert info["device_capability"] == (8, 0)


def test_precision_resolution_on_t4_falls_back_to_fp16(monkeypatch):
    """T4 (capability 7.5) lacks native BF16 -> 'auto' safely falls back to 'float16'."""
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    monkeypatch.setattr(torch.cuda, "get_device_capability", lambda *a, **k: (7, 5))
    monkeypatch.setattr(torch.cuda, "get_device_name", lambda *a, **k: "Tesla T4")

    dev, prec, info = resolve_circuit_precision("auto", device="cuda")
    assert dev == "cuda"
    assert prec == "float16"
    assert info["cuda_supports_bf16"] is False
    assert info["device_capability"] == (7, 5)


def test_precision_resolution_on_cpu_resolves_to_fp32(monkeypatch):
    """CPU execution -> 'auto' resolves to 'float32'."""
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)

    dev, prec, info = resolve_circuit_precision("auto", device="cpu")
    assert dev == "cpu"
    assert prec == "float32"
    assert info["cuda_available"] is False


def test_explicit_unsupported_bf16_on_t4_raises_error(monkeypatch):
    """Requesting explicit 'bfloat16' on CUDA hardware without BF16 support raises an error."""
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    monkeypatch.setattr(torch.cuda, "get_device_capability", lambda *a, **k: (7, 5))
    monkeypatch.setattr(torch.cuda, "get_device_name", lambda *a, **k: "Tesla T4")

    with pytest.raises(ValueError, match="Explicit precision 'bfloat16' is not supported"):
        resolve_circuit_precision("bfloat16", device="cuda")


def test_explicit_unsupported_fp16_on_cpu_raises_error(monkeypatch):
    """Requesting explicit 'float16' on CPU execution raises an error."""
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)

    with pytest.raises(ValueError, match="Explicit precision 'float16' is not supported for CPU"):
        resolve_circuit_precision("float16", device="cpu")


# ==============================================================================
# 4. INTEGRATION, ARTIFACTS & DRY-RUN TESTS
# ==============================================================================

def test_dry_run_records_honest_not_run_with_hardware_and_revision(tmp_path):
    """Dry-run writes an honest NOT_RUN summary with exact model revision, hardware info,
    and passes anti-fabrication checks.
    """
    runner = CircuitExperimentRunner()
    cfg = CircuitExperimentConfig(
        split="test",
        dry_run=True,
        output_dir=str(tmp_path),
    )

    summary = runner.run(cfg, pipeline=None)

    assert summary.status == CircuitStatus.NOT_RUN.value
    assert summary.split == "test"
    assert summary.config["model_name"] == "CohereLabs/aya-expanse-8b"
    assert summary.config["model_revision"] == "5062468bf9bc0c6035fd64e06274333ec127d980"
    assert "hardware" in summary.discovery.metadata

    # Anti-fabrication verification
    summary.verify_no_fabricated_scores()

    # Artifacts on disk
    assert (tmp_path / "summary.json").exists()
    assert (tmp_path / "discovery.json").exists()
    assert (tmp_path / "faithfulness.json").exists()
    assert (tmp_path / "intervention.json").exists()

    with open(tmp_path / "summary.json", "r", encoding="utf-8") as f:
        loaded = json.load(f)
        assert loaded["status"] == "NOT_RUN"
        assert loaded["split"] == "test"
        assert loaded["config"]["model_name"] == "CohereLabs/aya-expanse-8b"
        assert loaded["config"]["model_revision"] == "5062468bf9bc0c6035fd64e06274333ec127d980"


def test_cli_argument_overrides_config_file_values(tmp_path):
    """CLI arguments override settings defined in an external JSON configuration file."""
    import sys
    from scripts.run_circuit_experiment import parse_args

    config_file = tmp_path / "sample_config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "split": "dev",
                "model_name": "other/model-id",
                "model_revision": "1111111111111111111111111111111111111111",
                "sparsity": 0.20,
            },
            f,
        )

    test_args = [
        "run_circuit_experiment.py",
        "--config",
        str(config_file),
        "--split",
        "test",
        "--model-name",
        "CohereLabs/aya-expanse-8b",
        "--model-revision",
        "5062468bf9bc0c6035fd64e06274333ec127d980",
    ]
    sys_argv_bak = sys.argv
    try:
        sys.argv = test_args
        args = parse_args()
        assert args.split == "test"
        assert args.model_name == "CohereLabs/aya-expanse-8b"
        assert args.model_revision == "5062468bf9bc0c6035fd64e06274333ec127d980"
    finally:
        sys.argv = sys_argv_bak
