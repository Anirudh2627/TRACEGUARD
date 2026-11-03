"""Tests for CircuitKIT experiment execution, adapter, CSV generation, and runner flows."""

import csv
from pathlib import Path
import pytest

from traceguard.experiments.circuit_config import CircuitExperimentConfig
from traceguard.experiments.circuit_experiment import (
    CircuitExperimentRunner,
    CircuitKITAdapter,
    MockCircuitPipeline,
    export_contrastive_to_csv,
    load_contrastive_dataset,
)
from traceguard.experiments.circuit_results import CircuitStatus


def test_adapter_environment_check():
    info = CircuitKITAdapter.check_environment()
    assert isinstance(info, dict)
    assert "platform" in info
    assert "circuitkit_available" in info
    assert "torch_available" in info
    assert "device" in info


def test_export_contrastive_to_csv(tmp_path):
    records = [
        {
            "example_id": "ex1",
            "template_id": "TPL_1",
            "split": "dev",
            "attack_family": "A",
            "clean_prompt": "Prompt 1",
            "clean_answer": "Answer 1",
            "corrupt_prompt": "Corrupt 1",
            "corrupt_answer": "Corrupt Answer 1",
        }
    ]
    csv_file = tmp_path / "test.csv"
    exported_path = export_contrastive_to_csv(records, csv_file)
    assert exported_path.exists()

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == 1
        assert reader[0]["clean_prompt"] == "Prompt 1"
        assert reader[0]["clean_answer"] == "Answer 1"
        assert reader[0]["corrupt_prompt"] == "Corrupt 1"
        assert reader[0]["corrupt_answer"] == "Corrupt Answer 1"


def test_runner_execution_without_model(tmp_path):
    runner = CircuitExperimentRunner()
    cfg = CircuitExperimentConfig(
        split="dev",
        output_dir=str(tmp_path),
    )

    summary = runner.run(cfg, pipeline=None)
    assert summary.status == CircuitStatus.NOT_RUN.value
    assert summary.discovery.status == CircuitStatus.NOT_RUN.value
    assert summary.faithfulness.status == CircuitStatus.NOT_RUN.value
    assert summary.intervention.status == CircuitStatus.NOT_RUN.value
    assert "Real model not supplied" in summary.notes

    # Verify no fabricated values
    summary.verify_no_fabricated_scores()

    # Check files created
    assert (tmp_path / "summary.json").exists()
    assert (tmp_path / "discovery.json").exists()
    assert (tmp_path / "faithfulness.json").exists()
    assert (tmp_path / "intervention.json").exists()


def test_runner_execution_with_mock_pipeline(tmp_path):
    runner = CircuitExperimentRunner()
    cfg = CircuitExperimentConfig(
        split="dev",
        output_dir=str(tmp_path),
        allow_intervention=True,
    )

    mock_pipe = MockCircuitPipeline(output_dir=str(tmp_path))
    summary = runner.run(cfg, pipeline=mock_pipe)

    assert summary.status == CircuitStatus.SUCCESS.value
    assert summary.discovery.status == CircuitStatus.SUCCESS.value
    assert summary.discovery.n_nodes == 6
    assert summary.discovery.node_names == ["L10H4", "L10H7", "L11H2", "L11H9", "L12H1", "L12H8"]

    assert summary.faithfulness.status == CircuitStatus.SUCCESS.value
    assert summary.faithfulness.patching_score == pytest.approx(0.8842)
    assert summary.faithfulness.ablation_score == pytest.approx(0.8215)
    assert summary.faithfulness.overall_faithfulness == pytest.approx(0.8528, abs=1e-3)

    assert summary.intervention.status == CircuitStatus.SUCCESS.value
    assert summary.intervention.delta_safety == pytest.approx(0.65)
    assert summary.intervention.delta_clean_utility == pytest.approx(-0.01)


def test_runner_discovery_failure_handling(tmp_path):
    runner = CircuitExperimentRunner()
    cfg = CircuitExperimentConfig(
        split="dev",
        output_dir=str(tmp_path),
    )

    failing_pipe = MockCircuitPipeline(output_dir=str(tmp_path), fail_discovery=True)
    summary = runner.run(cfg, pipeline=failing_pipe)

    assert summary.status == CircuitStatus.FAILED.value
    assert summary.discovery.status == CircuitStatus.FAILED.value
    assert "Simulated discovery failure" in summary.discovery.error_message
    assert summary.faithfulness.status == CircuitStatus.NOT_RUN.value


def test_runner_evaluation_failure_handling(tmp_path):
    runner = CircuitExperimentRunner()
    cfg = CircuitExperimentConfig(
        split="dev",
        output_dir=str(tmp_path),
    )

    failing_pipe = MockCircuitPipeline(output_dir=str(tmp_path), fail_evaluation=True)
    summary = runner.run(cfg, pipeline=failing_pipe)

    assert summary.status == CircuitStatus.FAILED.value
    assert summary.discovery.status == CircuitStatus.SUCCESS.value
    assert summary.faithfulness.status == CircuitStatus.FAILED.value
    assert "Simulated evaluation failure" in summary.faithfulness.error_message


def test_runner_missing_dataset_path(tmp_path):
    runner = CircuitExperimentRunner(
        dev_dataset_path=tmp_path / "non_existent.jsonl",
        test_dataset_path=tmp_path / "non_existent.jsonl",
    )
    with pytest.raises(FileNotFoundError):
        runner.validate_datasets()


def test_mock_pipeline_flagged_and_cannot_masquerade_as_real(tmp_path):
    runner = CircuitExperimentRunner()
    cfg = CircuitExperimentConfig(split="dev", output_dir=str(tmp_path))
    mock_pipe = MockCircuitPipeline(output_dir=str(tmp_path))

    summary = runner.run(cfg, pipeline=mock_pipe)
    assert summary.config.get("is_mock") is True
    assert summary.discovery.metadata.get("is_mock") is True
    assert summary.faithfulness.pillar_details.get("is_mock") is True
    assert "[MOCK MODE]" in summary.notes


def test_dataclass_faithfulness_report_details_extraction(tmp_path):
    from dataclasses import dataclass
    from traceguard.experiments.circuit_experiment import MockCircuit

    @dataclass
    class DataclassFaithfulnessReport:
        patching_score: float = 0.8123
        ablation_score: float = 0.7654
        stability: float = 0.8900
        robustness: float = 0.8300
        generalization: float = 0.7700

    class PipelineWithDataclassReport:
        _circuit = MockCircuit(["L10H4", "L10H7"])
        _artifact_path = f"{tmp_path}/circuit.pt"
        report = DataclassFaithfulnessReport()

        def discover(self, **kwargs):
            return self

        def evaluate(self, **kwargs):
            return self

    runner = CircuitExperimentRunner()
    cfg = CircuitExperimentConfig(split="dev", output_dir=str(tmp_path))
    summary = runner.run(cfg, pipeline=PipelineWithDataclassReport())

    assert summary.faithfulness.status == CircuitStatus.SUCCESS.value
    assert summary.faithfulness.patching_score == pytest.approx(0.8123)
    assert "patching_score" in summary.faithfulness.pillar_details
    assert summary.faithfulness.pillar_details["stability"] == pytest.approx(0.8900)

