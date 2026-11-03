"""Tests for CircuitKIT experiment configuration and validation."""

import pytest

from traceguard.experiments.circuit_config import CircuitExperimentConfig


def test_circuit_config_defaults():
    cfg = CircuitExperimentConfig()
    assert cfg.algorithm == "eap-ig"
    assert cfg.level == "node"
    assert cfg.sparsity == 0.15
    assert cfg.n_examples == 32
    assert cfg.batch_size == 1
    assert cfg.scope == "both"
    assert cfg.seed == 42
    assert cfg.pillars == ["patching", "ablation"]
    assert cfg.split == "dev"
    assert cfg.output_dir == "results/circuit"
    assert cfg.allow_intervention is False


def test_circuit_config_valid_custom():
    cfg = CircuitExperimentConfig(
        algorithm="acdc",
        level="neuron",
        sparsity=0.25,
        n_examples=16,
        batch_size=2,
        scope="heads",
        pillars=["patching", "stability", "robustness"],
        split="test",
        output_dir="custom_results",
        allow_intervention=True,
    )
    assert cfg.algorithm == "acdc"
    assert cfg.level == "neuron"
    assert cfg.sparsity == 0.25
    assert cfg.split == "test"
    assert cfg.allow_intervention is True


def test_circuit_config_invalid_algorithm():
    with pytest.raises(ValueError, match="Invalid algorithm"):
        CircuitExperimentConfig(algorithm="magic_wand")


def test_circuit_config_invalid_level():
    with pytest.raises(ValueError, match="Invalid level"):
        CircuitExperimentConfig(level="token")


@pytest.mark.parametrize("invalid_sparsity", [0.0, 1.0, -0.1, 1.5, "zero"])
def test_circuit_config_invalid_sparsity(invalid_sparsity):
    with pytest.raises(ValueError, match="Invalid sparsity"):
        CircuitExperimentConfig(sparsity=invalid_sparsity)


@pytest.mark.parametrize("invalid_n", [0, -5, "ten"])
def test_circuit_config_invalid_n_examples(invalid_n):
    with pytest.raises(ValueError, match="Invalid n_examples"):
        CircuitExperimentConfig(n_examples=invalid_n)


@pytest.mark.parametrize("invalid_batch", [0, -1])
def test_circuit_config_invalid_batch_size(invalid_batch):
    with pytest.raises(ValueError, match="Invalid batch_size"):
        CircuitExperimentConfig(batch_size=invalid_batch)


def test_circuit_config_invalid_scope():
    with pytest.raises(ValueError, match="Invalid scope"):
        CircuitExperimentConfig(scope="attention_only")


def test_circuit_config_invalid_pillar():
    with pytest.raises(ValueError, match="Invalid pillar"):
        CircuitExperimentConfig(pillars=["patching", "non_existent_pillar"])


def test_circuit_config_empty_pillars():
    with pytest.raises(ValueError, match="Pillars must be a non-empty list"):
        CircuitExperimentConfig(pillars=[])


def test_circuit_config_invalid_split():
    with pytest.raises(ValueError, match="Invalid split"):
        CircuitExperimentConfig(split="validation")


def test_circuit_config_serialization(tmp_path):
    cfg = CircuitExperimentConfig(algorithm="eap", sparsity=0.2, split="test")
    d = cfg.to_dict()
    assert isinstance(d, dict)
    assert d["algorithm"] == "eap"

    restored = CircuitExperimentConfig.from_dict(d)
    assert restored.algorithm == cfg.algorithm
    assert restored.sparsity == cfg.sparsity
    assert restored.split == cfg.split

    json_str = cfg.to_json()
    from_json_cfg = CircuitExperimentConfig.from_json(json_str)
    assert from_json_cfg.algorithm == cfg.algorithm

    save_path = tmp_path / "config.json"
    cfg.save(save_path)
    assert save_path.exists()
