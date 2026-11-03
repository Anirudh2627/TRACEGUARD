"""Tests for CircuitKIT structured results, status reporting, and score transparency."""

import json
import pytest

from traceguard.experiments.circuit_results import (
    CircuitExperimentSummary,
    CircuitStatus,
    DiscoveryResult,
    FaithfulnessResult,
    InterventionResult,
)


def test_results_defaults():
    disc = DiscoveryResult()
    assert disc.status == CircuitStatus.NOT_RUN.value
    assert disc.n_nodes is None
    assert disc.n_edges is None

    faith = FaithfulnessResult()
    assert faith.status == CircuitStatus.NOT_RUN.value
    assert faith.patching_score is None
    assert faith.ablation_score is None

    inter = InterventionResult()
    assert inter.status == CircuitStatus.NOT_RUN.value
    assert inter.applied is False
    assert inter.delta_safety is None

    summary = CircuitExperimentSummary(discovery=disc, faithfulness=faith, intervention=inter)
    assert summary.status == CircuitStatus.NOT_RUN.value
    # Must pass transparency verification
    summary.verify_no_fabricated_scores()


def test_verify_no_fabricated_scores_catches_unauthorized_scores():
    # Discovery fabrication
    disc_bad = DiscoveryResult(status=CircuitStatus.NOT_RUN.value, n_nodes=12)
    sum_bad = CircuitExperimentSummary(discovery=disc_bad)
    with pytest.raises(ValueError, match="discovery.n_nodes must be None"):
        sum_bad.verify_no_fabricated_scores()

    # Faithfulness fabrication
    faith_bad = FaithfulnessResult(status=CircuitStatus.NOT_RUN.value, patching_score=0.92)
    sum_bad2 = CircuitExperimentSummary(faithfulness=faith_bad)
    with pytest.raises(ValueError, match="faithfulness.patching_score must be None"):
        sum_bad2.verify_no_fabricated_scores()

    # Intervention fabrication
    inter_bad = InterventionResult(status=CircuitStatus.NOT_RUN.value, delta_safety=0.45)
    sum_bad3 = CircuitExperimentSummary(intervention=inter_bad)
    with pytest.raises(ValueError, match="intervention.delta_safety must be None"):
        sum_bad3.verify_no_fabricated_scores()


def test_results_serialization_and_roundtrip(tmp_path):
    disc = DiscoveryResult(
        status=CircuitStatus.SUCCESS.value,
        algorithm="eap-ig",
        level="node",
        target_sparsity=0.15,
        n_nodes=8,
        n_edges=12,
        node_names=["L10H4", "L11H2"],
        execution_time_seconds=0.42,
    )
    faith = FaithfulnessResult(
        status=CircuitStatus.SUCCESS.value,
        pillars_evaluated=["patching", "ablation"],
        patching_score=0.88,
        ablation_score=0.81,
        overall_faithfulness=0.845,
    )
    inter = InterventionResult(
        status=CircuitStatus.SUCCESS.value,
        applied=True,
        delta_safety=0.62,
        delta_clean_utility=-0.02,
    )

    summary = CircuitExperimentSummary(
        status=CircuitStatus.SUCCESS.value,
        split="dev",
        config={"algorithm": "eap-ig"},
        dataset_hash="testhash123",
        n_examples=12,
        discovery=disc,
        faithfulness=faith,
        intervention=inter,
    )

    d = summary.to_dict()
    assert d["status"] == "SUCCESS"
    assert d["discovery"]["n_nodes"] == 8
    assert d["faithfulness"]["patching_score"] == 0.88

    restored = CircuitExperimentSummary.from_dict(d)
    assert restored.status == summary.status
    assert restored.discovery.n_nodes == 8
    assert restored.faithfulness.overall_faithfulness == 0.845

    saved_paths = summary.save(tmp_path)
    for name, p in saved_paths.items():
        assert p.exists(), f"Expected artifact {name} at {p}"
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert isinstance(data, dict)
