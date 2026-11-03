"""Structured result definitions and serialization for CircuitKIT interpretability experiments.

Maintains strict transparency: when models or experiments are unexecuted, status is explicitly
marked as NOT_RUN and numeric metrics remain None (never fabricated as synthetic 0.0s).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class CircuitStatus(str, Enum):
    """Execution status for circuit discovery, evaluation, or intervention."""

    NOT_RUN = "NOT_RUN"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class DiscoveryResult:
    """Result from circuit discovery (e.g. EAP-IG, ACDC)."""

    status: str = CircuitStatus.NOT_RUN.value
    algorithm: str = "eap-ig"
    level: str = "node"
    target_sparsity: float = 0.15
    actual_sparsity: Optional[float] = None
    n_nodes: Optional[int] = None
    n_edges: Optional[int] = None
    node_names: Optional[list[str]] = None
    artifact_path: Optional[str] = None
    execution_time_seconds: Optional[float] = None
    error_message: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FaithfulnessResult:
    """Result from 6-pillar faithfulness evaluation."""

    status: str = CircuitStatus.NOT_RUN.value
    pillars_evaluated: list[str] = field(default_factory=list)
    patching_score: Optional[float] = None
    ablation_score: Optional[float] = None
    stability_score: Optional[float] = None
    robustness_score: Optional[float] = None
    baseline_comparison: Optional[dict[str, Any]] = None
    generalization_score: Optional[float] = None
    overall_faithfulness: Optional[float] = None
    pillar_details: dict[str, Any] = field(default_factory=dict)
    execution_time_seconds: Optional[float] = None
    error_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InterventionResult:
    """Result from optional circuit-targeted intervention (e.g. circuit pruning / ablation)."""

    status: str = CircuitStatus.NOT_RUN.value
    intervention_type: str = "circuit_pruning"
    applied: bool = False
    clean_accuracy_pre: Optional[float] = None
    clean_accuracy_post: Optional[float] = None
    attack_success_rate_pre: Optional[float] = None
    attack_success_rate_post: Optional[float] = None
    safety_score_pre: Optional[float] = None
    safety_score_post: Optional[float] = None
    delta_safety: Optional[float] = None
    delta_clean_utility: Optional[float] = None
    error_message: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CircuitExperimentSummary:
    """Consolidated summary of CircuitKIT discovery, faithfulness, and intervention."""

    status: str = CircuitStatus.NOT_RUN.value
    split: str = "dev"
    config: dict[str, Any] = field(default_factory=dict)
    dataset_hash: str = ""
    n_examples: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    discovery: DiscoveryResult = field(default_factory=DiscoveryResult)
    faithfulness: FaithfulnessResult = field(default_factory=FaithfulnessResult)
    intervention: InterventionResult = field(default_factory=InterventionResult)
    notes: Optional[str] = None

    def verify_no_fabricated_scores(self) -> None:
        """Verify that when components are NOT_RUN, no numeric scores are fabricated."""
        if self.discovery.status in (CircuitStatus.NOT_RUN.value, CircuitStatus.UNAVAILABLE.value):
            if self.discovery.n_nodes is not None:
                raise ValueError("discovery.n_nodes must be None when status is NOT_RUN")
            if self.discovery.n_edges is not None:
                raise ValueError("discovery.n_edges must be None when status is NOT_RUN")

        if self.faithfulness.status in (CircuitStatus.NOT_RUN.value, CircuitStatus.UNAVAILABLE.value):
            if self.faithfulness.patching_score is not None:
                raise ValueError("faithfulness.patching_score must be None when status is NOT_RUN")
            if self.faithfulness.ablation_score is not None:
                raise ValueError("faithfulness.ablation_score must be None when status is NOT_RUN")
            if self.faithfulness.overall_faithfulness is not None:
                raise ValueError("faithfulness.overall_faithfulness must be None when status is NOT_RUN")

        if self.intervention.status in (CircuitStatus.NOT_RUN.value, CircuitStatus.UNAVAILABLE.value):
            if self.intervention.delta_safety is not None:
                raise ValueError("intervention.delta_safety must be None when status is NOT_RUN")
            if self.intervention.delta_clean_utility is not None:
                raise ValueError("intervention.delta_clean_utility must be None when status is NOT_RUN")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "split": self.split,
            "config": self.config,
            "dataset_hash": self.dataset_hash,
            "n_examples": self.n_examples,
            "timestamp": self.timestamp,
            "discovery": self.discovery.to_dict(),
            "faithfulness": self.faithfulness.to_dict(),
            "intervention": self.intervention.to_dict(),
            "notes": self.notes,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CircuitExperimentSummary:
        discovery = DiscoveryResult(**data.get("discovery", {}))
        faithfulness = FaithfulnessResult(**data.get("faithfulness", {}))
        intervention = InterventionResult(**data.get("intervention", {}))

        return cls(
            status=data.get("status", CircuitStatus.NOT_RUN.value),
            split=data.get("split", "dev"),
            config=data.get("config", {}),
            dataset_hash=data.get("dataset_hash", ""),
            n_examples=data.get("n_examples", 0),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            discovery=discovery,
            faithfulness=faithfulness,
            intervention=intervention,
            notes=data.get("notes"),
        )

    def save(self, directory: str | Path) -> dict[str, Path]:
        """Save structured artifacts: discovery.json, faithfulness.json, intervention.json, and summary.json."""
        out_dir = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)

        paths = {
            "discovery": out_dir / "discovery.json",
            "faithfulness": out_dir / "faithfulness.json",
            "intervention": out_dir / "intervention.json",
            "summary": out_dir / "summary.json",
        }

        with open(paths["discovery"], "w", encoding="utf-8") as f:
            json.dump(self.discovery.to_dict(), f, indent=2)

        with open(paths["faithfulness"], "w", encoding="utf-8") as f:
            json.dump(self.faithfulness.to_dict(), f, indent=2)

        with open(paths["intervention"], "w", encoding="utf-8") as f:
            json.dump(self.intervention.to_dict(), f, indent=2)

        with open(paths["summary"], "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

        return paths
