"""CircuitKIT experiment configuration schema and validation for TraceGuard.

Supports circuit discovery algorithms (e.g. eap-ig, eap, acdc), sparsity levels,
evaluation pillars (patching, ablation, stability, robustness, baselines, generalization),
and dataset split assignments.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

ALLOWED_ALGORITHMS = {
    "eap-ig",
    "eap",
    "acdc",
    "act-patch",
    "edge-pruning",
    "integrated-gradients",
}

ALLOWED_LEVELS = {"node", "neuron"}
ALLOWED_SCOPES = {"heads", "mlp", "both"}
ALLOWED_SPLITS = {"dev", "test"}
ALLOWED_PILLARS = {
    "patching",
    "ablation",
    "stability",
    "robustness",
    "baselines",
    "generalization",
}


@dataclass
class CircuitExperimentConfig:
    """Configuration for circuit discovery, faithfulness, and optional intervention."""

    algorithm: str = "eap-ig"
    level: str = "node"
    sparsity: float = 0.15
    n_examples: int = 32
    batch_size: int = 1
    scope: str = "both"
    seed: int = 42
    pillars: list[str] = field(default_factory=lambda: ["patching", "ablation"])
    n_eval_examples: int = 64
    n_stability_runs: int = 3
    output_dir: str = "results/circuit"
    model_name: Optional[str] = None
    allow_intervention: bool = False
    task_name: Optional[str] = None
    split: str = "dev"
    precision: str = "bfloat16"
    device: Optional[str] = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Validate all configuration attributes and raise ValueError on invalid settings."""
        if self.algorithm not in ALLOWED_ALGORITHMS:
            raise ValueError(
                f"Invalid algorithm '{self.algorithm}'. Must be one of: {sorted(ALLOWED_ALGORITHMS)}"
            )

        if self.level not in ALLOWED_LEVELS:
            raise ValueError(
                f"Invalid level '{self.level}'. Must be one of: {sorted(ALLOWED_LEVELS)}"
            )

        if not isinstance(self.sparsity, (int, float)) or not (0.0 < float(self.sparsity) < 1.0):
            raise ValueError(
                f"Invalid sparsity '{self.sparsity}'. Sparsity must be a float strictly between 0.0 and 1.0"
            )
        self.sparsity = float(self.sparsity)

        if not isinstance(self.n_examples, int) or self.n_examples <= 0:
            raise ValueError(
                f"Invalid n_examples '{self.n_examples}'. Must be a positive integer > 0"
            )

        if not isinstance(self.batch_size, int) or self.batch_size <= 0:
            raise ValueError(
                f"Invalid batch_size '{self.batch_size}'. Must be a positive integer > 0"
            )

        if self.scope not in ALLOWED_SCOPES:
            raise ValueError(
                f"Invalid scope '{self.scope}'. Must be one of: {sorted(ALLOWED_SCOPES)}"
            )

        if not isinstance(self.pillars, (list, tuple)) or len(self.pillars) == 0:
            raise ValueError("Pillars must be a non-empty list of evaluation pillars")

        for pillar in self.pillars:
            if pillar not in ALLOWED_PILLARS:
                raise ValueError(
                    f"Invalid pillar '{pillar}'. Must be one of: {sorted(ALLOWED_PILLARS)}"
                )

        if self.split not in ALLOWED_SPLITS:
            raise ValueError(
                f"Invalid split '{self.split}'. Must be one of: {sorted(ALLOWED_SPLITS)}"
            )

        if not isinstance(self.n_eval_examples, int) or self.n_eval_examples <= 0:
            raise ValueError(
                f"Invalid n_eval_examples '{self.n_eval_examples}'. Must be a positive integer > 0"
            )

        if not isinstance(self.n_stability_runs, int) or self.n_stability_runs <= 0:
            raise ValueError(
                f"Invalid n_stability_runs '{self.n_stability_runs}'. Must be a positive integer > 0"
            )

        if not self.output_dir or not str(self.output_dir).strip():
            raise ValueError("output_dir must be a non-empty string path")

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CircuitExperimentConfig:
        """Create configuration instance from dictionary."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def to_json(self, indent: int = 2) -> str:
        """Serialize configuration to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> CircuitExperimentConfig:
        """Deserialize configuration from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def save(self, path: str | Path) -> None:
        """Save configuration to JSON file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_json())
