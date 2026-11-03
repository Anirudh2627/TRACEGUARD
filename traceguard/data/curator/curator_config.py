"""Configuration schemas for CuratorKIT pipeline in TraceGuard."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

DEFAULT_DATASET_MAP = {
    "attack_dev": "episodes_attack_dev.jsonl",
    "attack_test": "episodes_attack_test.jsonl",
    "benign_dev": "episodes_benign_dev.jsonl",
    "benign_test": "episodes_benign_test.jsonl",
}


@dataclass
class CuratorPipelineConfig:
    """Configuration settings for CuratorKIT dataset curation and validation pipeline."""

    input_dir: str = "traceguard/data"
    output_dir: str = "traceguard/data/curated"
    dataset_files: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_DATASET_MAP))
    clean_whitespace: bool = True
    dedup_exact: bool = True
    dedup_similarity: bool = True
    similarity_threshold: float = 0.85
    minhash_ngram: int = 3
    minhash_num_perm: int = 128
    minhash_seed: int = 42
    run_quality_gates: bool = True
    generate_manifests: bool = True
    generate_dataset_cards: bool = True
    generate_trainer_exports: bool = True
    splits: list[str] = field(default_factory=lambda: ["dev", "test"])
    target_datasets: Optional[list[str]] = None
    dry_run: bool = False
    validation_only: bool = False

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Validate configuration settings and raise ValueError on invalid parameters."""
        if not self.input_dir or not str(self.input_dir).strip():
            raise ValueError("input_dir must be a non-empty string path")
        if not self.output_dir or not str(self.output_dir).strip():
            raise ValueError("output_dir must be a non-empty string path")

        if not isinstance(self.similarity_threshold, (int, float)) or not (
            0.0 < float(self.similarity_threshold) <= 1.0
        ):
            raise ValueError(
                f"Invalid similarity_threshold {self.similarity_threshold!r}; must be in (0.0, 1.0]"
            )
        self.similarity_threshold = float(self.similarity_threshold)

        if not isinstance(self.minhash_ngram, int) or self.minhash_ngram < 1:
            raise ValueError("minhash_ngram must be an integer >= 1")

        if not isinstance(self.minhash_num_perm, int) or self.minhash_num_perm < 8:
            raise ValueError("minhash_num_perm must be an integer >= 8")

        for s in self.splits:
            if s not in ("dev", "test"):
                raise ValueError(f"Invalid split {s!r}; must be 'dev' or 'test'")

        if self.target_datasets is not None:
            valid_keys = set(self.dataset_files.keys())
            for td in self.target_datasets:
                if td not in valid_keys:
                    raise ValueError(
                        f"Unknown target_dataset {td!r}; valid options: {sorted(valid_keys)}"
                    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CuratorPipelineConfig:
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> CuratorPipelineConfig:
        return cls.from_dict(json.loads(json_str))
