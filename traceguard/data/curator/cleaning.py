"""Deterministic cleaning and normalization for TraceGuard episodes."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from traceguard.data.schema import (
    Episode,
    SourceRecord,
    Turn,
    validate_provenance_label,
)

logger = logging.getLogger(__name__)


@dataclass
class CleaningReport:
    """Audit report of cleaning and normalization operations performed."""

    dataset_name: str
    episodes_examined: int = 0
    episodes_modified: int = 0
    transformations_applied: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def record_transform(self, transform_name: str) -> None:
        self.transformations_applied[transform_name] = (
            self.transformations_applied.get(transform_name, 0) + 1
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_name": self.dataset_name,
            "episodes_examined": self.episodes_examined,
            "episodes_modified": self.episodes_modified,
            "transformations_applied": self.transformations_applied,
            "warnings": self.warnings,
        }


class EpisodeCleaner:
    """Safe, non-destructive normalizer for TraceGuard multi-turn episodes."""

    def __init__(self, normalize_whitespace: bool = True) -> None:
        self.normalize_whitespace = normalize_whitespace

    def clean_episode(self, episode: Episode) -> tuple[Episode, list[str]]:
        """Clean an individual episode without modifying the semantics of attack instructions.

        Returns:
            (cleaned_episode, applied_transformations_list)
        """
        transforms: list[str] = []
        raw = episode.to_dict()

        # 1. Normalize initial_user_task whitespace
        task = raw.get("initial_user_task", "")
        if self.normalize_whitespace and isinstance(task, str):
            stripped_task = task.strip()
            if stripped_task != task:
                raw["initial_user_task"] = stripped_task
                transforms.append("normalize_initial_user_task_whitespace")

        # 2. Normalize and validate turns
        cleaned_turns = []
        for idx, t in enumerate(raw.get("turns", [])):
            turn_dict = dict(t)
            user_msg = turn_dict.get("user_message", "")
            if self.normalize_whitespace and isinstance(user_msg, str):
                cleaned_msg = user_msg.strip()
                if cleaned_msg != user_msg:
                    turn_dict["user_message"] = cleaned_msg
                    transforms.append("normalize_turn_whitespace")

            # Clean and validate source records inside turn
            cleaned_sources = []
            for s in turn_dict.get("source_records", []):
                src_dict = dict(s)
                prov = src_dict.get("provenance")
                if prov is not None:
                    validate_provenance_label(prov)
                cleaned_sources.append(SourceRecord.from_dict(src_dict))
            turn_dict["source_records"] = cleaned_sources

            cleaned_turns.append(Turn.from_dict(turn_dict))
        raw["turns"] = cleaned_turns

        # 3. Normalize top-level source records
        cleaned_top_sources = []
        for s in raw.get("source_records", []):
            src_dict = dict(s)
            prov = src_dict.get("provenance")
            if prov is not None:
                validate_provenance_label(prov)
            cleaned_top_sources.append(SourceRecord.from_dict(src_dict))
        raw["source_records"] = cleaned_top_sources

        # 4. Validate trust labels in expected_trust_labels
        for _, lbl in raw.get("expected_trust_labels", {}).items():
            validate_provenance_label(lbl)

        # 5. Metadata normalization: track curator provenance without overwriting episode data
        meta = dict(raw.get("metadata", {}))
        meta["curated_clean"] = True
        raw["metadata"] = meta

        cleaned_episode = Episode.from_dict(raw)
        return cleaned_episode, transforms

    def clean_dataset(
        self, episodes: list[Episode], dataset_name: str = "dataset"
    ) -> tuple[list[Episode], CleaningReport]:
        """Clean a list of episodes and produce a transformation audit report."""
        report = CleaningReport(dataset_name=dataset_name, episodes_examined=len(episodes))
        cleaned_list: list[Episode] = []

        for ep in episodes:
            cleaned_ep, transforms = self.clean_episode(ep)
            cleaned_list.append(cleaned_ep)
            if transforms:
                report.episodes_modified += 1
                for t in transforms:
                    report.record_transform(t)

        return cleaned_list, report
