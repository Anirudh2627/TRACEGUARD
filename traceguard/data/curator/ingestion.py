"""JSONL Dataset ingestion pipeline for TraceGuard CuratorKIT integration."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from curatorkit.schema import DataSample, ProvenanceRecord
from traceguard.data.schema import Episode

logger = logging.getLogger(__name__)

REQUIRED_EPISODE_FIELDS = [
    "episode_id",
    "template_id",
    "split",
    "initial_user_task",
    "turns",
]


@dataclass
class IngestionReport:
    """Statistics and details from a dataset ingestion run."""

    dataset_name: str
    source_path: str
    total_lines: int = 0
    valid_count: int = 0
    rejected_count: int = 0
    malformed_json_count: int = 0
    schema_violation_count: int = 0
    rejected_records: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_name": self.dataset_name,
            "source_path": self.source_path,
            "total_lines": self.total_lines,
            "valid_count": self.valid_count,
            "rejected_count": self.rejected_count,
            "malformed_json_count": self.malformed_json_count,
            "schema_violation_count": self.schema_violation_count,
            "rejected_records": self.rejected_records,
        }


def episode_to_curatorkit_sample(episode: Episode) -> DataSample:
    """Convert a TraceGuard Episode to a CuratorKIT DataSample.

    Preserves full episode fidelity in DataSample.metadata['episode'],
    and tracks turns in the provenance chain.
    """
    first_user = episode.turns[0].user_message if episode.turns else episode.initial_user_task

    prov_records: list[ProvenanceRecord] = []
    for idx, t in enumerate(episode.turns):
        prov_records.append(
            ProvenanceRecord(
                step_name=f"turn_{t.turn_id}",
                step_version="1.0",
                config_hash="traceguard_turn_provenance",
                notes={
                    "user_message_len": len(t.user_message),
                    "source_count": len(t.source_records),
                    "expected_action": t.expected_action,
                },
            )
        )

    return DataSample(
        id=episode.episode_id,
        source_uri=f"traceguard://{episode.split}/{episode.episode_id}",
        instruction=episode.initial_user_task,
        input=first_user,
        output=episode.expected_safe_behavior,
        task_type="attack" if episode.is_attack else "benign",
        label=1.0 if episode.is_attack else 0.0,
        metadata={
            "episode": episode.to_dict(),
            "template_id": episode.template_id,
            "split": episode.split,
            "attack_family": episode.attack_family,
            "is_attack": episode.is_attack,
            "canaries": [c.value for c in episode.synthetic_canaries],
            "prohibited_actions": list(episode.expected_prohibited_actions),
        },
        provenance_chain=prov_records,
    )


def curatorkit_sample_to_episode(sample: DataSample) -> Episode:
    """Reconstruct a TraceGuard Episode from a CuratorKIT DataSample."""
    raw_ep = sample.metadata.get("episode")
    if not raw_ep or not isinstance(raw_ep, dict):
        raise ValueError(f"DataSample {sample.id} missing raw episode in metadata")
    return Episode.from_dict(raw_ep)


class DatasetIngester:
    """Ingests and validates TraceGuard JSONL episode datasets."""

    def __init__(self, fail_fast: bool = False) -> None:
        self.fail_fast = fail_fast

    def ingest_file(
        self, path: str | Path, dataset_name: Optional[str] = None
    ) -> tuple[list[Episode], IngestionReport]:
        """Ingest a single JSONL file into a list of validated Episode instances."""
        p = Path(path)
        name = dataset_name or p.stem

        if not p.exists():
            raise FileNotFoundError(f"Dataset file not found at {p}")

        report = IngestionReport(dataset_name=name, source_path=str(p))
        episodes: list[Episode] = []

        with open(p, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                raw = line.strip()
                if not raw:
                    continue
                report.total_lines += 1

                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as e:
                    report.malformed_json_count += 1
                    report.rejected_count += 1
                    rej = {
                        "line_number": line_idx,
                        "raw_line": raw[:200],
                        "error_type": "JSONDecodeError",
                        "reason": str(e),
                    }
                    report.rejected_records.append(rej)
                    if self.fail_fast:
                        raise ValueError(f"Malformed JSON at line {line_idx} in {p}: {e}")
                    continue

                if not isinstance(data, dict):
                    report.schema_violation_count += 1
                    report.rejected_count += 1
                    rej = {
                        "line_number": line_idx,
                        "raw_line": raw[:200],
                        "error_type": "TypeError",
                        "reason": f"Expected JSON object, got {type(data).__name__}",
                    }
                    report.rejected_records.append(rej)
                    if self.fail_fast:
                        raise ValueError(rej["reason"])
                    continue

                # Check required fields
                missing = [fld for fld in REQUIRED_EPISODE_FIELDS if fld not in data]
                if missing:
                    report.schema_violation_count += 1
                    report.rejected_count += 1
                    rej = {
                        "line_number": line_idx,
                        "episode_id": data.get("episode_id", "UNKNOWN"),
                        "error_type": "MissingFieldsError",
                        "reason": f"Missing required fields: {missing}",
                    }
                    report.rejected_records.append(rej)
                    if self.fail_fast:
                        raise ValueError(rej["reason"])
                    continue

                try:
                    ep = Episode.from_dict(data)
                    episodes.append(ep)
                    report.valid_count += 1
                except Exception as e:
                    report.schema_violation_count += 1
                    report.rejected_count += 1
                    rej = {
                        "line_number": line_idx,
                        "episode_id": data.get("episode_id", "UNKNOWN"),
                        "error_type": type(e).__name__,
                        "reason": str(e),
                    }
                    report.rejected_records.append(rej)
                    if self.fail_fast:
                        raise

        return episodes, report

    def ingest_collection(
        self, input_dir: str | Path, dataset_map: dict[str, str]
    ) -> tuple[dict[str, list[Episode]], dict[str, IngestionReport]]:
        """Ingest all datasets in the dataset_map."""
        base_dir = Path(input_dir)
        all_episodes: dict[str, list[Episode]] = {}
        all_reports: dict[str, IngestionReport] = {}

        for ds_name, filename in dataset_map.items():
            file_path = base_dir / filename
            eps, rpt = self.ingest_file(file_path, dataset_name=ds_name)
            all_episodes[ds_name] = eps
            all_reports[ds_name] = rpt

        return all_episodes, all_reports
