"""Curator execution results and summary schemas for TraceGuard."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class CuratorExecutionSummary:
    """Consolidated summary of a complete CuratorKIT execution run."""

    status: str = "PASSED"  # "PASSED" or "FAILED"
    run_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    config: dict[str, Any] = field(default_factory=dict)
    datasets_processed: list[str] = field(default_factory=list)
    total_episodes_ingested: int = 0
    total_episodes_curated: int = 0
    total_episodes_rejected: int = 0
    ingestion_reports: dict[str, Any] = field(default_factory=dict)
    cleaning_reports: dict[str, Any] = field(default_factory=dict)
    deduplication_reports: dict[str, Any] = field(default_factory=dict)
    quality_gate_report: dict[str, Any] = field(default_factory=dict)
    manifest_paths: list[str] = field(default_factory=list)
    dataset_card_paths: list[str] = field(default_factory=list)
    curated_file_paths: list[str] = field(default_factory=list)
    checksums_path: Optional[str] = None
    wall_clock_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CuratorExecutionSummary:
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def save(self, directory: str | Path) -> Path:
        p = Path(directory) / "curator_summary.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        return p
