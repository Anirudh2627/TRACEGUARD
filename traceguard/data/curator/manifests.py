"""Provenance manifest generator for TraceGuard curated datasets."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import curatorkit
from curatorkit.manifest import _file_sha256
from traceguard.data.curator.cleaning import CleaningReport
from traceguard.data.curator.deduplication import DeduplicationReport
from traceguard.data.curator.quality_gates import QualityGateReport
from traceguard.data.schema import Episode

logger = logging.getLogger(__name__)

TRACEGUARD_COMMIT = "6c851e1"
DATASET_VERSION = "1.0.0"


def compute_sha256(path: str | Path) -> str:
    """Compute SHA-256 hash of a file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    return _file_sha256(p)


def extract_provenance_label_counts(episodes: list[Episode]) -> dict[str, int]:
    """Aggregate all provenance trust labels across turns and source records."""
    counts: dict[str, int] = {}
    for ep in episodes:
        for t in ep.turns:
            for s in t.source_records:
                lbl = s.provenance.value if hasattr(s.provenance, "value") else str(s.provenance)
                counts[lbl] = counts.get(lbl, 0) + 1
        for s in ep.source_records:
            lbl = s.provenance.value if hasattr(s.provenance, "value") else str(s.provenance)
            counts[lbl] = counts.get(lbl, 0) + 1
        for _, lbl in ep.expected_trust_labels.items():
            counts[lbl] = counts.get(lbl, 0) + 1
    return counts


class ManifestBuilder:
    """Constructs deterministic provenance manifests for curated datasets."""

    def __init__(
        self,
        output_dir: str | Path = "traceguard/data/curated/manifests",
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def build_dataset_manifest(
        self,
        dataset_name: str,
        episodes: list[Episode],
        source_path: str | Path,
        curated_path: str | Path,
        cleaning_report: Optional[CleaningReport] = None,
        dedup_report: Optional[DeduplicationReport] = None,
        gate_report: Optional[QualityGateReport] = None,
    ) -> dict[str, Any]:
        """Construct manifest dictionary for a single dataset."""
        src_p = Path(source_path)
        cur_p = Path(curated_path)

        src_hash = compute_sha256(src_p) if src_p.is_file() else "NOT_A_SINGLE_FILE"
        cur_hash = compute_sha256(cur_p) if cur_p.is_file() else "NOT_A_SINGLE_FILE"

        attack_count = sum(1 for ep in episodes if ep.is_attack)
        benign_count = sum(1 for ep in episodes if not ep.is_attack)
        dev_count = sum(1 for ep in episodes if ep.split == "dev")
        test_count = sum(1 for ep in episodes if ep.split == "test")

        families: dict[str, int] = {}
        templates: list[str] = sorted(list({ep.template_id for ep in episodes}))
        for ep in episodes:
            fam = ep.attack_family or ("attack" if ep.is_attack else "benign")
            families[fam] = families.get(fam, 0) + 1

        canaries = set()
        for ep in episodes:
            for c in ep.synthetic_canaries:
                canaries.add(c.value)

        prov_counts = extract_provenance_label_counts(episodes)

        manifest: dict[str, Any] = {
            "dataset_name": dataset_name,
            "dataset_version": DATASET_VERSION,
            "generation_timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_versions": {
                "curatorkit": getattr(curatorkit, "__version__", "0.1.22"),
                "traceguard_commit": TRACEGUARD_COMMIT,
            },
            "source_files": [
                {
                    "path": str(src_p),
                    "filename": src_p.name,
                    "sha256": src_hash,
                }
            ],
            "curated_output": {
                "path": str(cur_p),
                "filename": cur_p.name,
                "sha256": cur_hash,
            },
            "metrics": {
                "episode_count": len(episodes),
                "attack_count": attack_count,
                "benign_count": benign_count,
                "dev_count": dev_count,
                "test_count": test_count,
                "attack_family_distribution": families,
                "unique_templates_count": len(templates),
                "template_ids": templates,
                "unique_canary_count": len(canaries),
                "provenance_labels_distribution": prov_counts,
            },
            "cleaning_operations": cleaning_report.to_dict() if cleaning_report else {},
            "duplicate_findings": dedup_report.to_dict() if dedup_report else {},
            "quality_gate_results": gate_report.to_dict() if gate_report else {},
        }
        return manifest

    def write_manifest(self, manifest: dict[str, Any], filename: str) -> Path:
        """Write manifest dict to JSON file."""
        out_path = self.output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        return out_path

    def write_checksums(self, file_paths: list[Path], output_file: Path) -> Path:
        """Write SHA-256 checksums file for all curated outputs."""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        base_dir = output_file.parent
        with open(output_file, "w", encoding="utf-8") as f:
            for p in sorted(file_paths):
                if p.is_file():
                    try:
                        rel = p.relative_to(base_dir).as_posix()
                    except ValueError:
                        rel = p.name
                    f.write(f"{compute_sha256(p)}  {rel}\n")
        return output_file
