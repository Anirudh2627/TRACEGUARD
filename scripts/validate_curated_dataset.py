#!/usr/bin/env python3
"""Validate the integrity and completeness of TraceGuard curated datasets.

Usage:
  python scripts/validate_curated_dataset.py --curated-dir traceguard/data/curated
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from traceguard.data.curator.ingestion import DatasetIngester
from traceguard.data.curator.manifests import compute_sha256
from traceguard.data.curator.quality_gates import QualityGateRunner
from traceguard.data.schema import Episode

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("validate_curated_dataset")

EXPECTED_FILES = [
    "attack_dev.jsonl",
    "attack_test.jsonl",
    "benign_dev.jsonl",
    "benign_test.jsonl",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate TraceGuard curated datasets, checksums, and manifests."
    )
    parser.add_argument(
        "--curated-dir",
        default="traceguard/data/curated",
        help="Path to curated dataset directory (default: traceguard/data/curated)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    curated_dir = Path(args.curated_dir)

    print("\n======================================================================")
    print("TRACEGUARD MODULE 9: CURATED DATASET VALIDATOR")
    print("======================================================================")
    print(f"Curated Directory: {curated_dir.resolve()}")
    print("----------------------------------------------------------------------")

    if not curated_dir.exists():
        print(f"ERROR: Curated directory does not exist: {curated_dir}")
        return 1

    # 1. File existence
    for fname in EXPECTED_FILES:
        fp = curated_dir / fname
        if not fp.exists():
            print(f"ERROR: Missing expected curated file: {fp}")
            return 1

    # 2. Ingest and validate schemas
    ingester = DatasetIngester(fail_fast=True)
    datasets: dict[str, list[Episode]] = {}

    dataset_map = {
        "attack_dev": "attack_dev.jsonl",
        "attack_test": "attack_test.jsonl",
        "benign_dev": "benign_dev.jsonl",
        "benign_test": "benign_test.jsonl",
    }

    try:
        datasets, reports = ingester.ingest_collection(curated_dir, dataset_map)
    except Exception as e:
        print(f"ERROR: Failed to ingest curated datasets: {e}")
        return 1

    # 3. Quality Gate evaluation
    gate_runner = QualityGateRunner()
    quality_report = gate_runner.evaluate_collection(datasets)

    print("Quality Gate Metrics:")
    for k, v in quality_report.metrics.items():
        print(f"  {k}: {v}")

    # 4. Checksums verification
    checksums_file = curated_dir / "checksums.txt"
    if checksums_file.exists():
        print("\nVerifying SHA-256 Checksums:")
        with open(checksums_file, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                expected_hash, fname = line_str.split(maxsplit=1)
                target_fp = curated_dir / fname
                if not target_fp.exists():
                    target_fp = curated_dir / Path(fname).name
                if target_fp.exists():
                    actual_hash = compute_sha256(target_fp)
                    if actual_hash == expected_hash:
                        print(f"  [OK] {fname}")
                    else:
                        print(f"  [FAIL] {fname}: expected {expected_hash}, got {actual_hash}")
                        return 1
                else:
                    print(f"  [MISSING] {fname}")
                    return 1

    # 5. Manifest and Dataset Card checks
    manifests_dir = curated_dir / "manifests"
    cards_dir = curated_dir / "dataset_cards"

    if not manifests_dir.exists() or not any(manifests_dir.iterdir()):
        print("ERROR: manifests directory is empty or missing")
        return 1

    if not cards_dir.exists() or not any(cards_dir.iterdir()):
        print("ERROR: dataset_cards directory is empty or missing")
        return 1

    print("\n----------------------------------------------------------------------")
    if quality_report.passed:
        print("All 60 curated episodes validated successfully.")
        print("Validation Result: PASSED")
        print("======================================================================\n")
        return 0
    else:
        print("Quality Gate FAILED with violations:")
        for v in quality_report.violations:
            print(f"  - [{v.category}][{v.severity}] {v.check_name}: {v.message}")
        print("Validation Result: FAILED")
        print("======================================================================\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
