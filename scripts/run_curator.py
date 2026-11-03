#!/usr/bin/env python3
"""Run CuratorKIT dataset curation and validation pipeline for TraceGuard.

Usage:
  python scripts/run_curator.py --input-dir traceguard/data --output-dir traceguard/data/curated
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from traceguard.data.curator.curator_config import CuratorPipelineConfig
from traceguard.data.curator.curator_pipeline import CuratorPipeline

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("run_curator")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run CuratorKIT dataset curation, cleaning, deduplication, and quality gates."
    )
    parser.add_argument(
        "--input-dir",
        default="traceguard/data",
        help="Directory containing original JSONL datasets (default: traceguard/data)",
    )
    parser.add_argument(
        "--output-dir",
        default="traceguard/data/curated",
        help="Directory to write curated datasets and manifests (default: traceguard/data/curated)",
    )
    parser.add_argument(
        "--split",
        choices=["dev", "test", "all"],
        default="all",
        help="Filter curation by split (default: all)",
    )
    parser.add_argument(
        "--dataset",
        choices=["attack_dev", "attack_test", "benign_dev", "benign_test", "all"],
        default="all",
        help="Target individual dataset or 'all' (default: all)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute curation, deduplication, and quality gates without writing curated files",
    )
    parser.add_argument(
        "--validation-only",
        action="store_true",
        help="Run quality gate validation only and report verdict",
    )
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.85,
        help="MinHash / Jaccard similarity threshold for duplicate warnings (default: 0.85)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Optional path to JSON pipeline configuration file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.exists():
            print(f"ERROR: Configuration file not found: {cfg_path}")
            return 1
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = CuratorPipelineConfig.from_dict(json.load(f))
    else:
        target_datasets = None
        if args.dataset != "all":
            target_datasets = [args.dataset]
        elif args.split == "dev":
            target_datasets = ["attack_dev", "benign_dev"]
        elif args.split == "test":
            target_datasets = ["attack_test", "benign_test"]

        cfg = CuratorPipelineConfig(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            target_datasets=target_datasets,
            similarity_threshold=args.similarity_threshold,
            dry_run=args.dry_run,
            validation_only=args.validation_only,
        )

    print("\n=======================================================")
    print("TraceGuard Module 9: CuratorKIT Dataset Pipeline")
    print("=======================================================")
    print(f"Input Directory:   {cfg.input_dir}")
    print(f"Output Directory:  {cfg.output_dir}")
    print(f"Target Datasets:   {cfg.target_datasets or 'all'}")
    print(f"Similarity Thresh: {cfg.similarity_threshold}")
    print(f"Execution Mode:    {'VALIDATION ONLY' if cfg.validation_only else 'DRY-RUN' if cfg.dry_run else 'CURATION & EXPORT'}")
    print("-------------------------------------------------------")

    pipeline = CuratorPipeline(config=cfg)
    summary = pipeline.run()

    print("\n=== CuratorKIT Execution Summary ===")
    print(f"Overall Status:    {summary.status}")
    print(f"Datasets:          {', '.join(summary.datasets_processed)}")
    print(f"Episodes Ingested: {summary.total_episodes_ingested}")
    print(f"Episodes Curated:  {summary.total_episodes_curated}")
    print(f"Episodes Rejected: {summary.total_episodes_rejected}")
    print(f"Wall Clock Time:   {summary.wall_clock_seconds}s")

    qg = summary.quality_gate_report
    print("\n=== Quality Gate Results ===")
    print(f"Gate Verdict:      {qg.get('status')}")
    print(f"Checks Passed:     {qg.get('passed_checks_count')} / {qg.get('total_checks_run')}")
    print(f"Warnings:          {qg.get('warning_count')}")

    if qg.get("violations"):
        print("\nQuality Gate Violations:")
        for v in qg["violations"]:
            print(f"  - [{v.get('category')}][{v.get('severity')}] {v.get('check_name')} (ID: {v.get('episode_id')}): {v.get('message')}")

    if summary.manifest_paths:
        print("\nGenerated Manifests:")
        for mp in summary.manifest_paths:
            print(f"  - {mp}")

    if summary.dataset_card_paths:
        print("\nGenerated Dataset Cards:")
        for cp in summary.dataset_card_paths:
            print(f"  - {cp}")

    if summary.checksums_path:
        print(f"\nChecksums File:    {summary.checksums_path}")

    print("\n=======================================================\n")
    return 0 if summary.status == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
