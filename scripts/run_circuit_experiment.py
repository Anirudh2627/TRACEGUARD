#!/usr/bin/env python3
"""Run CircuitKIT interpretability experiments for TraceGuard.

Supports environment checking, dataset validation, dry-run (honest NOT_RUN),
and mock pipeline execution for testing offline or awaiting real model integration.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from traceguard.experiments.circuit_config import CircuitExperimentConfig
from traceguard.experiments.circuit_experiment import (
    CircuitExperimentRunner,
    CircuitKITAdapter,
    MockCircuitPipeline,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("run_circuit_experiment")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run CircuitKIT interpretability experiments for TraceGuard."
    )
    parser.add_argument(
        "--split",
        choices=["dev", "test"],
        default="dev",
        help="Dataset split to evaluate (default: dev)",
    )
    parser.add_argument(
        "--validate-data",
        action="store_true",
        help="Validate contrastive datasets and split disjointness, then exit",
    )
    parser.add_argument(
        "--validate-env",
        action="store_true",
        help="Validate CircuitKIT environment, PyTorch, and hardware, then exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform configuration and data validation, writing an honest NOT_RUN summary",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run using MockCircuitPipeline to verify end-to-end harness offline",
    )
    parser.add_argument(
        "--intervention",
        action="store_true",
        help="Enable optional circuit intervention evaluation",
    )
    parser.add_argument(
        "--algorithm",
        default="eap-ig",
        help="Circuit discovery algorithm (default: eap-ig)",
    )
    parser.add_argument(
        "--sparsity",
        type=float,
        default=0.15,
        help="Target pruning sparsity (default: 0.15)",
    )
    parser.add_argument(
        "--out-dir",
        default="results/circuit",
        help="Directory to write experiment results (default: results/circuit)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Optional path to a JSON configuration file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # 1. Environment validation mode
    if args.validate_env:
        print("\n=== CircuitKIT Environment Check ===")
        env_info = CircuitKITAdapter.check_environment()
        for k, v in env_info.items():
            print(f"  {k}: {v}")
        if not env_info.get("circuitkit_available"):
            print("\nWARNING: CircuitKIT is not installed in the current environment.")
            return 1
        print("\nEnvironment check completed successfully.")
        return 0

    runner = CircuitExperimentRunner()

    # 2. Dataset validation mode
    if args.validate_data:
        print("\n=== Contrastive Dataset Validation ===")
        try:
            val_info = runner.validate_datasets()
            print(f"  Status: {val_info['status']}")
            print(f"  Dev Dataset: {val_info['dev_path']} ({val_info['dev_count']} examples)")
            print(f"  Dev Hash: {val_info['dev_hash']}")
            print(f"  Dev Families: {val_info['dev_families']}")
            print(f"  Test Dataset: {val_info['test_path']} ({val_info['test_count']} examples)")
            print(f"  Test Hash: {val_info['test_hash']}")
            print(f"  Test Families: {val_info['test_families']}")
            print(f"  Template Disjoint: {val_info['template_disjoint']}")
            print("\nDataset validation PASSED with zero template leakage.")
            return 0
        except Exception as e:
            print(f"\nERROR: Dataset validation failed: {e}")
            return 1

    # 3. Setup configuration
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"ERROR: Config file not found: {config_path}")
            return 1
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = CircuitExperimentConfig.from_dict(json.load(f))
    else:
        cfg = CircuitExperimentConfig(
            algorithm=args.algorithm,
            sparsity=args.sparsity,
            split=args.split,
            output_dir=args.out_dir,
            allow_intervention=args.intervention,
        )

    print("\n=======================================================")
    print("TraceGuard Module 8: CircuitKIT Interpretability Runner")
    print("=======================================================")
    print(f"Target Split:      {cfg.split}")
    print(f"Algorithm:         {cfg.algorithm}")
    print(f"Target Sparsity:   {cfg.sparsity}")
    print(f"Pillars:           {cfg.pillars}")
    print(f"Output Directory:  {cfg.output_dir}")
    print(f"Intervention:      {cfg.allow_intervention}")
    print(f"Execution Mode:    {'MOCK' if args.mock else 'DRY-RUN / NOT_RUN' if args.dry_run else 'DEFAULT'}")
    print("-------------------------------------------------------")

    pipeline = None
    if args.mock:
        print("[INFO] Initializing MockCircuitPipeline...")
        pipeline = MockCircuitPipeline(output_dir=cfg.output_dir)

    try:
        summary = runner.run(cfg, pipeline=pipeline)
    except Exception as e:
        print(f"\n[ERROR] Experiment execution failed: {e}")
        return 1

    print("\n=== Experiment Execution Results ===")
    print(f"Overall Status:    {summary.status}")
    print(f"Dataset Hash:      {summary.dataset_hash}")
    print(f"Examples Count:    {summary.n_examples}")
    print(f"Discovery Status:  {summary.discovery.status}")
    if summary.discovery.status == "SUCCESS":
        print(f"  Nodes Discovered: {summary.discovery.n_nodes}")
        print(f"  Node Names:       {summary.discovery.node_names}")
        print(f"  Execution Time:   {summary.discovery.execution_time_seconds}s")
    else:
        print(f"  Reason:           {summary.discovery.error_message}")

    print(f"Faithfulness:      {summary.faithfulness.status}")
    if summary.faithfulness.status == "SUCCESS":
        print(f"  Patching Score:   {summary.faithfulness.patching_score}")
        print(f"  Ablation Score:   {summary.faithfulness.ablation_score}")
        print(f"  Overall Faith:    {summary.faithfulness.overall_faithfulness}")
    else:
        print(f"  Reason:           {summary.faithfulness.error_message}")

    print(f"Intervention:      {summary.intervention.status}")
    if summary.intervention.status == "SUCCESS":
        print(f"  Delta Safety:     {summary.intervention.delta_safety}")
        print(f"  Delta Utility:    {summary.intervention.delta_clean_utility}")
    else:
        print(f"  Reason:           {summary.intervention.error_message}")

    print(f"\nResults saved to: {Path(cfg.output_dir).resolve()}")
    print("=======================================================\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
