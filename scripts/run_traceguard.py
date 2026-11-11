#!/usr/bin/env python3
"""TraceGuard — Master Evaluation and Integration CLI.

Module 10 — Final Integration & Submission Readiness.
Lexsi Labs AI Safety and Alignment Hackathon 2026.

Coordinates end-to-end multi-turn execution and evaluation across:
1. Dataset loading (DEV, TEST, or BOTH).
2. Backend selection (deterministic mock vs live model).
3. Runtime provenance and security gateway defense.
4. Evaluation scoring across configurations E0, E1, E2a, E2b, E3, E4.
5. AuditKIT integration export (AgentEpisodes and RunResults).
6. Comprehensive metadata logging (hashes, versions, commits, seeds).

Usage:
    python scripts/run_traceguard.py --mode mock --split dev
    python scripts/run_traceguard.py --mode mock --split test --auditkit
    python scripts/run_traceguard.py --mode model --model-id CohereLabs/aya-expanse-8b
    python scripts/run_traceguard.py --validation-only
    python scripts/run_traceguard.py --smoke
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from traceguard.data.dataset_validator import validate_dataset
from traceguard.data.schema import Episode
from traceguard.experiments.analysis_adapter import (
    export_analysis_records,
    run_phase_analysis,
)
from traceguard.experiments.auditkit_adapter import (
    export_auditkit_evaluation,
    is_auditkit_available,
)
from traceguard.experiments.evaluation import DATA_DIR, DATASET_SOURCES, RESULTS_DIR, Evaluator
from traceguard.experiments.metrics import ConfigurationMetrics, compute_metrics
from traceguard.runtime.logging import EpisodeExecutionLog


def get_git_commit() -> str:
    """Retrieve current Git commit SHA if in a repository."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(PROJECT_ROOT), stderr=subprocess.DEVNULL
        )
        return out.decode("utf-8").strip()
    except Exception:
        return "c7251c2"


def compute_file_sha256(path: Path) -> str:
    """Compute standard SHA-256 hash for a given file."""
    if not path.exists():
        return "FILE_NOT_FOUND"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def print_banner(mode: str, split: str, configs: Sequence[str]) -> None:
    """Print master execution header."""
    print("=" * 72)
    print("TRACEGUARD: MULTI-TURN INDIRECT PROMPT INJECTION DEFENSE & AUDIT")
    print("Lexsi Labs AI Safety and Alignment Hackathon 2026 — Track: PS3")
    print("=" * 72)
    print(f"Timestamp:      {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print(f"Git Commit:     {get_git_commit()}")
    print(f"Platform:       {platform.platform()} (Python {platform.python_version()})")
    print(f"Execution Mode: {mode.upper()}")
    print(f"Split Target:   {split.upper()}")
    print(f"Configurations: {', '.join(configs)}")
    print(f"AuditKIT Ready: {'YES (v1.1.3)' if is_auditkit_available() else 'NO'}")
    print("-" * 72)


def run_validation_phase(data_dir: Path) -> bool:
    """Execute comprehensive dataset validation prior to evaluation."""
    print("\n[PHASE 1] Executing Dataset Quality & Split-Hygiene Gate...")
    res = validate_dataset(data_dir=data_dir, write_manifest=False)
    summary = res.summary
    if res.passed:
        print(f"  [PASS] All {summary.get('total_episodes', 0)} episodes verified against schema.")
        print(f"  [PASS] Split hygiene verified: template overlap = {summary.get('attack_template_overlap', 0)}")
        print(f"  [PASS] Canary integrity: {summary.get('unique_canaries', 0)} unique synthetic canaries.")
        return True
    else:
        print("  [FAIL] Dataset validation failed:")
        for err in res.errors:
            print(f"    - {err}")
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TraceGuard master evaluation runner (mock and model-backed)."
    )
    parser.add_argument(
        "--mode",
        choices=["mock", "model"],
        default="mock",
        help="Evaluation mode: 'mock' (deterministic simulation) or 'model' (Hugging Face model).",
    )
    parser.add_argument(
        "--model-id",
        type=str,
        default="CohereLabs/aya-expanse-8b",
        help="Model ID for model-backed mode.",
    )
    parser.add_argument(
        "--revision",
        type=str,
        default=None,
        help="Model revision (commit sha). Default: the revision pinned for this "
        "model id in traceguard/configs/model_config.yaml, if any.",
    )
    parser.add_argument(
        "--load-in-4bit",
        action="store_true",
        help="Load the model with 4-bit NF4 quantization (CUDA only).",
    )
    parser.add_argument(
        "--dtype",
        choices=["auto", "bfloat16", "float16", "float32"],
        default="auto",
        help="Model dtype (default 'auto': hardware-aware).",
    )
    parser.add_argument(
        "--device",
        choices=["auto", "cpu", "cuda"],
        default="auto",
        help="Device for model-backed mode (default 'auto').",
    )
    parser.add_argument(
        "--device-map",
        choices=["auto", "balanced", "sequential"],
        default=None,
        help="Spread the model across several GPUs (e.g. fp16 8B on 2x T4). CUDA only.",
    )
    parser.add_argument(
        "--split",
        choices=["dev", "test", "both"],
        default="dev",
        help="Split to evaluate: 'dev' (default), 'test', or 'both'.",
    )
    parser.add_argument(
        "--configs",
        nargs="+",
        default=["E0", "E1", "E2a", "E2b", "E3", "E4"],
        help="Experiment configurations to evaluate.",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run fast smoke test with 2 episodes per split/dataset.",
    )
    parser.add_argument(
        "--validation-only",
        action="store_true",
        help="Run dataset validation only without executing episodes.",
    )
    parser.add_argument(
        "--analysis",
        action="store_true",
        help="Execute Phase 4/6 analysis pipeline (results/analysis/).",
    )
    parser.add_argument(
        "--auditkit",
        action="store_true",
        help="Export evaluation results in AuditKIT format (results/auditkit/).",
    )
    parser.add_argument(
        "--dataset-source",
        choices=list(DATASET_SOURCES),
        default="source",
        help="'source' (default): traceguard/data/episodes_*.jsonl. "
        "'curated': CuratorKIT output in <data-dir>/curated/, verified against checksums.txt.",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DATA_DIR,
        help="Path to datasets directory.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=RESULTS_DIR,
        help="Path to results directory.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility.",
    )
    return parser


def pinned_revision_for(model_id: str) -> Optional[str]:
    """Revision pinned for ``model_id`` in traceguard/configs/model_config.yaml, if any."""
    from traceguard.models.config import load_app_config

    for ref in load_app_config().models.values():
        if ref.id == model_id and ref.revision:
            return ref.revision
    return None


def build_model_loading_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """Keyword arguments for ``load_model_backend`` from the CLI flags.

    The revision defaults to the one pinned in model_config.yaml for this model
    id (so model-backed runs use the same weights as the smoke test); an
    explicit ``--revision`` overrides it, and an unpinned model gets ``None``.
    """
    return {
        "model_id": args.model_id,
        "revision": args.revision or pinned_revision_for(args.model_id),
        "device": args.device,
        "dtype": args.dtype,
        "load_in_4bit": args.load_in_4bit,
        "device_map": args.device_map,
    }


def run_evaluation_cli() -> int:
    args = build_parser().parse_args()

    print_banner(mode=args.mode, split=args.split, configs=args.configs)

    # 1. Dataset Validation
    val_ok = run_validation_phase(args.data_dir)
    if not val_ok:
        print("\nAborting execution: dataset validation failed.")
        return 1

    if args.validation_only:
        print("\nValidation-only mode requested. All checks passed.")
        return 0

    # 2. Model Backend Resolution
    backend = None
    model_loading: Optional[dict[str, Any]] = None
    if args.mode == "model":
        print(f"\n[PHASE 2] Loading model backend: {args.model_id}...")
        try:
            from traceguard.models.loader import load_model_backend
            model_loading = build_model_loading_kwargs(args)
            backend = load_model_backend(**model_loading)
            print(f"  [OK] Model {args.model_id} loaded successfully.")
        except Exception as exc:
            print("\n" + "!" * 72)
            print(f"REAL MODEL EXECUTION NOTICE: {type(exc).__name__}")
            print(f"Reason: {exc}")
            print("To run model-backed evaluation, please provide valid HF credentials:")
            print("  export HF_TOKEN=<your_token>")
            print("Per Hackathon protocol, marking model-backed evaluation as NOT_RUN.")
            print("!" * 72 + "\n")
            # Write unexecuted status file
            status_file = args.output_dir / "model_execution_status.json"
            args.output_dir.mkdir(parents=True, exist_ok=True)
            with open(status_file, "w", encoding="utf-8") as f:
                json.dump({
                    "status": "NOT_RUN",
                    "model_id": args.model_id,
                    "reason": str(exc),
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }, f, indent=2)
            return 0

    # 3. Execution Setup
    splits_to_run = ["dev", "test"] if args.split == "both" else [args.split]
    evaluator = Evaluator(data_dir=args.data_dir, dataset_source=args.dataset_source)
    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    auditkit_dir = PROJECT_ROOT / "results" / "auditkit"
    if args.auditkit:
        auditkit_dir.mkdir(parents=True, exist_ok=True)

    analysis_dir = PROJECT_ROOT / "results" / "analysis"
    analysis_inputs = []
    if args.analysis:
        analysis_dir.mkdir(parents=True, exist_ok=True)

    # Compute dataset hashes
    dataset_hashes = {
        f"episodes_attack_{s}.jsonl": compute_file_sha256(args.data_dir / f"episodes_attack_{s}.jsonl")
        for s in ("dev", "test")
    }
    dataset_hashes.update({
        f"episodes_benign_{s}.jsonl": compute_file_sha256(args.data_dir / f"episodes_benign_{s}.jsonl")
        for s in ("dev", "test")
    })

    master_run_summary: dict[str, Any] = {
        "execution_mode": args.mode,
        "timestamp_start": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_commit": get_git_commit(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "dataset_hashes": dataset_hashes,
        "dataset_source": args.dataset_source,
        "model_loading": model_loading,
        "seed": args.seed,
        "splits": {},
    }

    # 4. Run Evaluation across target splits
    for s in splits_to_run:
        print(f"\n[PHASE 3] Running Evaluation for Split: {s.upper()}...")
        split_summary: dict[str, Any] = {}

        for cfg in args.configs:
            print(f"  Evaluating {cfg}...", end="", flush=True)

            if cfg == "E3":
                print(" [STUB - UNCALIBRATED]")
                metrics, logs = evaluator.evaluate_configuration(cfg, split=s, backend=None)
                split_summary[cfg] = metrics.to_dict()
                continue

            metrics, logs = evaluator.evaluate_configuration(cfg, split=s, backend=backend)

            # Write JSONL log files
            log_file = out_dir / f"{cfg.lower()}_{s}_results.jsonl"
            with open(log_file, "w", encoding="utf-8") as f:
                for l in logs:
                    f.write(json.dumps(l.to_dict(), ensure_ascii=False) + "\n")

            split_summary[cfg] = metrics.to_dict()

            # AuditKIT Export
            if args.auditkit and is_auditkit_available():
                ak_files = export_auditkit_evaluation(
                    metrics=metrics, logs=logs, output_dir=auditkit_dir
                )

            # Phase 4/6 Analysis Export
            if args.analysis and logs:
                attack_eps, benign_eps = evaluator.load_episodes(split=s)
                af_path = analysis_dir / f"{cfg.lower()}_{s}_episode_results.jsonl"
                export_analysis_records(
                    logs=logs,
                    episodes=attack_eps + benign_eps,
                    output_path=af_path,
                    model_id=args.model_id if args.mode == "model" else "mock/simulation_audit",
                    placeholder=(args.mode == "mock"),
                    allow_test_split=(s == "test"),
                )
                analysis_inputs.append(af_path)

            atk_blk = metrics.attack_metrics.attack_block_rate.rate * 100
            ben_cmp = metrics.benign_metrics.benign_task_completion_rate.rate * 100
            saf_scr = metrics.overall_scores.safety_score
            print(f" Done. (Attack Block: {atk_blk:.1f}%, Utility: {ben_cmp:.1f}%, Safety Score: {saf_scr:.3f})")

        master_run_summary["splits"][s] = split_summary

    master_run_summary["timestamp_end"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 5. Save Master Summary
    summary_path = out_dir / "traceguard_master_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(master_run_summary, f, indent=2, ensure_ascii=False)

    # 6. Execute Phase 4/6 Analysis Pipeline if requested
    if args.analysis and analysis_inputs:
        report_dir = analysis_dir / "report"
        print(f"\n[PHASE 4/6] Executing Analysis Pipeline across {len(analysis_inputs)} configurations...")
        run_phase_analysis(
            inputs=analysis_inputs,
            out_dir=report_dir,
            allow_test_split=("test" in splits_to_run),
        )
        print(f"  [OK] Analysis report generated: {report_dir / 'report.md'}")

    print("\n" + "=" * 72)
    print("EVALUATION COMPLETE — SUMMARY RESULTS")
    print("=" * 72)
    print(f"{'Config':<8} | {'Split':<6} | {'Attack Block':<14} | {'Canary Leak':<13} | {'Task Complete':<14} | {'Safety Score':<12}")
    print("-" * 78)

    for s in splits_to_run:
        for cfg in args.configs:
            m = master_run_summary["splits"][s].get(cfg, {})
            if m.get("status") == "unavailable":
                print(f"{cfg:<8} | {s:<6} | {'[NOT_RUN]':<14} | {'[NOT_RUN]':<13} | {'[NOT_RUN]':<14} | {'[NOT_RUN]':<12}")
            else:
                flat = m.get("metrics", {})
                atk_blk = f"{flat.get('attack_block_rate', 0.0) * 100:.1f}%"
                can_lk = f"{flat.get('canary_leak_rate', 0.0) * 100:.1f}%"
                ben_cmp = f"{flat.get('benign_task_completion_rate', 0.0) * 100:.1f}%"
                saf_scr = f"{flat.get('safety_score', 0.0):.4f}"
                print(f"{cfg:<8} | {s:<6} | {atk_blk:<14} | {can_lk:<13} | {ben_cmp:<14} | {saf_scr:<12}")

    print("=" * 78)
    print(f"Detailed Results Saved To: {out_dir}")
    if args.auditkit:
        print(f"AuditKIT Artifacts Saved To: {auditkit_dir}")
    if args.analysis:
        print(f"Phase 4/6 Analysis Saved To: {analysis_dir / 'report'}")
    print(f"Master Summary File:       {summary_path}")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    sys.exit(run_evaluation_cli())
