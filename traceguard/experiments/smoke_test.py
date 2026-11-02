"""T01-T10 model smoke-test runner (Responsibility B).

Runs every task against one backend (real transformers model or scripted
mock), scores deterministically, enforces the acceptance gate
(**>= 8/10 passed AND zero critical safety failures** — fixed by config, not
overridable from the CLI), and writes four artifacts:

* ``raw_outputs.jsonl``  — one line per task: raw text, latency, tokens, parse
  result, outcome (raw model outputs saved separately from structured results)
* ``results.json``       — per-task outcomes + aggregate acceptance result
* ``manifest.json``      — reproducibility manifest
* ``errors.log``         — structured log of the whole run

Exit codes: 0 = accepted, 2 = not accepted, 1 = infrastructure error.

Example (sandbox, no GPU, ungated tiny model — infrastructure check ONLY)::

    python -m traceguard.experiments.smoke_test \
        --model hf-internal-testing/tiny-random-gpt2 \
        --out results/smoke/tiny-random-gpt2/

Example (Colab, real gated model)::

    export HF_TOKEN=...   # never hardcode
    python -m traceguard.experiments.smoke_test \
        --model primary --out results/smoke/tiny-aya-global/
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from traceguard.experiments.manifest import build_manifest, write_manifest
from traceguard.experiments.scoring import (
    AcceptanceResult,
    SmokeTask,
    evaluate_acceptance,
    score_task,
)
from traceguard.models.config import load_app_config, resolve_path
from traceguard.models.generation import GenerationBackend, GenerationSettings
from traceguard.models.json_parser import ToolRegistry, load_tool_registry
from traceguard.models.mock_backend import ScriptedMockBackend
from traceguard.models.prompt_builder import TaskSetup, build_messages

logger = logging.getLogger("traceguard.smoke")

DATASET_META = {
    "name": "traceguard-smoke-tasks",
    "version": "1.0",
    "split": "smoke",
    "description": "T01-T10 initial model acceptance tasks (master prompt §B)",
}


def load_smoke_tasks(path: str | Path) -> list[SmokeTask]:
    """Load and validate the smoke-task JSONL dataset."""
    path = Path(path)
    tasks: list[SmokeTask] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON ({exc})") from exc
            task = SmokeTask.from_dict(doc)
            if task.task_id in seen:
                raise ValueError(f"{path}:{line_no}: duplicate task_id {task.task_id!r}")
            seen.add(task.task_id)
            tasks.append(task)
    if not tasks:
        raise ValueError(f"{path}: no tasks found")
    return tasks


def _configure_logging(out_dir: Path) -> Path:
    """Structured logging to stderr + ``errors.log`` inside the artifact dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "errors.log"
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z"
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in list(root.handlers):  # avoid duplicate handlers on re-entry
        root.removeHandler(handler)
    stderr = logging.StreamHandler(sys.stderr)
    stderr.setFormatter(fmt)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    root.addHandler(stderr)
    root.addHandler(file_handler)
    return log_path


def run_smoke(
    tasks: Sequence[SmokeTask],
    registry: ToolRegistry,
    backend: GenerationBackend,
    out_dir: str | Path,
    settings: GenerationSettings,
    min_pass: int = 8,
    critical_failures_allowed: int = 0,
    seed: int = 1234,
    configuration_name: str = "smoke",
    dataset_meta: Optional[dict[str, Any]] = None,
) -> AcceptanceResult:
    """Execute the full smoke test and persist all artifacts. Returns the gate."""
    out_dir = Path(out_dir)
    _configure_logging(out_dir)
    random.seed(seed)
    try:
        import torch

        torch.manual_seed(seed)
    except ImportError:  # mock-only runs do not need torch
        pass

    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    experiment_id = f"smoke-{started_at.replace(':', '').replace('-', '')}"
    logger.info(
        "smoke run start experiment_id=%s backend=%s tasks=%d min_pass=%d",
        experiment_id,
        backend.name,
        len(tasks),
        min_pass,
    )

    raw_path = out_dir / "raw_outputs.jsonl"
    outcomes = []
    with raw_path.open("w", encoding="utf-8") as raw_fh:
        for task in tasks:
            setup = TaskSetup.from_dict(task.setup)
            messages = build_messages(task.user_message, registry, setup)
            record = backend.generate(messages)
            outcome = score_task(task, record, registry)
            outcomes.append(outcome)
            raw_line = {
                "task_id": task.task_id,
                "record": record.to_dict(),
                "outcome": outcome.to_dict(),
            }
            raw_fh.write(json.dumps(raw_line, ensure_ascii=False) + "\n")
            logger.info(
                "task=%s passed=%s critical=%s parse_ok=%s latency_s=%s violations=%s",
                task.task_id,
                outcome.passed,
                outcome.critical_failure,
                outcome.parse_ok,
                record.latency_seconds,
                list(outcome.violations),
            )

    acceptance = evaluate_acceptance(outcomes, min_pass, critical_failures_allowed)
    finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    results_path = out_dir / "results.json"
    with results_path.open("w", encoding="utf-8") as fh:
        json.dump(acceptance.to_dict(), fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    manifest = build_manifest(
        experiment_id=experiment_id,
        configuration_name=configuration_name,
        backend_description=backend.describe(),
        generation_settings=asdict(settings),
        dataset={**(dataset_meta or DATASET_META), "path": str(resolve_path("traceguard/configs/smoke_tasks.jsonl"))},
        seed=seed,
        started_at=started_at,
        finished_at=finished_at,
        artifact_paths=[str(raw_path), str(results_path), str(out_dir / "errors.log")],
    )
    manifest_path = write_manifest(manifest, out_dir)

    logger.info(
        "smoke run done: passed=%d/%d critical=%d parse_failures=%d accepted=%s",
        acceptance.passed,
        acceptance.total,
        acceptance.critical_failures,
        acceptance.parse_failures,
        acceptance.accepted,
    )
    logger.info("artifacts: %s %s %s", raw_path, results_path, manifest_path)
    return acceptance


def _build_backend(args: argparse.Namespace, settings: GenerationSettings) -> GenerationBackend:
    """Instantiate the backend requested on the command line."""
    if args.backend == "mock":
        if not args.mock_script:
            raise SystemExit("--backend mock requires --mock-script <jsonl>")
        task_ids = [t for t in _task_ids(args)]
        return ScriptedMockBackend.from_jsonl(args.mock_script, task_ids, settings)

    from traceguard.models.loader import load_transformers_backend

    config = load_app_config(args.config)
    model_ref = config.models.get(args.model)
    model_id = model_ref.id if model_ref else args.model
    revision = args.revision or (model_ref.revision if model_ref else None)
    if not revision:
        logger.warning(
            "No pinned revision for %s; results will record revision=null "
            "(pin a sha for reproducible experiments)",
            model_id,
        )
    return load_transformers_backend(
        model_id=model_id,
        revision=revision,
        device=args.device,
        dtype=args.dtype,
        load_in_4bit=args.load_in_4bit,
        settings=settings,
    )


def _task_ids(args: argparse.Namespace) -> Sequence[str]:
    config = load_app_config(args.config)
    tasks_path = args.tasks or (config.smoke.tasks_path if config.smoke else None)
    if not tasks_path:
        raise SystemExit("no tasks path (pass --tasks or configure smoke.tasks_path)")
    return [t.task_id for t in load_smoke_tasks(tasks_path)]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TraceGuard T01-T10 model smoke test")
    parser.add_argument(
        "--model",
        default="primary",
        help="model alias from model_config.yaml (primary/fallback/sandbox_probe) "
        "or a literal HF hub id",
    )
    parser.add_argument("--revision", default=None, help="override pinned model revision")
    parser.add_argument("--config", default=None, help="path to model_config.yaml")
    parser.add_argument("--tasks", default=None, help="path to smoke_tasks.jsonl")
    parser.add_argument("--tools", default=None, help="path to tools.yaml")
    parser.add_argument("--out", default=None, help="artifact output directory")
    parser.add_argument(
        "--backend",
        choices=("auto", "mock"),
        default="auto",
        help="'auto' = transformers; 'mock' = scripted responses (testing only)",
    )
    parser.add_argument("--mock-script", default=None, help="JSONL script for --backend mock")
    parser.add_argument("--device", default="auto", choices=("auto", "cpu", "cuda"))
    parser.add_argument("--dtype", default="auto", choices=("auto", "bfloat16", "float16", "float32"))
    parser.add_argument("--load-in-4bit", action="store_true", help="bitsandbytes NF4 (CUDA only)")
    parser.add_argument("--max-new-tokens", type=int, default=None)
    args = parser.parse_args(argv)

    config = load_app_config(args.config)
    gen_doc = dict(config.generation)
    if args.max_new_tokens is not None:
        gen_doc["max_new_tokens"] = args.max_new_tokens
    settings = GenerationSettings(
        max_new_tokens=int(gen_doc.get("max_new_tokens", 512)),
        seed=int(config.defaults.get("seed", 1234)),
    )

    smoke_cfg = config.smoke
    tasks_path = args.tasks or (smoke_cfg.tasks_path if smoke_cfg else None)
    tools_path = args.tools or (smoke_cfg.tools_path if smoke_cfg else None)
    if not tasks_path or not tools_path:
        print("error: tasks/tools paths unresolved", file=sys.stderr)
        return 1
    tasks = load_smoke_tasks(tasks_path)
    registry: ToolRegistry = load_tool_registry(tools_path)

    model_alias = config.models.get(args.model)
    out_dir = Path(
        args.out
        or config.results_dir
        / "smoke"
        / (args.model if not model_alias else model_alias.id.replace("/", "__"))
    )

    try:
        backend = _build_backend(args, settings)
    except Exception as exc:
        print(f"error: backend construction failed: {exc}", file=sys.stderr)
        return 1

    if smoke_cfg is None:
        print("error: no [smoke] section in config", file=sys.stderr)
        return 1
    acceptance = run_smoke(
        tasks=tasks,
        registry=registry,
        backend=backend,
        out_dir=out_dir,
        settings=settings,
        min_pass=smoke_cfg.min_pass,
        critical_failures_allowed=smoke_cfg.critical_failures_allowed,
        seed=settings.seed,
        configuration_name=f"smoke:{args.model}",
    )
    print(
        json.dumps(
            {
                "accepted": acceptance.accepted,
                "passed": f"{acceptance.passed}/{acceptance.total}",
                "critical_failures": acceptance.critical_failures,
                "parse_failures": acceptance.parse_failures,
                "artifacts": str(out_dir),
            },
            indent=2,
        )
    )
    return 0 if acceptance.accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
