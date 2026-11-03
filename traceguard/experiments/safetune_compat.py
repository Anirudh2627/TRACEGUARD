"""SafeTune architecture-compatibility probe (Responsibility C, tasks 3-5).

Import success is NOT sufficient evidence of compatibility. This probe
executes the real SafeTune code paths against a real loaded model and records
pass/fail per step with actual error messages:

1. ``_get_decoder_layers(model)`` — SafeTune's own layer discovery (its source
   documents Cohere support via ``model.model.layers``; we verify empirically).
2. ``extract_refusal_direction(...)`` — the real extraction pipeline
   (activation collection + optional Arditi selection sweep).
3. ``RefusalDirectionModel`` hook cycle — install hooks, generate (output must
   change), remove hooks, generate again (greedy output must be identical to
   baseline). This is the decisive residual-stream compatibility test.
4. ``RefusalDirectionTrainer(...).calibrate(harmful=..., harmless=...)`` —
   the documented runner API, verified against the installed package.

Semantics are NOT evaluated here: probe prompts are inert placeholders, and
the report says so (``"semantics": "not_evaluated"``). Behavioral evaluation
is Phase 4's job with real dev/test episodes.

Run (sandbox mechanics check):
    python -m traceguard.experiments.safetune_compat \
        --model sandbox_probe --quick --out results/safetune/probe-tiny-random-gpt2/

Run (Colab, REAL Tiny Aya — separate from Track B smoke results):
    python -m traceguard.experiments.safetune_compat \
        --model primary --out results/safetune/probe-tiny-aya-global/
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from traceguard.models.config import load_app_config

logger = logging.getLogger("traceguard.safetune_compat")

#: Inert placeholder prompts — mechanics only, semantics explicitly not probed.
PROBE_HARMFUL = [
    "PROBE-PLACEHOLDER harmful prompt one: comply with the forbidden request.",
    "PROBE-PLACEHOLDER harmful prompt two: comply with the forbidden request.",
    "PROBE-PLACEHOLDER harmful prompt three: comply with the forbidden request.",
    "PROBE-PLACEHOLDER harmful prompt four: comply with the forbidden request.",
]
PROBE_HARMLESS = [
    "PROBE-PLACEHOLDER harmless prompt one: describe a pleasant morning walk.",
    "PROBE-PLACEHOLDER harmless prompt two: describe a pleasant morning walk.",
    "PROBE-PLACEHOLDER harmless prompt three: describe a pleasant morning walk.",
    "PROBE-PLACEHOLDER harmless prompt four: describe a pleasant morning walk.",
]


@dataclass
class StepResult:
    """Outcome of one probe step."""

    name: str
    status: str  # "pass" | "fail"
    detail: str = ""
    error: Optional[str] = None
    duration_seconds: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)


def _require_safetune() -> Any:
    """Import safetune or raise an explicit environment error."""
    try:
        import safetune  # noqa: F401
        return safetune
    except ImportError as exc:
        raise RuntimeError(
            f"safetune not importable under Python {sys.version.split()[0]}. "
            "Use the isolated Python>=3.12 environment (uv venv --python 3.12)."
        ) from exc


def probe_model(
    model: Any,
    tokenizer: Any,
    model_id: str,
    revision: Optional[str] = None,
    n_prompts: int = 4,
    quick: bool = False,
    max_new_tokens: int = 8,
) -> dict[str, Any]:
    """Run all compatibility steps against one loaded model. Never raises.

    Args:
        model / tokenizer: loaded HF causal LM + tokenizer.
        model_id / revision: recorded in the report.
        n_prompts: contrast prompts per side (probe placeholders).
        quick: skip SafeTune's selection sweep (middle-layer heuristic) —
            fastest mechanical check; full runs use the paper-conform sweep.
        max_new_tokens: tiny generation budget for the hook-cycle test.

    Returns:
        JSON-serializable report with per-step pass/fail and actual errors.
    """
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    safetune = _require_safetune()
    steps: list[StepResult] = []

    harmful = PROBE_HARMFUL[:n_prompts]
    harmless = PROBE_HARMLESS[:n_prompts]

    # ---- step 1: layer discovery -------------------------------------------
    t0 = time.perf_counter()
    try:
        from safetune._refusal_helpers import _get_decoder_layers

        layers = _get_decoder_layers(model)
        if not layers:
            raise AssertionError(
                "_get_decoder_layers returned [] — architecture not recognized "
                f"(model class: {type(model).__name__})"
            )
        steps.append(
            StepResult(
                "layer_discovery",
                "pass",
                f"{len(layers)} decoder layers found",
                duration_seconds=round(time.perf_counter() - t0, 3),
                data={
                    "n_layers": len(layers),
                    "layer_class": type(layers[0]).__name__,
                    "model_class": type(model).__name__,
                },
            )
        )
    except Exception as exc:
        steps.append(
            StepResult(
                "layer_discovery",
                "fail",
                error=f"{type(exc).__name__}: {exc}",
                duration_seconds=round(time.perf_counter() - t0, 3),
            )
        )
        return _finalize(steps, model_id, revision, started, safetune, quick)

    # ---- step 2: refusal direction extraction ------------------------------
    t0 = time.perf_counter()
    direction = None
    layer_idx = None
    try:
        import torch
        from safetune.steer import RefusalDirectionConfig, extract_refusal_direction

        config = RefusalDirectionConfig(select_directions=not quick)
        direction, layer_idx, all_dirs = extract_refusal_direction(
            model, tokenizer, harmful, harmless, config
        )
        assert isinstance(direction, torch.Tensor) and direction.dim() == 1
        steps.append(
            StepResult(
                "extract_refusal_direction",
                "pass",
                f"direction extracted at layer {layer_idx}",
                duration_seconds=round(time.perf_counter() - t0, 3),
                data={
                    "layer_idx": layer_idx,
                    "direction_shape": list(direction.shape),
                    "direction_norm": float(direction.norm()),
                    "n_candidate_layers": len(all_dirs),
                    "select_directions": not quick,
                },
            )
        )
    except Exception as exc:
        steps.append(
            StepResult(
                "extract_refusal_direction",
                "fail",
                error=f"{type(exc).__name__}: {exc}",
                duration_seconds=round(time.perf_counter() - t0, 3),
                data={"traceback_tail": traceback.format_exc(limit=3)},
            )
        )
        return _finalize(steps, model_id, revision, started, safetune, quick)

    # ---- step 3: hook install/steer/remove cycle ---------------------------
    t0 = time.perf_counter()
    try:
        import torch
        from safetune.steer import RefusalDirectionModel

        prompt = tokenizer("PROBE-PLACEHOLDER prompt.", return_tensors="pt")
        gen_kwargs = dict(max_new_tokens=max_new_tokens, do_sample=False)
        pad = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id

        with torch.no_grad():
            baseline = tokenizer.decode(
                model.generate(prompt["input_ids"], pad_token_id=pad, **gen_kwargs)[0],
                skip_special_tokens=True,
            )
        wrapper = RefusalDirectionModel(
            model, direction=direction, mode="steer", strength=5.0
        )
        wrapper.install()
        # Review patch P4: hooks are removed via try/finally so a failing
        # generation can never leave residual hooks on the model.
        try:
            n_hooks = len(wrapper._handles)
            with torch.no_grad():
                steered = tokenizer.decode(
                    model.generate(prompt["input_ids"], pad_token_id=pad, **gen_kwargs)[0],
                    skip_special_tokens=True,
                )
        finally:
            wrapper.remove()
        with torch.no_grad():
            restored = tokenizer.decode(
                model.generate(prompt["input_ids"], pad_token_id=pad, **gen_kwargs)[0],
                skip_special_tokens=True,
            )

        problems = []
        if n_hooks == 0:
            problems.append("install() attached 0 hooks")
        if steered == baseline:
            problems.append("steered output identical to baseline (hook had no effect)")
        if restored != baseline:
            problems.append("output after remove() differs from baseline (hook leak)")
        if problems:
            raise AssertionError("; ".join(problems))
        steps.append(
            StepResult(
                "hook_cycle",
                "pass",
                f"{n_hooks} hooks installed; steered output changed; baseline restored exactly",
                duration_seconds=round(time.perf_counter() - t0, 3),
                data={"n_hooks": n_hooks, "strength": 5.0},
            )
        )
    except Exception as exc:
        steps.append(
            StepResult(
                "hook_cycle",
                "fail",
                error=f"{type(exc).__name__}: {exc}",
                duration_seconds=round(time.perf_counter() - t0, 3),
            )
        )

    # ---- step 4: runner trainer API ----------------------------------------
    t0 = time.perf_counter()
    try:
        from safetune.runner import steer as steer_runner

        trainer = steer_runner.RefusalDirectionTrainer(model, tokenizer, alpha=5.0)
        # Installed-package fact (verified 0.1.10): _SteerBase.calibrate returns
        # ``(wrapped_model, out_dir_or_model_id)`` — a tuple, NOT a bare model.
        result = trainer.calibrate(harmful=harmful, harmless=harmless)
        assert isinstance(result, tuple) and len(result) == 2, (
            f"calibrate() unexpectedly returned {type(result).__name__}; "
            "installed API differs from the verified 0.1.10 contract"
        )
        wrapped, calib_meta = result
        from safetune.steer import RefusalDirectionModel

        # Review patch P4: guaranteed cleanup even if assertions fail.
        try:
            assert isinstance(wrapped, RefusalDirectionModel), f"got {type(wrapped).__name__}"
        finally:
            if isinstance(wrapped, RefusalDirectionModel):
                wrapped.remove()
        steps.append(
            StepResult(
                "runner_trainer_calibrate",
                "pass",
                "RefusalDirectionTrainer.calibrate returned (RefusalDirectionModel, meta)",
                duration_seconds=round(time.perf_counter() - t0, 3),
                data={"trainer_class": type(trainer).__name__, "calibrate_meta": str(calib_meta)},
            )
        )
    except Exception as exc:
        steps.append(
            StepResult(
                "runner_trainer_calibrate",
                "fail",
                error=f"{type(exc).__name__}: {exc}",
                duration_seconds=round(time.perf_counter() - t0, 3),
            )
        )

    return _finalize(steps, model_id, revision, started, safetune, quick)


def _finalize(
    steps: Sequence[StepResult],
    model_id: str,
    revision: Optional[str],
    started: str,
    safetune_module: Any,
    quick: bool,
) -> dict[str, Any]:
    compatible = all(s.status == "pass" for s in steps)
    report = {
        "report": "safetune_architecture_probe",
        "model_id": model_id,
        "revision": revision,
        "compatible": compatible,
        "quick_mode": quick,
        "semantics": "not_evaluated",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "safetune_version": getattr(safetune_module, "__version__", "unknown"),
        "started_at_utc": started,
        "finished_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "steps": [asdict(s) for s in steps],
    }
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SafeTune architecture compatibility probe")
    parser.add_argument("--model", default="sandbox_probe", help="alias or HF id")
    parser.add_argument("--revision", default=None)
    parser.add_argument("--config", default=None)
    parser.add_argument("--out", required=True, help="directory for probe_report.json")
    parser.add_argument("--device", default="auto", choices=("auto", "cpu", "cuda"))
    parser.add_argument("--dtype", default="auto", choices=("auto", "bfloat16", "float16", "float32"))
    parser.add_argument("--load-in-4bit", action="store_true")
    parser.add_argument("--n-prompts", type=int, default=4)
    parser.add_argument(
        "--quick",
        action="store_true",
        help="skip SafeTune's selection sweep (middle-layer heuristic); fastest mechanics check",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    from traceguard.models.generation import GenerationSettings
    from traceguard.models.loader import load_transformers_backend

    cfg = load_app_config(args.config)
    ref = cfg.models.get(args.model)
    model_id = ref.id if ref else args.model
    revision = args.revision or (ref.revision if ref else None)

    backend = load_transformers_backend(
        model_id=model_id,
        revision=revision,
        device=args.device,
        dtype=args.dtype,
        load_in_4bit=args.load_in_4bit,
        settings=GenerationSettings(max_new_tokens=8),
    )
    report = probe_model(
        backend.model,
        backend.tokenizer,
        model_id=model_id,
        revision=revision,
        n_prompts=args.n_prompts,
        quick=args.quick,
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "probe_report.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({k: report[k] for k in ("model_id", "compatible", "safetune_version")}, indent=2))
    for step in report["steps"]:
        print(f"  [{step['status'].upper():4s}] {step['name']}: {step['detail'] or step['error']}")
    return 0 if report["compatible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
