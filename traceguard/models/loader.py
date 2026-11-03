"""Model/tokenizer loading with pinned revisions and explicit failure modes.

Policy:
* HF credentials come ONLY from the ``HF_TOKEN`` environment variable and are
  never logged or stored in artifacts.
* Model and tokenizer are loaded from the SAME pinned revision when one is
  given, so manifests can record both.
* Gated models (both Aya checkpoints are gated, verified 2026-11-02) produce
  an actionable error instead of a raw 401 traceback.
* Device/dtype resolution is explicit: "auto" -> CUDA+bfloat16 when a GPU is
  present, else CPU (+ warning for models that will not fit in RAM).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

from traceguard.models.generation import GenerationSettings, TransformersBackend

logger = logging.getLogger(__name__)


class ModelAccessError(RuntimeError):
    """Model cannot be downloaded/authenticated (gated, missing token, network)."""


@dataclass(frozen=True)
class LoadingPlan:
    """Resolved loading configuration (recorded in the manifest)."""

    model_id: str
    revision: Optional[str]
    device: str  # "cuda" | "cpu"
    dtype: str  # "bfloat16" | "float16" | "float32" | "auto"
    load_in_4bit: bool
    cuda_bf16_supported: Optional[bool] = None  # None when no CUDA present


def cuda_supports_bf16() -> bool:
    """Hardware capability check for native bfloat16 on the current GPU.

    Native BF16 requires NVIDIA compute capability >= 8.0 (Ampere+).
    T4 (7.5), V100 (7.0) and older do NOT support it natively — those must
    run in FP16. Returns False (with a logged reason) when CUDA is absent or
    the capability cannot be queried, so 'auto' never selects BF16 blindly.
    """
    import torch

    if not torch.cuda.is_available():
        return False
    try:
        major, _minor = torch.cuda.get_device_capability()
    except Exception as exc:  # capability query failed -> assume no BF16
        logger.warning("Could not query CUDA capability (%s); assuming no native BF16", exc)
        return False
    return major >= 8


def _bnb_quant_kwargs(dtype_name: str) -> dict[str, Any]:
    """BitsAndBytes 4-bit kwargs using the RESOLVED compatible compute dtype.

    Pure function (no bitsandbytes import) so the dtype resolution is testable
    on machines without CUDA/bitsandbytes. The compute dtype follows the same
    hardware check as the loading dtype — never hardcoded BF16 (T4-class GPUs
    do not support it natively).
    """
    import torch

    return {
        "load_in_4bit": True,
        "bnb_4bit_compute_dtype": _dtype_from_name(dtype_name),
        "bnb_4bit_quant_type": "nf4",
    }


def resolve_loading_plan(
    model_id: str,
    revision: Optional[str] = None,
    device: str = "auto",
    dtype: str = "auto",
    load_in_4bit: bool = False,
) -> LoadingPlan:
    """Turn 'auto' placeholders into concrete device/dtype choices.

    dtype='auto' resolution (review patch P1):
    * CUDA + compute capability >= 8.0 -> bfloat16
    * CUDA + capability < 8.0 (e.g. T4/7.5) or unknown -> float16
    * CPU -> float32
    An explicitly requested dtype is honored, but requesting bfloat16 on a GPU
    without native support logs a loud warning.
    """
    import torch

    if device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    if device not in ("cuda", "cpu"):
        raise ValueError(f"unsupported device {device!r} (use 'auto', 'cuda', 'cpu')")

    bf16_supported: Optional[bool] = None
    if device == "cuda":
        bf16_supported = cuda_supports_bf16()
        if dtype == "auto":
            dtype = "bfloat16" if bf16_supported else "float16"
            logger.info(
                "CUDA dtype auto-resolved to %s (bf16 native support: %s)",
                dtype,
                bf16_supported,
            )
        elif dtype == "bfloat16" and not bf16_supported:
            logger.warning(
                "bfloat16 explicitly requested but this GPU lacks native BF16 "
                "(compute capability < 8.0, e.g. T4); expect emulation overhead "
                "or errors — consider --dtype float16"
            )
    elif dtype == "auto":
        dtype = "float32"

    if load_in_4bit and device == "cpu":
        raise ValueError("4-bit loading (bitsandbytes) requires a CUDA device")
    if device == "cpu" and not load_in_4bit:
        logger.warning(
            "Loading %s on CPU in %s; large models (>1B params) need roughly "
            "2 bytes/param (bf16) to 4 bytes/param (fp32) of free RAM",
            model_id,
            dtype,
        )
    return LoadingPlan(model_id, revision, device, dtype, load_in_4bit, bf16_supported)


def _hf_token() -> Optional[str]:
    """Read the HF token from the environment (never hardcode, never log it)."""
    token = os.environ.get("HF_TOKEN")
    if token:
        logger.info("HF_TOKEN detected in environment (value not logged)")
    else:
        logger.info("No HF_TOKEN in environment; downloads are anonymous")
    return token or None


def _dtype_from_name(name: str) -> Any:
    import torch

    return {
        "bfloat16": torch.bfloat16,
        "float16": torch.float16,
        "float32": torch.float32,
    }[name]


def load_transformers_backend(
    model_id: str,
    revision: Optional[str] = None,
    device: str = "auto",
    dtype: str = "auto",
    load_in_4bit: bool = False,
    settings: Optional[GenerationSettings] = None,
    trust_remote_code: bool = False,
    prompt_truncation: Optional[int] = None,
) -> TransformersBackend:
    """Load model + tokenizer and wrap them in a greedy :class:`TransformersBackend`.

    Args:
        model_id: HF hub id, e.g. ``CohereLabs/tiny-aya-global``.
        revision: Pinned commit sha (strongly recommended for experiments).
        device / dtype: ``"auto"`` or explicit values (see :func:`resolve_loading_plan`).
        load_in_4bit: bitsandbytes NF4 quantization (CUDA only, lazy import).
        settings: Deterministic generation settings (greedy enforced by type).
        trust_remote_code: Passed through to transformers; default False.
        prompt_truncation: EXPLICIT opt-in max prompt tokens (infrastructure
            runs on small-context probe models only; real runs must leave None).

    Raises:
        ModelAccessError: gated/unauthorized/network failures, with guidance.
        RuntimeError: any other load failure (original exception chained).
    """
    from transformers import AutoModelForCausalLM, AutoTokenizer

    plan = resolve_loading_plan(model_id, revision, device, dtype, load_in_4bit)
    settings = settings or GenerationSettings()
    token = _hf_token()

    common: dict[str, Any] = dict(revision=plan.revision, token=token)
    try:
        tokenizer = AutoTokenizer.from_pretrained(
            model_id, trust_remote_code=trust_remote_code, **common
        )
    except Exception as exc:
        raise _access_error(model_id, plan.revision, exc) from exc

    if tokenizer.pad_token is None and tokenizer.eos_token is not None:
        tokenizer.pad_token = tokenizer.eos_token
        logger.info("pad_token unset; using eos_token as pad_token")

    model_kwargs: dict[str, Any] = dict(trust_remote_code=trust_remote_code)
    # device_map requires `accelerate`; CPU placement is the transformers
    # default, so only pass it for CUDA (avoids a hard accelerate dependency
    # for CPU-only sandbox runs).
    if plan.device == "cuda":
        model_kwargs["device_map"] = plan.device
    if load_in_4bit:
        from transformers import BitsAndBytesConfig

        # Compute dtype follows the resolved plan (FP16 on T4-class GPUs,
        # BF16 only where natively supported) — never hardcoded.
        compute_dtype_name = plan.dtype
        if compute_dtype_name == "float32":
            compute_dtype_name = "float16"
            logger.warning(
                "4-bit loading with dtype=float32 requested; bitsandbytes compute "
                "dtype must be fp16/bf16 — using float16"
            )
        model_kwargs["quantization_config"] = BitsAndBytesConfig(
            **_bnb_quant_kwargs(compute_dtype_name)
        )
    else:
        # transformers renamed torch_dtype -> dtype across the 4.x/5.x line;
        # try the modern kwarg first, fall back for older installs.
        try:
            model_kwargs["dtype"] = _dtype_from_name(plan.dtype)
        except KeyError as exc:
            raise ValueError(f"unknown dtype {plan.dtype!r}") from exc

    try:
        try:
            model = AutoModelForCausalLM.from_pretrained(model_id, **common, **model_kwargs)
        except TypeError:
            model_kwargs_torch = dict(model_kwargs)
            model_kwargs_torch["torch_dtype"] = model_kwargs_torch.pop("dtype", None)
            model = AutoModelForCausalLM.from_pretrained(
                model_id, **common, **model_kwargs_torch
            )
    except Exception as exc:
        raise _access_error(model_id, plan.revision, exc) from exc

    if not getattr(tokenizer, "chat_template", None):
        logger.warning(
            "Tokenizer for %s has no chat template; prompt rendering will use "
            "the documented fallback template (renderer is recorded per output)",
            model_id,
        )

    return TransformersBackend(
        model=model,
        tokenizer=tokenizer,
        model_id=model_id,
        revision=plan.revision,
        settings=settings,
        device=plan.device,
        dtype=("nf4" if load_in_4bit else plan.dtype),
        prompt_truncation=prompt_truncation,
    )


def _access_error(model_id: str, revision: Optional[str], exc: Exception) -> RuntimeError:
    """Map hub errors to actionable messages (gated 401/403 get dedicated help)."""
    text = str(exc)
    lowered = text.lower()
    if "401" in text or "403" in text or "gated" in lowered or "unauthorized" in lowered:
        return ModelAccessError(
            f"Cannot access {model_id}@{revision or 'main'}: {type(exc).__name__}. "
            "This model is GATED. Steps: (1) log in on huggingface.co and accept the "
            f"license at https://huggingface.co/{model_id}; (2) create a read token at "
            "https://huggingface.co/settings/tokens; (3) export HF_TOKEN=<token> in the "
            "shell or Colab Secrets. Never commit the token."
        )
    return RuntimeError(f"Failed to load {model_id}@{revision or 'main'}: {exc}")
