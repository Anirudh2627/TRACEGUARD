"""Regression tests for review patch P1 — GPU precision resolution.

T4-class GPUs (compute capability 7.5) do NOT support native BF16; dtype
'auto' must resolve to FP16 there and to BF16 only on capability >= 8.0.
The 4-bit compute dtype must follow the resolved dtype, never a hardcoded
BF16. All tests run without a GPU via monkeypatched capability queries.
"""

from __future__ import annotations

import logging

import pytest
import torch

from traceguard.models.loader import (
    _bnb_quant_kwargs,
    _dtype_from_name,
    cuda_supports_bf16,
    resolve_loading_plan,
)


@pytest.fixture
def fake_t4(monkeypatch):
    """Simulate a CUDA device with T4 capability (7.5)."""
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    monkeypatch.setattr(torch.cuda, "get_device_capability", lambda *a, **k: (7, 5))


@pytest.fixture
def fake_ampere(monkeypatch):
    """Simulate a CUDA device with Ampere capability (8.0)."""
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    monkeypatch.setattr(torch.cuda, "get_device_capability", lambda *a, **k: (8, 0))


@pytest.fixture
def fake_no_cuda(monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)


def test_auto_dtype_on_t4_resolves_to_fp16(fake_t4):
    plan = resolve_loading_plan("m", device="cuda", dtype="auto")
    assert plan.dtype == "float16"
    assert plan.cuda_bf16_supported is False


def test_auto_dtype_on_ampere_resolves_to_bf16(fake_ampere):
    plan = resolve_loading_plan("m", device="cuda", dtype="auto")
    assert plan.dtype == "bfloat16"
    assert plan.cuda_bf16_supported is True


def test_device_auto_picks_cuda_and_t4_dtype(fake_t4):
    plan = resolve_loading_plan("m", device="auto", dtype="auto")
    assert plan.device == "cuda"
    assert plan.dtype == "float16"


def test_capability_query_failure_falls_back_to_fp16(monkeypatch, caplog):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)

    def boom(*a, **k):
        raise RuntimeError("nvml unavailable")

    monkeypatch.setattr(torch.cuda, "get_device_capability", boom)
    with caplog.at_level(logging.WARNING):
        plan = resolve_loading_plan("m", device="cuda", dtype="auto")
    assert plan.dtype == "float16"
    assert plan.cuda_bf16_supported is False
    assert "assuming no native BF16" in caplog.text


def test_explicit_bf16_on_t4_warns_but_is_honored(fake_t4, caplog):
    with caplog.at_level(logging.WARNING):
        plan = resolve_loading_plan("m", device="cuda", dtype="bfloat16")
    assert plan.dtype == "bfloat16"  # explicit request honored
    assert "lacks native BF16" in caplog.text


def test_no_cuda_means_no_bf16_and_cpu_fp32(fake_no_cuda):
    assert cuda_supports_bf16() is False
    plan = resolve_loading_plan("m", device="auto", dtype="auto")
    assert plan.device == "cpu"
    assert plan.dtype == "float32"
    assert plan.cuda_bf16_supported is None


def test_bnb_compute_dtype_follows_resolved_dtype():
    kwargs_fp16 = _bnb_quant_kwargs("float16")
    assert kwargs_fp16["bnb_4bit_compute_dtype"] is torch.float16
    assert kwargs_fp16["load_in_4bit"] is True
    assert kwargs_fp16["bnb_4bit_quant_type"] == "nf4"

    kwargs_bf16 = _bnb_quant_kwargs("bfloat16")
    assert kwargs_bf16["bnb_4bit_compute_dtype"] is torch.bfloat16


def test_bnb_compute_dtype_never_hardcoded_bf16_on_t4(fake_t4):
    """End-to-end of the resolution: T4 + 4bit -> compute dtype must be FP16."""
    plan = resolve_loading_plan("m", device="cuda", dtype="auto", load_in_4bit=True)
    kwargs = _bnb_quant_kwargs(plan.dtype)
    assert kwargs["bnb_4bit_compute_dtype"] is torch.float16


def test_dtype_name_mapping():
    assert _dtype_from_name("float16") is torch.float16
    assert _dtype_from_name("bfloat16") is torch.bfloat16
    assert _dtype_from_name("float32") is torch.float32
    with pytest.raises(KeyError):
        _dtype_from_name("int8")
