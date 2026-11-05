"""Integration tests with real transformers (tiny random GPT-2, ungated).

Purpose (per approved Phase 2 change #3): these prove the *infrastructure*
works — loading, fallback template rendering, greedy generation, latency/token
measurement, graceful handling of protocol-invalid gibberish, artifact
writing, and honest gate failure. They are NEVER counted as model success:
a random-weight model cannot pass T01-T10, and the test asserts exactly that.
"""

from __future__ import annotations

import json
import socket

import pytest

from traceguard.experiments.smoke_test import load_smoke_tasks, run_smoke
from traceguard.models.config import CONFIG_DIR
from traceguard.models.generation import GenerationSettings
from traceguard.models.json_parser import load_tool_registry

TINY_MODEL = "hf-internal-testing/tiny-random-gpt2"


def _network_available() -> bool:
    try:
        socket.create_connection(("huggingface.co", 443), timeout=5).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _network_available(), reason="HF hub unreachable; integration test needs network"
)


@pytest.fixture(scope="module")
def backend():
    from traceguard.models.loader import load_transformers_backend

    return load_transformers_backend(
        TINY_MODEL,
        device="cpu",
        dtype="float32",
        settings=GenerationSettings(max_new_tokens=16),
    )


def test_loader_reports_missing_chat_template(backend):
    desc = backend.describe()
    assert desc["model_id"] == TINY_MODEL
    assert desc["device"] == "cpu"
    assert desc["has_chat_template"] is False  # tiny-random-gpt2 has none


def test_generation_record_measurements(backend):
    messages = [
        {"role": "system", "content": "Reply with one JSON object."},
        {"role": "user", "content": "Hello?"},
    ]
    record = backend.generate(messages)
    assert record.error is None
    assert record.latency_seconds > 0.0
    assert record.prompt_tokens and record.prompt_tokens > 0
    assert record.completion_tokens is not None
    assert 0 < record.completion_tokens <= 16
    assert record.renderer == "fallback_template"  # no chat template -> documented fallback
    assert record.settings["do_sample"] is False


def test_full_smoke_infrastructure_run_fails_gate_honestly(backend, tmp_path):
    tasks = load_smoke_tasks(CONFIG_DIR / "smoke_tasks.jsonl")
    registry = load_tool_registry(CONFIG_DIR / "tools.yaml")
    acc = run_smoke(
        tasks=tasks,
        registry=registry,
        backend=backend,
        out_dir=tmp_path,
        settings=GenerationSettings(max_new_tokens=16),
        configuration_name="smoke:infrastructure-check",
    )
    # A random-weight model must NOT be accepted; this asserts the gate is honest.
    assert acc.accepted is False
    assert acc.total == 10
    # Real finding (2026-11-02): the smoke system prompt is ~1242 GPT-2 tokens,
    # above tiny-random-gpt2's 1024 context -> every task must record an
    # explicit prompt_exceeds_context generation error (never silent truncation).
    assert (tmp_path / "raw_outputs.jsonl").exists()
    raw = [json.loads(l) for l in (tmp_path / "raw_outputs.jsonl").read_text().splitlines()]
    assert len(raw) == 10
    assert all(r["record"]["backend_name"] == "transformers" for r in raw)
    errors = [r["record"]["error"] or "" for r in raw]
    assert all("prompt_exceeds_context" in e for e in errors), errors
    assert acc.parse_failures == 10 and acc.passed == 0
    results = json.loads((tmp_path / "results.json").read_text())
    assert results["accepted"] is False


def test_gated_model_without_token_raises_actionable_error():
    """Real check of the gating finding from Phase 1: no token -> clear guidance."""
    import os

    from traceguard.models.loader import ModelAccessError, load_transformers_backend

    if os.environ.get("HF_TOKEN"):
        pytest.skip("HF_TOKEN present; gating error path not exercised")
    with pytest.raises(ModelAccessError, match="GATED"):
        load_transformers_backend("CohereLabs/aya-expanse-8b", device="cpu", dtype="float32")
