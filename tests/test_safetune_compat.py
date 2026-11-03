"""SafeTune compatibility tests — run ONLY where safetune is installed
(the isolated Python 3.12 environment). Skipped automatically elsewhere.

Executes the real probe against an ungated tiny model (GPT-2 family is
explicitly supported by SafeTune's layer discovery via ``transformer.h``),
proving the probe itself works end to end. The authoritative Tiny Aya probe
runs on Colab with the same code path.
"""

from __future__ import annotations

import json
import socket

import pytest

safetune = pytest.importorskip("safetune", reason="needs the Python>=3.12 SafeTune env")


def _network_available() -> bool:
    try:
        socket.create_connection(("huggingface.co", 443), timeout=5).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _network_available(), reason="HF hub unreachable; needs to download the probe model"
)


@pytest.fixture(scope="module")
def tiny_backend():
    from traceguard.models.generation import GenerationSettings
    from traceguard.models.loader import load_transformers_backend

    return load_transformers_backend(
        "hf-internal-testing/tiny-random-gpt2",
        device="cpu",
        dtype="float32",
        settings=GenerationSettings(max_new_tokens=8),
    )


def test_probe_passes_on_supported_tiny_model(tiny_backend):
    from traceguard.experiments.safetune_compat import probe_model

    report = probe_model(
        tiny_backend.model,
        tiny_backend.tokenizer,
        model_id="hf-internal-testing/tiny-random-gpt2",
        n_prompts=4,
        quick=True,
        max_new_tokens=8,
    )
    assert report["compatible"] is True, json.dumps(report["steps"], indent=1)
    step_names = [s["name"] for s in report["steps"]]
    assert step_names == [
        "layer_discovery",
        "extract_refusal_direction",
        "hook_cycle",
        "runner_trainer_calibrate",
    ]
    assert all(s["status"] == "pass" for s in report["steps"])
    discovery = report["steps"][0]["data"]
    assert discovery["n_layers"] > 0
    assert discovery["layer_class"] == "GPT2Block"
    assert report["semantics"] == "not_evaluated"


def test_installed_api_matches_source_expectations():
    """Condition 2: signatures verified against the INSTALLED package."""
    import dataclasses
    import inspect

    from safetune import steer as S
    from safetune.runner import steer as runner

    params = list(inspect.signature(S.extract_refusal_direction).parameters)
    assert params[:5] == ["model", "tokenizer", "harmful_prompts", "harmless_prompts", "config"]

    init_params = inspect.signature(S.RefusalDirectionModel.__init__).parameters
    assert set(init_params) >= {"model", "direction", "mode", "strength", "layers"}

    cfg_fields = {f.name for f in dataclasses.fields(S.RefusalDirectionConfig)}
    assert {"select_directions", "kl_threshold", "strength"} <= cfg_fields

    trainer_init = inspect.signature(runner.RefusalDirectionTrainer.__init__).parameters
    assert {"layers", "alpha", "orthogonalize"} <= set(trainer_init)
    assert float(trainer_init["alpha"].default) == 20.0


# ---------- review patch P4: hook cleanup under failure ----------

def _assert_no_residual_hooks(model):
    from safetune._refusal_helpers import _get_decoder_layers

    layers = _get_decoder_layers(model)
    assert layers, "layer discovery must work for this check"
    residual = {i: len(l._forward_hooks) for i, l in enumerate(layers) if len(l._forward_hooks)}
    assert not residual, f"residual forward hooks after failure: {residual}"


def test_probe_hook_cycle_cleans_up_when_generation_raises(tiny_backend, monkeypatch):
    from traceguard.experiments.safetune_compat import probe_model

    model = tiny_backend.model
    original_generate = model.generate
    calls = {"n": 0}

    def flaky_generate(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:  # first call = baseline, second = steered
            raise RuntimeError("simulated generation failure")
        return original_generate(*args, **kwargs)

    monkeypatch.setattr(model, "generate", flaky_generate)
    report = probe_model(
        model, tiny_backend.tokenizer, model_id="probe-cleanup-test",
        n_prompts=4, quick=True, max_new_tokens=4,
    )
    hook_step = next(s for s in report["steps"] if s["name"] == "hook_cycle")
    assert hook_step["status"] == "fail"
    assert "simulated generation failure" in hook_step["error"]
    _assert_no_residual_hooks(model)  # try/finally removed every hook


def test_steered_backend_removes_hooks_when_inner_generation_raises(tiny_backend, tmp_path):
    import torch

    from traceguard.models.steered_backend import SteeredBackend

    direction_file = tmp_path / "refusal_direction.pt"
    hidden = tiny_backend.model.config.n_embd
    torch.save(
        {"direction": torch.randn(hidden), "layer_idx": 0, "meta": {"model_id": "t"}},
        direction_file,
    )

    class BoomInner:
        name = "transformers"
        model = tiny_backend.model

        def describe(self):
            return {"backend": "transformers", "model_id": "dummy", "revision": None}

        def generate(self, messages):
            raise RuntimeError("simulated inner failure")

    backend = SteeredBackend(BoomInner(), direction_file, strength=1.0)
    with pytest.raises(RuntimeError, match="simulated inner failure"):
        backend.generate([{"role": "user", "content": "hi"}])
    _assert_no_residual_hooks(tiny_backend.model)
