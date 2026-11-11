"""run_traceguard --mode model: loading flags, pinned revision, multi-GPU device_map.

No GPU or network needed: the loader and transformers are faked.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import torch

from traceguard.models import loader

ROOT = Path(__file__).resolve().parent.parent
AYA = "CohereLabs/aya-expanse-8b"
AYA_REV = "5062468bf9bc0c6035fd64e06274333ec127d980"


@pytest.fixture(scope="module")
def cli():
    spec = importlib.util.spec_from_file_location("run_traceguard_cli", ROOT / "scripts" / "run_traceguard.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _kwargs(cli, *argv):
    return cli.build_model_loading_kwargs(cli.build_parser().parse_args(["--mode", "model", *argv]))


def test_defaults_use_pinned_revision_and_auto_loading(cli):
    k = _kwargs(cli)
    assert k == {
        "model_id": AYA, "revision": AYA_REV, "device": "auto", "dtype": "auto",
        "load_in_4bit": False, "device_map": None,
    }


def test_flags_are_passed_through(cli):
    k = _kwargs(cli, "--load-in-4bit", "--dtype", "float16", "--device", "cuda", "--device-map", "auto")
    assert (k["load_in_4bit"], k["dtype"], k["device"], k["device_map"]) == (True, "float16", "cuda", "auto")


def test_explicit_revision_overrides_pin_and_unknown_model_is_unpinned(cli):
    assert _kwargs(cli, "--revision", "abc123")["revision"] == "abc123"
    assert _kwargs(cli, "--model-id", "some/other-model")["revision"] is None


def test_invalid_flag_values_rejected(cli):
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--dtype", "int8"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--device-map", "everywhere"])


def test_cli_passes_flags_to_loader(cli, monkeypatch, tmp_path):
    seen = {}

    def fake_loader(**kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here (no model in tests)")

    monkeypatch.setattr(loader, "load_model_backend", fake_loader)
    monkeypatch.setattr(sys, "argv", [
        "run_traceguard.py", "--mode", "model", "--split", "dev", "--output-dir", str(tmp_path),
        "--load-in-4bit", "--dtype", "float16", "--device-map", "auto",
    ])
    assert cli.run_evaluation_cli() == 0
    assert seen["revision"] == AYA_REV and seen["load_in_4bit"] is True
    assert seen["dtype"] == "float16" and seen["device_map"] == "auto"
    # Loader failure is reported honestly as NOT_RUN, never as results.
    assert json.loads((tmp_path / "model_execution_status.json").read_text())["status"] == "NOT_RUN"


# ---- loader.device_map ----

@pytest.fixture
def fake_two_t4(monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    monkeypatch.setattr(torch.cuda, "get_device_capability", lambda *a, **k: (7, 5))


@pytest.fixture
def captured(monkeypatch):
    """Fake `transformers` module so no real package or model is needed."""
    import types

    seen = {}

    class FakeTok:
        pad_token, eos_token, chat_template = "x", "x", "tpl"
        pad_token_id, eos_token_id = 0, 0

        @classmethod
        def from_pretrained(cls, *a, **k):
            return cls()

    class FakeModel:
        @classmethod
        def from_pretrained(cls, model_id, **kwargs):
            seen.update(kwargs)
            return cls()

        def eval(self):
            return self

    fake = types.ModuleType("transformers")
    fake.AutoTokenizer = FakeTok
    fake.AutoModelForCausalLM = FakeModel
    monkeypatch.setitem(sys.modules, "transformers", fake)
    monkeypatch.setattr(loader, "TransformersBackend", lambda **kw: kw)
    return seen


def test_default_placement_is_unchanged(fake_two_t4, captured):
    loader.load_transformers_backend("m", device="cuda", dtype="float16")
    assert captured["device_map"] == "cuda"


def test_device_map_spreads_model_across_gpus(fake_two_t4, captured):
    loader.load_transformers_backend("m", device="cuda", dtype="float16", device_map="auto")
    assert captured["device_map"] == "auto"


def test_bad_or_cpu_device_map_rejected(fake_two_t4, captured, monkeypatch):
    with pytest.raises(ValueError):
        loader.load_transformers_backend("m", device="cuda", device_map="everywhere")
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    with pytest.raises(ValueError, match="CUDA"):
        loader.load_transformers_backend("m", device="cpu", device_map="auto")
