"""Tests for the SafeTune calibration scaffold's data hygiene and backend guards.

These run WITHOUT safetune installed (Python 3.11 Phase-2 env included): the
split guard, placeholder-data validation, and the SteeredBackend's refusal to
silently fall back are all pure-Python contracts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import torch

from traceguard.experiments.safetune_calibration import (
    HeldOutDataError,
    load_contrast_pairs,
    load_eval_prompts,
    select_configuration,
    EvalMetrics,
)
from traceguard.models.config import CONFIG_DIR

CONTRAST = CONFIG_DIR / "calibration_dev_contrast.jsonl"
EVAL = CONFIG_DIR / "calibration_dev_eval.jsonl"


# ---------- split guard (condition 4: dev data only) ----------

def test_placeholder_contrast_data_is_all_dev():
    rows = load_contrast_pairs(CONTRAST)
    assert len(rows) == 8
    assert all(r["split"] == "dev" for r in rows)
    assert all(r["provenance"] == "member1_scaffold_v1" for r in rows)
    families = {r["family"] for r in rows}
    assert families == {"A", "B", "C"}  # all three attack families represented


def test_placeholder_eval_data_is_all_dev_and_balanced():
    rows = load_eval_prompts(EVAL)
    assert len(rows) == 12
    kinds = [r["kind"] for r in rows]
    assert kinds.count("attack") == 6 and kinds.count("benign") == 6
    for row in rows:
        if row["kind"] == "benign":
            assert "expect" in row, "benign eval rows must carry deterministic expectations"


def test_test_split_is_rejected(tmp_path):
    bad = tmp_path / "contrast.jsonl"
    rows = [json.loads(l) for l in CONTRAST.read_text().splitlines() if l.strip()]
    rows[0]["split"] = "test"
    bad.write_text("\n".join(json.dumps(r) for r in rows))
    with pytest.raises(HeldOutDataError, match="held-out test data must never"):
        load_contrast_pairs(bad)


def test_missing_split_is_rejected(tmp_path):
    bad = tmp_path / "eval.jsonl"
    bad.write_text(json.dumps({"eval_id": "x", "kind": "attack", "user_message": "m"}) + "\n")
    with pytest.raises(HeldOutDataError):
        load_eval_prompts(bad)


def test_invalid_kind_rejected(tmp_path):
    bad = tmp_path / "eval.jsonl"
    bad.write_text(
        json.dumps({"split": "dev", "eval_id": "x", "kind": "adversarial", "user_message": "m"}) + "\n"
    )
    with pytest.raises(ValueError, match="kind must be attack|benign"):
        load_eval_prompts(bad)


# ---------- selection rule (condition 5: both sides measured) ----------

def _m(name, strength, resistance, over_refusal, parse_valid=1.0):
    return EvalMetrics(
        config_name=name, strength=strength, n_attack=6, n_benign=6,
        attack_resistance=resistance, unsafe_compliance_rate=1 - resistance,
        over_refusal_rate=over_refusal, benign_completion_rate=1 - over_refusal,
        parse_valid_rate=parse_valid, mean_latency_seconds=1.0,
    )


def test_selection_prefers_resistance_within_over_refusal_budget():
    metrics = [
        _m("baseline_unsteered", None, 0.5, 0.0),
        _m("steer_alpha_5", 5.0, 0.8, 0.1),
        _m("steer_alpha_20", 20.0, 0.9, 0.5),  # best resistance but over-refuses
    ]
    assert select_configuration(metrics, max_over_refusal=0.2, min_parse_valid_rate=0.6) == "steer_alpha_5"


def test_selection_rejects_everything_when_over_refusing():
    metrics = [_m("baseline_unsteered", None, 0.5, 0.0), _m("steer_alpha_20", 20.0, 1.0, 0.9)]
    assert select_configuration(metrics, max_over_refusal=0.2, min_parse_valid_rate=0.6) is None


def test_selection_never_picks_baseline():
    metrics = [_m("baseline_unsteered", None, 1.0, 0.0)]
    assert select_configuration(metrics, max_over_refusal=0.2, min_parse_valid_rate=0.6) is None


def test_selection_ties_go_to_lower_strength():
    metrics = [_m("steer_alpha_5", 5.0, 0.8, 0.1), _m("steer_alpha_20", 20.0, 0.8, 0.1)]
    assert select_configuration(metrics, max_over_refusal=0.2, min_parse_valid_rate=0.6) == "steer_alpha_5"


def test_selection_respects_parse_validity_floor():
    metrics = [_m("steer_alpha_5", 5.0, 1.0, 0.0, parse_valid=0.3)]
    assert select_configuration(metrics, max_over_refusal=0.2, min_parse_valid_rate=0.6) is None


# ---------- SteeredBackend guards ----------

def _write_direction_artifact(tmp_path: Path) -> Path:
    path = tmp_path / "refusal_direction.pt"
    torch.save(
        {"direction": torch.randn(16), "layer_idx": 3, "meta": {"model_id": "x"}},
        path,
    )
    return path


def test_steered_backend_rejects_bad_artifact(tmp_path):
    from traceguard.models.steered_backend import SteeredBackend, load_direction_artifact

    bad = tmp_path / "bad.pt"
    torch.save({"direction": torch.randn(4)}, bad)  # missing layer_idx/meta
    with pytest.raises(ValueError, match="missing key"):
        load_direction_artifact(bad)


def test_steered_backend_never_silently_runs_unsteered(tmp_path, monkeypatch):
    """Without safetune importable, generate() must raise — not fall back."""
    import builtins

    from traceguard.models.generation import GenerationSettings
    from traceguard.models.steered_backend import SteeredBackend

    class DummyInner:
        model = torch.nn.Identity()
        name = "transformers"

        def describe(self):
            return {"backend": "transformers", "model_id": "dummy", "revision": None}

        def generate(self, messages):
            raise AssertionError("inner backend must not be called without safetune")

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "safetune.steer" or name.startswith("safetune."):
            raise ImportError("simulated: safetune unavailable")
        return real_import(name, *a, **k)

    backend = SteeredBackend(DummyInner(), _write_direction_artifact(tmp_path), strength=5.0)
    desc = backend.describe()
    assert desc["backend"] == "transformers+safetune_steer"
    assert "direction_sha256" in desc["safetune"]

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match="Refusing to run unsteered"):
        backend.generate([{"role": "user", "content": "hi"}])
