"""Configuration loading for Member 1 experiments (YAML-driven, no hardcoding)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

#: Repository root = parent of the ``traceguard`` package directory.
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "traceguard" / "configs"


def resolve_path(path: str | Path, base: Path = REPO_ROOT) -> Path:
    """Resolve a possibly-relative config path against the repository root."""
    p = Path(path)
    return p if p.is_absolute() else (base / p)


@dataclass(frozen=True)
class ModelRef:
    """A pinned model reference."""

    alias: str
    id: str
    revision: Optional[str]


@dataclass(frozen=True)
class SmokeConfig:
    """Smoke-test knobs (acceptance gate values live here, not in code)."""

    tasks_path: Path
    tools_path: Path
    min_pass: int = 8
    critical_failures_allowed: int = 0
    total_tasks: int = 10
    #: Prompt configuration for the smoke run. Default "E1" = baseline
    #: protocol + untrusted-content instructions, which reproduces the
    #: approved Phase-2 smoke semantics (the P2 provenance-label additions
    #: are conditional and NOT part of model acceptance). Recorded in every
    #: artifact so results are never ambiguous about which prompt ran.
    prompt_mode: str = "E1"


@dataclass(frozen=True)
class AppConfig:
    """Top-level experiment configuration for Phase 2."""

    defaults: dict[str, Any] = field(default_factory=dict)
    generation: dict[str, Any] = field(default_factory=dict)
    models: dict[str, ModelRef] = field(default_factory=dict)
    smoke: Optional[SmokeConfig] = None
    results_dir: Path = REPO_ROOT / "results"


def load_app_config(path: str | Path | None = None) -> AppConfig:
    """Load ``model_config.yaml`` (default) into typed dataclasses."""
    path = resolve_path(path or CONFIG_DIR / "model_config.yaml")
    with path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    models = {
        alias: ModelRef(alias=alias, id=m["id"], revision=m.get("revision"))
        for alias, m in (doc.get("models") or {}).items()
    }
    smoke_doc = doc.get("smoke") or {}
    smoke = (
        SmokeConfig(
            tasks_path=resolve_path(smoke_doc["tasks_path"]),
            tools_path=resolve_path(smoke_doc["tools_path"]),
            min_pass=int(smoke_doc.get("min_pass", 8)),
            critical_failures_allowed=int(smoke_doc.get("critical_failures_allowed", 0)),
            total_tasks=int(smoke_doc.get("total_tasks", 10)),
            prompt_mode=str(smoke_doc.get("prompt_mode", "E1")),
        )
        if smoke_doc
        else None
    )
    if smoke is not None:
        from traceguard.models.prompt_builder import PROMPT_MODES

        if smoke.prompt_mode not in PROMPT_MODES:
            raise ValueError(
                f"smoke.prompt_mode {smoke.prompt_mode!r} invalid; "
                f"expected one of {sorted(PROMPT_MODES)}"
            )
    return AppConfig(
        defaults=doc.get("defaults") or {},
        generation=doc.get("generation") or {},
        models=models,
        smoke=smoke,
        results_dir=resolve_path(doc.get("results_dir", "results")),
    )
