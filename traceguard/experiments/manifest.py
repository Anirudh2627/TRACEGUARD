"""Machine-readable experiment manifests (reproducibility requirement §9).

A manifest records everything needed to re-run and audit an experiment:
ids, pinned model/tokenizer revisions, generation settings, dataset identity,
SafeTune settings (null until Phase 3+), package versions, seed, timestamps
and artifact paths. Values are collected at run time — never fabricated.
"""

from __future__ import annotations

import platform
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Optional, Sequence

_PACKAGES_TO_RECORD = (
    "torch",
    "transformers",
    "huggingface-hub",
    "safetune",
    "pyyaml",
    "accelerate",
    "bitsandbytes",
    "pytest",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def package_versions(names: Sequence[str] = _PACKAGES_TO_RECORD) -> dict[str, Optional[str]]:
    """Installed versions of key packages; ``None`` when not installed."""
    versions: dict[str, Optional[str]] = {}
    for name in names:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def build_manifest(
    *,
    experiment_id: str,
    configuration_name: str,
    backend_description: dict[str, Any],
    generation_settings: dict[str, Any],
    dataset: dict[str, Any],
    safetune_settings: Optional[dict[str, Any]] = None,
    seed: Optional[int] = None,
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
    artifact_paths: Sequence[str] = (),
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Assemble the manifest dict (caller serializes it next to the artifacts)."""
    manifest: dict[str, Any] = {
        "manifest_version": "1.0",
        "experiment_id": experiment_id,
        "configuration_name": configuration_name,
        "model_id": backend_description.get("model_id"),
        "model_revision": backend_description.get("revision"),
        "tokenizer_revision": backend_description.get("revision"),
        "backend": backend_description,
        "generation_settings": generation_settings,
        "dataset": dataset,
        "safetune": safetune_settings,
        "seed": seed,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "packages": package_versions(),
        },
        "started_at_utc": started_at or _utc_now(),
        "finished_at_utc": finished_at or _utc_now(),
        "artifacts": list(artifact_paths),
    }
    if extra:
        manifest["extra"] = extra
    return manifest


def write_manifest(manifest: dict[str, Any], out_dir: str | Path) -> Path:
    """Serialize the manifest as ``manifest.json`` inside ``out_dir``."""
    import json

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "manifest.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path
