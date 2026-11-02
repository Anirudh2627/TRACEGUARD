"""SafeTune-steered generation backend (E3/E4 building block).

Wraps a :class:`TransformersBackend` and installs SafeTune's
``RefusalDirectionModel`` residual-stream hooks around every generation
(``mode="steer"`` adds the refusal direction; the direction is loaded from a
calibration artifact, never re-derived at eval time).

Requires the isolated Python >= 3.12 SafeTune environment (Phase 2's 3.11 env
does not have safetune). If safetune is missing, ``generate`` raises a clear
``RuntimeError`` — it never silently falls back to unsteered generation,
because that would mislabel results.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional, Sequence, Union

from traceguard.models.generation import GenerationRecord, TransformersBackend

logger = logging.getLogger(__name__)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_direction_artifact(path: Union[str, Path]) -> dict[str, Any]:
    """Load ``refusal_direction.pt`` written by the calibration experiment.

    Expected content: ``{"direction": Tensor, "layer_idx": int, "meta": dict}``.
    """
    import torch

    path = Path(path)
    blob = torch.load(path, map_location="cpu", weights_only=False)
    for key in ("direction", "layer_idx", "meta"):
        if key not in blob:
            raise ValueError(f"{path}: direction artifact missing key {key!r}")
    return blob


class SteeredBackend:
    """:class:`~traceguard.models.generation.GenerationBackend` with SafeTune steering."""

    name = "transformers+safetune_steer"

    def __init__(
        self,
        inner: TransformersBackend,
        direction_file: Union[str, Path],
        strength: float,
        mode: str = "steer",
        layers: Optional[Sequence[int]] = None,
    ) -> None:
        if mode not in ("steer", "ablate"):
            raise ValueError(f"mode must be 'steer' or 'ablate', got {mode!r}")
        self._inner = inner
        self._direction_file = Path(direction_file)
        blob = load_direction_artifact(self._direction_file)
        self._direction = blob["direction"]
        self._layer_idx = int(blob["layer_idx"])
        self._direction_meta = dict(blob.get("meta") or {})
        self._strength = float(strength)
        self._mode = mode
        self._layers = list(layers) if layers is not None else None

    def describe(self) -> dict[str, Any]:
        base = self._inner.describe()
        base["backend"] = self.name
        base["safetune"] = {
            "direction_file": str(self._direction_file),
            "direction_sha256": _sha256(self._direction_file),
            "layer_idx": self._layer_idx,
            "strength": self._strength,
            "mode": self._mode,
            "layers": self._layers,
            "direction_meta": self._direction_meta,
        }
        return base

    def generate(self, messages: Sequence[dict[str, str]]) -> GenerationRecord:
        try:
            from safetune.steer import RefusalDirectionModel
        except ImportError as exc:  # explicit failure, never a silent fallback
            raise RuntimeError(
                "safetune is not importable in this interpreter. Steered runs "
                "require the isolated Python>=3.12 SafeTune environment "
                "(see docs/PHASE3_REPORT.md). Refusing to run unsteered."
            ) from exc

        wrapper = RefusalDirectionModel(
            self._inner.model,
            direction=self._direction,
            mode=self._mode,
            strength=self._strength,
            layers=self._layers,
        )
        with wrapper:  # install() on enter, remove() on exit
            record = self._inner.generate(messages)
        return replace(
            record,
            backend_name=self.name,
            settings={**record.settings, "safetune": self.describe()["safetune"]},
        )
