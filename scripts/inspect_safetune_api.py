#!/usr/bin/env python
"""Introspect the INSTALLED safetune package and record actual API signatures.

Condition 2 (Phase 3): verify the real installed API rather than README
examples. Run inside the Python >= 3.12 SafeTune environment:

    python scripts/inspect_safetune_api.py --out results/safetune/api_report.json
"""

from __future__ import annotations

import argparse
import dataclasses
import inspect
import json
import platform
import sys
from pathlib import Path
from typing import Any


def _sig(obj: Any) -> str | None:
    try:
        return str(inspect.signature(obj))
    except (TypeError, ValueError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    report: dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }

    import safetune

    report["safetune"] = {
        "version": getattr(safetune, "__version__", "unknown"),
        "file": getattr(safetune, "__file__", None),
    }

    # --- low-level steer API (interventions) ---
    from safetune import steer as S

    steer_api: dict[str, Any] = {}
    for name in (
        "extract_refusal_direction",
        "RefusalDirectionModel",
        "RefusalDirectionConfig",
    ):
        obj = getattr(S, name, None)
        entry: dict[str, Any] = {"present": obj is not None}
        if obj is not None:
            entry["signature"] = _sig(obj) if not dataclasses.is_dataclass(obj) else None
            entry["qualname"] = getattr(obj, "__qualname__", None)
            entry["module"] = getattr(obj, "__module__", None)
            if dataclasses.is_dataclass(obj):
                entry["fields"] = {
                    f.name: repr(f.default) if f.default is not dataclasses.MISSING else "<required>"
                    for f in dataclasses.fields(obj)
                }
            if inspect.isclass(obj):
                entry["methods"] = {
                    m: _sig(getattr(obj, m))
                    for m in ("__init__", "install", "remove")
                    if hasattr(obj, m)
                }
        steer_api[name] = entry
    report["safetune.steer"] = steer_api

    # --- layer-discovery helper ---
    from safetune._refusal_helpers import _get_decoder_layers

    report["_get_decoder_layers"] = {
        "signature": _sig(_get_decoder_layers),
        "module": _get_decoder_layers.__module__,
        "doc_first_line": (_get_decoder_layers.__doc__ or "").strip().splitlines()[0],
    }

    # --- runner trainer API ---
    from safetune.runner import steer as steer_runner

    trainer = steer_runner.RefusalDirectionTrainer
    report["RefusalDirectionTrainer"] = {
        "module": trainer.__module__,
        "init_signature": _sig(trainer.__init__),
        "calibrate_signature": _sig(trainer.calibrate),
        "eval_live_signature": _sig(trainer.eval_live),
        "save_results_signature": _sig(trainer.save_results),
        "method_attr": getattr(trainer, "METHOD", None),
    }

    # --- versions of key deps in THIS environment ---
    from importlib import metadata

    deps = {}
    for pkg in ("torch", "transformers", "accelerate", "peft", "trl", "huggingface-hub", "safetune"):
        try:
            deps[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            deps[pkg] = None
    report["dependency_versions"] = deps

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
