"""Analysis CLI — Phase 4/6 orchestrator (model-free, deterministic).

Usage:
    python -m traceguard.experiments.run_analysis \
        --input results/analysis/<run_id>/<config>.jsonl ... \
        --out results/analysis/<run_id>/report/ \
        [--allow-test-split]   # ONLY after the configuration freeze

Inputs are per-configuration episode-result JSONL files in schema draft-v0
(emitted by the future benchmark runtime / Member-3 harness; see
docs/GATEWAY_CONTRACT.md). The pipeline: validate -> score -> aggregate ->
pair (E0 vs each of E1..E4, plus E2a vs E2b) -> report. Placeholder inputs
propagate into every artifact.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from traceguard.experiments.episode_scoring import EpisodeScore, score_episode
from traceguard.experiments.metrics import aggregate, metrics_table
from traceguard.experiments.paired_analysis import paired_comparison
from traceguard.experiments.reporting import (
    build_manifest,
    render_markdown,
    write_outputs,
)
from traceguard.experiments.results_schema import (
    EpisodeResult,
    HeldOutDataError,
    SchemaError,
    check_homogeneous,
    load_episode_results,
)

#: Which pairs the report always attempts (only those with data on both sides).
STANDARD_PAIRS = (
    ("E0", "E1"),
    ("E0", "E2a"),
    ("E0", "E2b"),
    ("E0", "E3"),
    ("E0", "E4"),
    ("E2a", "E2b"),
)


def _load_all(
    inputs: Sequence[Path], allow_test_split: bool
) -> tuple[list[EpisodeResult], dict[str, object]]:
    records: list[EpisodeResult] = []
    for path in inputs:
        records.extend(load_episode_results(path, allow_test_split=allow_test_split))
    identity = check_homogeneous(records, "run_analysis input set")
    return records, identity


def run(
    inputs: Sequence[Path],
    out_dir: Path,
    allow_test_split: bool = False,
) -> dict[str, Path]:
    records, identity = _load_all(inputs, allow_test_split)

    scores: list[EpisodeScore] = [score_episode(rec) for rec in records]
    metrics_rows = aggregate(scores)
    table_rows = metrics_table(metrics_rows)

    by_config: dict[str, list[EpisodeScore]] = {}
    for score in scores:
        by_config.setdefault(score.configuration, []).append(score)

    comparisons = []
    for baseline, treatment in STANDARD_PAIRS:
        if baseline in by_config and treatment in by_config:
            comparisons.append(
                paired_comparison(by_config[baseline], by_config[treatment])
            )

    any_placeholder = any(score.placeholder for score in scores)
    notes: list[str] = []
    if any_placeholder:
        n = sum(1 for s in scores if s.placeholder)
        notes.append(
            f"{n}/{len(scores)} episodes are PLACEHOLDER records — this run "
            "validates the analysis pipeline, not any model."
        )

    report_md = render_markdown(
        identity=identity,
        metrics_rows=metrics_rows,
        comparisons=comparisons,
        any_placeholder=any_placeholder,
        episode_scores=scores,
        notes=notes,
    )
    manifest = build_manifest(
        input_paths=inputs,
        identity=identity,
        extra={
            "configurations_present": sorted(by_config),
            "pairs_compared": [
                [c.baseline_configuration, c.treatment_configuration]
                for c in comparisons
            ],
            "any_placeholder": any_placeholder,
            "allow_test_split": allow_test_split,
        },
    )
    return write_outputs(
        out_dir,
        report_md=report_md,
        table_rows=table_rows,
        comparisons=comparisons,
        episode_scores=scores,
        manifest=manifest,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True,
                        help="episode-result JSONL (repeatable)")
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument("--allow-test-split", action="store_true",
                        help="ONLY after configuration freeze")
    args = parser.parse_args(argv)

    try:
        paths = run(
            [Path(p) for p in args.input],
            Path(args.out),
            allow_test_split=args.allow_test_split,
        )
    except (SchemaError, HeldOutDataError, ValueError) as exc:
        print(f"analysis failed: {exc}", file=sys.stderr)
        return 2
    for name, path in paths.items():
        print(f"wrote {name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
