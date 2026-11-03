"""Reproducible report generation (Markdown + CSV + JSON, sha256-stamped).

Every report:
* carries the exact input inventory (path + sha256) and package versions,
* states the placeholder banner whenever ANY input record is placeholder,
* restates the canary-matching and over-refusal heuristics limitations,
* refuses to render cross-model comparisons (single model_id enforced upstream).
"""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from traceguard.experiments.episode_scoring import MATCH_LIMITATION_NOTE
from traceguard.experiments.metrics import (
    ATTACK_METRICS,
    BENIGN_METRICS,
    ConfigurationMetrics,
    metrics_table,
)
from traceguard.experiments.paired_analysis import (
    POWER_LIMITATION_NOTE,
    PairedComparison,
)

PLACEHOLDER_BANNER = (
    "> **⚠ PLACEHOLDER DATA — NOT BENCHMARK RESULTS.** One or more input "
    "episodes are synthetic stand-ins (`placeholder: true`) used to validate "
    "the analysis pipeline itself. No claim about any model's safety is made "
    "or implied by numbers in this report."
)

_PACKAGE_NAMES = ("safetune", "torch", "transformers")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def environment_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }
    for name in _PACKAGE_NAMES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def build_manifest(
    input_paths: Iterable[Path],
    identity: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reproducibility manifest: inputs (sha256), identity, environment."""
    manifest: dict[str, Any] = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "identity": identity,
        "inputs": [
            {"path": str(p), "sha256": sha256_file(Path(p))} for p in input_paths
        ],
        "environment": environment_versions(),
    }
    if extra:
        manifest["extra"] = extra
    return manifest


def _fmt_cell(row: ConfigurationMetrics, metric: str) -> str:
    cell = row.metrics.get(metric)
    if cell is None:
        return "—"
    pct = "n/a" if cell.percentage is None else f"{cell.percentage:.1f}%"
    return f"{cell.numerator}/{cell.denominator} ({pct})"


def render_markdown(
    *,
    identity: dict[str, Any],
    metrics_rows: Sequence[ConfigurationMetrics],
    comparisons: Sequence[PairedComparison],
    any_placeholder: bool,
    episode_scores: Sequence[Any],
    notes: Sequence[str] = (),
) -> str:
    """Render the human-readable analysis report."""
    lines: list[str] = []
    lines.append("# TraceGuard E0–E4 Analysis Report (draft schema v0)")
    lines.append("")
    if any_placeholder:
        lines.append(PLACEHOLDER_BANNER)
        lines.append("")
    lines.append("## Run identity")
    lines.append("")
    for key, value in identity.items():
        lines.append(f"- **{key}**: `{value}`")
    lines.append("")

    lines.append("## Aggregate metrics (raw counts / denominator, percentage)")
    lines.append("")
    header = ["config", "group", "n"] + [
        m.replace("_rate", "") for m in ATTACK_METRICS + BENIGN_METRICS
    ]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "---|" * len(header))
    for row in metrics_rows:
        cells = [row.configuration, row.group, str(row.episodes)]
        for metric in ATTACK_METRICS + BENIGN_METRICS:
            cells.append(_fmt_cell(row, metric))
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")

    lines.append("## Paired episode-level changes")
    lines.append("")
    lines.append(f"_{POWER_LIMITATION_NOTE}_")
    lines.append("")
    for comparison in comparisons:
        lines.append(
            f"### {comparison.baseline_configuration} → {comparison.treatment_configuration}"
        )
        lines.append("")
        lines.append(
            f"Matched episodes: **{comparison.matched_episodes}**; "
            f"unmatched baseline: {comparison.unmatched_baseline or 'none'}; "
            f"unmatched treatment: {comparison.unmatched_treatment or 'none'}"
        )
        lines.append("")
        if comparison.outcome_counts:
            lines.append(
                "| outcome | both true | baseline-only | treatment-only | both false | net Δ |"
            )
            lines.append("|---|---|---|---|---|---|")
            for outcome, counts in comparison.outcome_counts.items():
                d = counts.to_dict()
                lines.append(
                    f"| {outcome} | {d['both_true']} | {d['baseline_only_true']} | "
                    f"{d['treatment_only_true']} | {d['both_false']} | "
                    f"{d['net_change_treatment_minus_baseline']:+d} |"
                )
            lines.append("")
        if comparison.episode_changes:
            lines.append("<details><summary>Per-episode change audit trail</summary>")
            lines.append("")
            for episode_id, changes in comparison.episode_changes.items():
                for change in changes:
                    lines.append(f"- `{episode_id}`: {change}")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    lines.append("## Failure-mode notes")
    lines.append("")
    lines.append(f"- {_canary_note()}")
    lines.append(
        "- Over-refusal on benign episodes uses conservative transcript refusal "
        "markers plus ledger evidence; it is the one non-fully-deterministic "
        "outcome and is flagged as heuristic wherever reported."
    )
    mode_counts: dict[str, int] = {}
    for score in episode_scores:
        if score.failure_mode:
            mode_counts[score.failure_mode] = mode_counts.get(score.failure_mode, 0) + 1
    if mode_counts:
        lines.append(
            "- Observed attack failure modes (counts): "
            + ", ".join(f"{k}={v}" for k, v in sorted(mode_counts.items()))
        )
    for note in notes:
        lines.append(f"- {note}")
    lines.append("")
    lines.append(
        "_This report is generated mechanically from the episode-result logs; "
        "no numbers were edited by hand. See manifest.json for input checksums._"
    )
    lines.append("")
    return "\n".join(lines)


def _canary_note() -> str:
    return MATCH_LIMITATION_NOTE


def write_outputs(
    out_dir: Path,
    *,
    report_md: str,
    table_rows: Sequence[dict[str, Any]],
    comparisons: Sequence[PairedComparison],
    episode_scores: Sequence[Any],
    manifest: dict[str, Any],
) -> dict[str, Path]:
    """Write report.md, metrics.csv, paired.json, episode_scores.jsonl, manifest.json."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    paths["report_md"] = out_dir / "report.md"
    paths["report_md"].write_text(report_md, encoding="utf-8")

    paths["metrics_csv"] = out_dir / "metrics.csv"
    if table_rows:
        with paths["metrics_csv"].open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(table_rows[0].keys()))
            writer.writeheader()
            writer.writerows(table_rows)

    paths["paired_json"] = out_dir / "paired.json"
    paths["paired_json"].write_text(
        json.dumps([c.to_dict() for c in comparisons], indent=2), encoding="utf-8"
    )

    paths["episode_scores"] = out_dir / "episode_scores.jsonl"
    with paths["episode_scores"].open("w", encoding="utf-8") as fh:
        for score in episode_scores:
            fh.write(json.dumps(score.to_dict(), ensure_ascii=False) + "\n")

    paths["manifest"] = out_dir / "manifest.json"
    paths["manifest"].write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return paths
