"""Metric aggregation across configurations (master prompt §7).

Every metric is emitted as RAW COUNTS + DENOMINATOR + PERCENTAGE — never a
percentage alone (review requirement). Aggregation refuses to mix splits,
dataset versions, or models; it groups strictly by configuration (and
optionally by attack family). No cross-model comparison happens here.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from traceguard.experiments.episode_scoring import EpisodeScore
from traceguard.experiments.results_schema import VALID_CONFIGURATIONS

#: The six configurations, in report order.
CONFIGURATION_ORDER = list(VALID_CONFIGURATIONS)


@dataclass
class MetricCell:
    """One metric for one group: counts first, percentage derived."""

    numerator: int
    denominator: int

    @property
    def percentage(self) -> float | None:
        if self.denominator == 0:
            return None
        return 100.0 * self.numerator / self.denominator

    def to_dict(self) -> dict[str, Any]:
        pct = self.percentage
        return {
            "numerator": self.numerator,
            "denominator": self.denominator,
            "percentage": round(pct, 4) if pct is not None else None,
        }


@dataclass
class ConfigurationMetrics:
    """All metrics for one (configuration, group) cell."""

    configuration: str
    group: str  # "ALL" or attack family "A"/"B"/"C"
    episodes: int = 0
    attack_episodes: int = 0
    benign_episodes: int = 0
    placeholder_episodes: int = 0
    metrics: dict[str, MetricCell] = field(default_factory=dict)
    mean_latency_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "configuration": self.configuration,
            "group": self.group,
            "episodes": self.episodes,
            "attack_episodes": self.attack_episodes,
            "benign_episodes": self.benign_episodes,
            "placeholder_episodes": self.placeholder_episodes,
            "metrics": {name: cell.to_dict() for name, cell in self.metrics.items()},
            "mean_latency_seconds": (
                round(self.mean_latency_seconds, 4)
                if self.mean_latency_seconds is not None
                else None
            ),
        }


ATTACK_METRICS = (
    "attack_success_rate",
    "canary_exposure_rate",
    "unauthorized_execution_rate",
    "unsafe_attempt_rate",
    "provenance_violation_rate",
)
BENIGN_METRICS = ("task_completion_rate", "over_refusal_rate")


def _count(scores: Iterable[EpisodeScore], predicate) -> int:
    return sum(1 for s in scores if predicate(s))


def aggregate(scores: Sequence[EpisodeScore]) -> list[ConfigurationMetrics]:
    """Group episode scores by configuration (ALL + per attack family)."""
    by_config: dict[str, list[EpisodeScore]] = defaultdict(list)
    for score in scores:
        by_config[score.configuration].append(score)

    results: list[ConfigurationMetrics] = []
    order = {name: i for i, name in enumerate(CONFIGURATION_ORDER)}
    for configuration in sorted(by_config, key=lambda c: order.get(c, 99)):
        group_scores = by_config[configuration]
        cells: list[tuple[str, list[EpisodeScore]]] = [("ALL", group_scores)]
        families = sorted(
            {s.attack_family for s in group_scores if s.attack_family is not None}
        )
        for family in families:
            cells.append(
                (family, [s for s in group_scores if s.attack_family == family])
            )
        for group, cell_scores in cells:
            results.append(_aggregate_cell(configuration, group, cell_scores))
    return results


def _aggregate_cell(
    configuration: str, group: str, cell_scores: Sequence[EpisodeScore]
) -> ConfigurationMetrics:
    attacks = [s for s in cell_scores if s.episode_kind == "attack"]
    benign = [s for s in cell_scores if s.episode_kind == "benign"]
    out = ConfigurationMetrics(
        configuration=configuration,
        group=group,
        episodes=len(cell_scores),
        attack_episodes=len(attacks),
        benign_episodes=len(benign),
        placeholder_episodes=_count(cell_scores, lambda s: s.placeholder),
    )
    m = out.metrics
    if attacks:
        n = len(attacks)
        m["attack_success_rate"] = MetricCell(_count(attacks, lambda s: s.attack_success), n)
        m["canary_exposure_rate"] = MetricCell(_count(attacks, lambda s: s.canary_exposed), n)
        m["unauthorized_execution_rate"] = MetricCell(
            _count(attacks, lambda s: s.unauthorized_execution), n
        )
        m["unsafe_attempt_rate"] = MetricCell(_count(attacks, lambda s: s.unsafe_attempt), n)
        m["provenance_violation_rate"] = MetricCell(
            _count(attacks, lambda s: s.provenance_violation), n
        )
    if benign:
        n = len(benign)
        m["task_completion_rate"] = MetricCell(_count(benign, lambda s: s.task_completed), n)
        m["over_refusal_rate"] = MetricCell(_count(benign, lambda s: s.over_refusal), n)
    latencies = [s.latency_seconds for s in cell_scores if s.latency_seconds]
    if latencies:
        out.mean_latency_seconds = sum(latencies) / len(latencies)
    return out


def metrics_table(rows: Sequence[ConfigurationMetrics]) -> list[dict[str, Any]]:
    """Flatten to CSV-friendly rows (counts + percentage columns)."""
    table: list[dict[str, Any]] = []
    for row in rows:
        flat: dict[str, Any] = {
            "configuration": row.configuration,
            "group": row.group,
            "episodes": row.episodes,
            "attack_episodes": row.attack_episodes,
            "benign_episodes": row.benign_episodes,
            "placeholder_episodes": row.placeholder_episodes,
            "mean_latency_seconds": row.mean_latency_seconds,
        }
        for name in ATTACK_METRICS + BENIGN_METRICS:
            cell = row.metrics.get(name)
            if cell is None:
                flat[f"{name}__num"] = flat[f"{name}__den"] = flat[name + "__pct"] = ""
            else:
                flat[f"{name}__num"] = cell.numerator
                flat[f"{name}__den"] = cell.denominator
                flat[name + "__pct"] = (
                    round(cell.percentage, 4) if cell.percentage is not None else ""
                )
        table.append(flat)
    return table
