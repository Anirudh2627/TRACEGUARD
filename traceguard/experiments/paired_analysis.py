"""Paired episode-level analysis across two configurations.

Every episode is matched by ``episode_id`` between a baseline configuration
and a treatment configuration; unmatched ids are reported explicitly (never
silently dropped). For each binary outcome we report the 2x2 discordant
counts (McNemar-style: improved / worsened / unchanged). 

STATISTICAL HONESTY: with the dev protocol (15 attacks + 15 benign per
configuration), one episode = 6.7 percentage points; we report DESCRIPTIVE
discordant counts only. No p-values, no significance claims — the report
template states the power limitation verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from traceguard.experiments.episode_scoring import EpisodeScore

#: Outcomes compared pairwise (baseline -> treatment).
PAIRED_OUTCOMES = (
    "attack_success",
    "canary_exposed",
    "unauthorized_execution",
    "unsafe_attempt",
    "provenance_violation",
    "task_completed",
    "over_refusal",
)


@dataclass
class OutcomePairCounts:
    """2x2 counts for one outcome: (baseline_true, treatment_true)."""

    both_true: int = 0
    baseline_only: int = 0  # baseline bad/true, treatment false -> "improved"
    treatment_only: int = 0  # treatment true, baseline false -> "worsened"
    both_false: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "both_true": self.both_true,
            "baseline_only_true": self.baseline_only,
            "treatment_only_true": self.treatment_only,
            "both_false": self.both_false,
            "net_change_treatment_minus_baseline": self.treatment_only - self.baseline_only,
        }


@dataclass
class PairedComparison:
    """Full paired diff between two configurations."""

    baseline_configuration: str
    treatment_configuration: str
    matched_episodes: int = 0
    unmatched_baseline: list[str] = field(default_factory=list)
    unmatched_treatment: list[str] = field(default_factory=list)
    #: outcome -> PAIRED_OUTCOMES counts (only where the outcome applies)
    outcome_counts: dict[str, OutcomePairCounts] = field(default_factory=dict)
    #: episode_id -> list of human-readable changes (audit trail)
    episode_changes: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_configuration": self.baseline_configuration,
            "treatment_configuration": self.treatment_configuration,
            "matched_episodes": self.matched_episodes,
            "unmatched_baseline": self.unmatched_baseline,
            "unmatched_treatment": self.unmatched_treatment,
            "outcome_counts": {k: v.to_dict() for k, v in self.outcome_counts.items()},
            "episode_changes": self.episode_changes,
        }


def _index(scores: Sequence[EpisodeScore]) -> dict[str, EpisodeScore]:
    out: dict[str, EpisodeScore] = {}
    for score in scores:
        if score.episode_id in out:
            raise ValueError(
                f"duplicate episode_id {score.episode_id!r} in configuration "
                f"{score.configuration!r} — pairing requires unique ids"
            )
        out[score.episode_id] = score
    return out


def _outcome_value(score: EpisodeScore, outcome: str) -> bool | None:
    value = getattr(score, outcome)
    return None if value is None else bool(value)


def paired_comparison(
    baseline_scores: Sequence[EpisodeScore],
    treatment_scores: Sequence[EpisodeScore],
) -> PairedComparison:
    """Match episodes by id and diff every applicable binary outcome."""
    base_idx, treat_idx = _index(baseline_scores), _index(treatment_scores)
    if not base_idx or not treat_idx:
        raise ValueError("paired comparison requires non-empty score sets")
    base_conf = next(iter(base_idx.values())).configuration
    treat_conf = next(iter(treat_idx.values())).configuration
    comparison = PairedComparison(
        baseline_configuration=base_conf, treatment_configuration=treat_conf
    )
    comparison.unmatched_baseline = sorted(set(base_idx) - set(treat_idx))
    comparison.unmatched_treatment = sorted(set(treat_idx) - set(base_idx))

    for episode_id in sorted(set(base_idx) & set(treat_idx)):
        base, treat = base_idx[episode_id], treat_idx[episode_id]
        if base.episode_kind != treat.episode_kind:
            raise ValueError(
                f"episode {episode_id!r}: kind mismatch between configurations "
                f"({base.episode_kind!r} vs {treat.episode_kind!r})"
            )
        comparison.matched_episodes += 1
        changes: list[str] = []
        for outcome in PAIRED_OUTCOMES:
            b, t = _outcome_value(base, outcome), _outcome_value(treat, outcome)
            if b is None or t is None:
                continue  # outcome not applicable to this episode kind
            counts = comparison.outcome_counts.setdefault(outcome, OutcomePairCounts())
            if b and t:
                counts.both_true += 1
            elif b and not t:
                counts.baseline_only += 1
                changes.append(f"{outcome}: True->{False} (baseline-only)")
            elif t and not b:
                counts.treatment_only += 1
                changes.append(f"{outcome}: False->True (treatment-only)")
            else:
                counts.both_false += 1
        if changes:
            comparison.episode_changes[episode_id] = changes
    return comparison


POWER_LIMITATION_NOTE = (
    "Paired differences are DESCRIPTIVE. With the dev protocol (15 attacks + "
    "15 benign per configuration) one episode equals 6.7 percentage points; "
    "discordant counts at this n do not support significance claims and none "
    "are made here."
)
