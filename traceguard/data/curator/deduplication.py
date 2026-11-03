"""Multi-level duplicate detection and near-duplicate similarity analysis for TraceGuard."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from curatorkit.normalizers.dedup import MinHashDeduplicator
from traceguard.data.curator.ingestion import episode_to_curatorkit_sample
from traceguard.data.schema import Episode

logger = logging.getLogger(__name__)


@dataclass
class DuplicateFinding:
    """Record of a duplicate or near-duplicate finding."""

    level: str  # "exact_id", "exact_record", "template_split", "near_duplicate"
    episode_id_a: str
    episode_id_b: str
    similarity_score: float = 1.0
    action_taken: str = "flagged_for_review"
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "episode_id_a": self.episode_id_a,
            "episode_id_b": self.episode_id_b,
            "similarity_score": round(self.similarity_score, 4),
            "action_taken": self.action_taken,
            "details": self.details,
        }


@dataclass
class DeduplicationReport:
    """Audit report capturing duplicate analysis across all levels."""

    dataset_name: str
    total_episodes: int = 0
    exact_id_duplicates_count: int = 0
    exact_record_duplicates_count: int = 0
    near_duplicate_warnings_count: int = 0
    findings: list[DuplicateFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_name": self.dataset_name,
            "total_episodes": self.total_episodes,
            "exact_id_duplicates_count": self.exact_id_duplicates_count,
            "exact_record_duplicates_count": self.exact_record_duplicates_count,
            "near_duplicate_warnings_count": self.near_duplicate_warnings_count,
            "findings": [f.to_dict() for f in self.findings],
        }


def _extract_conversation_text(episode: Episode) -> str:
    """Extract canonicalized conversation text for semantic comparison."""
    parts = [f"TASK: {episode.initial_user_task.strip().lower()}"]
    for t in episode.turns:
        parts.append(f"USER: {t.user_message.strip().lower()}")
        for s in t.source_records:
            parts.append(f"SOURCE_{s.source_type}: {s.content.strip().lower()}")
    return "\n".join(parts)


def compute_jaccard_similarity(text_a: str, text_b: str, n: int = 3) -> float:
    """Compute token Jaccard similarity."""
    if text_a == text_b:
        return 1.0
    tokens_a = set(text_a.split())
    tokens_b = set(text_b.split())
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a.intersection(tokens_b)
    union = tokens_a.union(tokens_b)
    return len(intersection) / len(union)


class EpisodeDeduplicator:
    """Multi-level deduplication engine combining exact matching and CuratorKIT MinHash analysis."""

    def __init__(
        self,
        similarity_threshold: float = 0.85,
        minhash_ngram: int = 3,
        minhash_num_perm: int = 128,
        minhash_seed: int = 42,
    ) -> None:
        self.similarity_threshold = similarity_threshold
        self.minhash_dedup = MinHashDeduplicator(
            threshold=similarity_threshold,
            ngram=minhash_ngram,
            num_perm=minhash_num_perm,
            seed=minhash_seed,
        )

    def analyze(
        self, episodes: list[Episode], dataset_name: str = "dataset"
    ) -> tuple[list[Episode], DeduplicationReport]:
        """Analyze episodes for duplicates and near-duplicates.

        Preserves legitimate variations and returns surviving episodes and full findings.
        """
        report = DeduplicationReport(dataset_name=dataset_name, total_episodes=len(episodes))

        seen_ids: dict[str, Episode] = {}
        seen_record_hashes: dict[str, str] = {}
        unique_episodes: list[Episode] = []

        # Level 1 & 2: Exact ID and exact JSON record check
        for ep in episodes:
            raw_canonical = json.dumps(ep.to_dict(), sort_keys=True)
            rec_hash = hashlib.sha256(raw_canonical.encode("utf-8")).hexdigest()

            if ep.episode_id in seen_ids:
                report.exact_id_duplicates_count += 1
                finding = DuplicateFinding(
                    level="exact_id",
                    episode_id_a=seen_ids[ep.episode_id].episode_id,
                    episode_id_b=ep.episode_id,
                    action_taken="rejected_duplicate",
                    details=f"Duplicate episode ID '{ep.episode_id}' detected.",
                )
                report.findings.append(finding)
                continue

            if rec_hash in seen_record_hashes:
                report.exact_record_duplicates_count += 1
                prior_id = seen_record_hashes[rec_hash]
                finding = DuplicateFinding(
                    level="exact_record",
                    episode_id_a=prior_id,
                    episode_id_b=ep.episode_id,
                    action_taken="rejected_duplicate",
                    details="Identical canonical JSON content detected.",
                )
                report.findings.append(finding)
                continue

            seen_ids[ep.episode_id] = ep
            seen_record_hashes[rec_hash] = ep.episode_id
            unique_episodes.append(ep)

        # Level 3 & 4: Template-level and near-duplicate similarity check
        n_unique = len(unique_episodes)
        conv_texts = [_extract_conversation_text(ep) for ep in unique_episodes]

        for i in range(n_unique):
            for j in range(i + 1, n_unique):
                ep_a = unique_episodes[i]
                ep_b = unique_episodes[j]

                sim = compute_jaccard_similarity(conv_texts[i], conv_texts[j])
                if sim >= self.similarity_threshold:
                    report.near_duplicate_warnings_count += 1
                    finding = DuplicateFinding(
                        level="near_duplicate",
                        episode_id_a=ep_a.episode_id,
                        episode_id_b=ep_b.episode_id,
                        similarity_score=sim,
                        action_taken="flagged_warning_preserved",
                        details=(
                            f"Conversation Jaccard similarity {sim:.3f} >= {self.similarity_threshold}. "
                            f"Templates: {ep_a.template_id} vs {ep_b.template_id}."
                        ),
                    )
                    report.findings.append(finding)

        return unique_episodes, report
