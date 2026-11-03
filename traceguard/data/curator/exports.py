"""Export utilities for TraceGuard curated datasets and downstream trainer-ready formats."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from traceguard.data.schema import Episode

logger = logging.getLogger(__name__)


def export_full_fidelity_jsonl(episodes: list[Episode], output_path: str | Path) -> Path:
    """Export episodes in canonical full-fidelity TraceGuard JSONL format."""
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    with open(p, "w", encoding="utf-8") as f:
        for ep in episodes:
            f.write(ep.to_json() + "\n")

    return p


def export_trainer_ready_conversations(
    episodes: list[Episode], output_path: str | Path
) -> Path:
    """Export episodes as conversation projections for downstream SFT / alignment trainers.

    ARCHITECTURAL SPECIFICATION & CAVEATS:
    1. PROJECTION ONLY: These conversational exports are lossy projections of structured
       TraceGuard Episode objects into multi-turn dialogue text (ShareGPT/ChatML style).
       They flatten structured execution trees, authorization ledgers, and tool payloads
       into conversational strings for exploratory training.
    2. NOT A LOSSLESS REPLACEMENT: These files must never be used in place of canonical
       TraceGuard JSONL datasets (traceguard/data/curated/*.jsonl) for evaluation,
       runtime gateway execution, or provenance ablation experiments.
    3. NOT CONFIRMED SAFETUNE INPUTS: These projections do not represent verified or
       confirmed training inputs for SafeTune. SafeTune fine-tuning pipelines require
       their own distinct schema validation and tokenizer formatting.
    """
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    with open(p, "w", encoding="utf-8") as f:
        for ep in episodes:
            messages = [
                {
                    "role": "system",
                    "content": f"Task: {ep.initial_user_task}\nAuthorized Scope: {ep.authorized_scope}",
                }
            ]
            for t in ep.turns:
                turn_msg = f"Turn {t.turn_id}: {t.user_message}"
                sources = []
                for s in t.source_records:
                    lbl = s.provenance.value if hasattr(s.provenance, "value") else str(s.provenance)
                    sources.append(f"[{s.source_type} (provenance: {lbl})]: {s.content}")
                if sources:
                    turn_msg += "\nContext:\n" + "\n".join(sources)

                messages.append({"role": "user", "content": turn_msg})
                if t.expected_action:
                    messages.append(
                        {"role": "assistant", "content": json.dumps(t.expected_action)}
                    )

            row = {
                "id": ep.episode_id,
                "template_id": ep.template_id,
                "split": ep.split,
                "is_attack": ep.is_attack,
                "attack_family": ep.attack_family,
                "conversations": messages,
                "expected_safe_behavior": ep.expected_safe_behavior,
                "expected_prohibited_actions": ep.expected_prohibited_actions,
                "synthetic_canaries": [c.value for c in ep.synthetic_canaries],
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    return p
