"""AuditKIT integration adapter for TraceGuard.

Module 10 — Final Integration & Submission Readiness.
Member 2: Data & Interpretability Lead (in collaboration with Member 3).

Maps TraceGuard deterministic episode logs and configuration metrics into
official Lexsi Labs AuditKIT (1.1.3+) data representations:
- AgentEpisode & AgentEvent for multi-turn execution trajectories.
- RunResult for evaluation headlines, stats, and fingerprints.
- JSONL/JSON persistence compatible with the AuditKIT evaluation ecosystem.

Ensures TraceGuard deterministic evaluation remains the authoritative ground
truth, while providing full interoperability with the AuditKIT platform.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Union

from traceguard.data.schema import Episode
from traceguard.experiments.metrics import ConfigurationMetrics
from traceguard.runtime.logging import EpisodeExecutionLog, TurnExecutionRecord

logger = logging.getLogger(__name__)

# Check for native AuditKIT availability
try:
    import auditkit as ak
    from auditkit import AgentEpisode, AgentEvent, RunResult, Stat
    _AUDITKIT_AVAILABLE = True
except ImportError:
    _AUDITKIT_AVAILABLE = False
    ak = None
    AgentEpisode = None
    AgentEvent = None
    RunResult = None
    Stat = None


def is_auditkit_available() -> bool:
    """Return whether the native AuditKIT package is installed and importable."""
    return _AUDITKIT_AVAILABLE


def turn_to_auditkit_events(
    turn: TurnExecutionRecord, start_index: int = 0
) -> list[Any]:
    """Convert a TurnExecutionRecord into a sequence of AuditKIT AgentEvents."""
    if not _AUDITKIT_AVAILABLE:
        raise RuntimeError("AuditKIT is not installed. Install with `pip install auditkit`.")

    events: list[Any] = []
    idx = start_index
    call_id = f"turn{turn.turn_id}_call"

    # 1. User message event
    events.append(
        AgentEvent(
            index=idx,
            role="user",
            type="message",
            payload={"user_message": turn.user_message},
            turn_id=turn.turn_id,
            source="traceguard_runtime",
        )
    )
    idx += 1

    # 2. Model response / tool call event
    events.append(
        AgentEvent(
            index=idx,
            role="assistant",
            type="tool_call" if turn.parsed_tool else "message",
            payload={
                "raw_text": turn.model_raw_output,
                "parsed_kind": turn.parsed_kind,
                "tool_name": turn.parsed_tool,
                "arguments": turn.parsed_arguments,
                "argument_provenance": turn.argument_provenance,
                "parse_reason_code": turn.parse_reason_code,
                # AuditKIT call shape (``name``/``arguments``) so its tool-call
                # scorers can read the call; the TraceGuard keys above are kept.
                **(
                    {"name": turn.parsed_tool, "arguments": turn.parsed_arguments or {}}
                    if turn.parsed_tool
                    else {}
                ),
            },
            turn_id=turn.turn_id,
            call_id=call_id if turn.parsed_tool else None,
            source="traceguard_model",
        )
    )
    idx += 1

    # 3. Gateway decision event
    events.append(
        AgentEvent(
            index=idx,
            role="system",
            type="gateway_decision",
            payload={
                "gateway_decision": turn.gateway_decision,
                "gateway_reason": turn.gateway_reason,
                "gateway_detail": turn.gateway_detail,
                "canary_exposed": turn.canary_exposed,
                "prohibited_action_attempted": turn.prohibited_action_attempted,
            },
            turn_id=turn.turn_id,
            source="traceguard_gateway",
        )
    )
    idx += 1

    # 4. Tool execution result event (if executed)
    if turn.tool_executed:
        events.append(
            AgentEvent(
                index=idx,
                role="tool",
                type="tool_result",
                payload={
                    "tool_name": turn.parsed_tool,
                    "tool_result": turn.tool_result or {},
                    "prohibited_action_executed": turn.prohibited_action_executed,
                    "output": turn.tool_result or {},
                },
                turn_id=turn.turn_id,
                call_id=call_id,
                source="traceguard_simulated_tools",
            )
        )
        idx += 1

    return events


_OBSERVED = "observed"
_UNAVAILABLE = "unavailable"


def compute_coverage(events: Sequence[Any]) -> tuple[dict[str, str], dict[str, int]]:
    """Derive AuditKIT coverage flags from the events that were actually emitted.

    Nothing is assumed. A flag is ``observed`` only when the events prove it:

    * ``tool_call_names`` / ``tool_call_arguments``: at least one call-shaped
      ``tool_call`` event exists (arguments: every call carries a dict).
    * ``tool_results``: at least one ``tool_result`` exists and every call the
      gateway ALLOWED has one.
    * ``call_result_pairing``: at least one call is matched to a result by
      ``call_id`` and no allowed call is missing its result.

    A gateway-denied call never produces a result, so it is not a pair and never
    makes ``call_result_pairing`` (or ``tool_results``) observed by itself.
    Everything else is ``unavailable``. Also returns the counts behind the flags.
    """
    calls = [
        e for e in events
        if getattr(e, "type", None) == "tool_call"
        and isinstance(e.payload.get("name"), str)
        and e.payload.get("name")
    ]
    results = [e for e in events if getattr(e, "type", None) == "tool_result"]
    decisions = {
        e.turn_id: e.payload.get("gateway_decision")
        for e in events
        if getattr(e, "type", None) == "gateway_decision"
    }
    result_ids = {e.call_id for e in results if e.call_id}

    paired = [c for c in calls if c.call_id and c.call_id in result_ids]
    denied = [c for c in calls if decisions.get(c.turn_id) == "DENY"]
    allowed_missing = [
        c for c in calls
        if decisions.get(c.turn_id) == "ALLOW" and not (c.call_id and c.call_id in result_ids)
    ]

    def flag(ok: bool) -> str:
        return _OBSERVED if ok else _UNAVAILABLE

    coverage = {
        "tool_call_names": flag(bool(calls)),
        "tool_call_arguments": flag(
            bool(calls) and all(isinstance(c.payload.get("arguments"), dict) for c in calls)
        ),
        "tool_results": flag(bool(results) and not allowed_missing),
        "call_result_pairing": flag(bool(paired) and not allowed_missing),
    }
    detail = {
        "n_tool_calls": len(calls),
        "n_paired": len(paired),
        "n_denied": len(denied),
        "n_allowed_missing_result": len(allowed_missing),
    }
    return coverage, detail


def to_auditkit_episode(
    log: EpisodeExecutionLog, episode: Optional[Episode] = None
) -> Any:
    """Convert an EpisodeExecutionLog into an AuditKIT AgentEpisode."""
    if not _AUDITKIT_AVAILABLE:
        raise RuntimeError("AuditKIT is not installed. Install with `pip install auditkit`.")

    all_events: list[Any] = []
    current_idx = 0
    for turn in log.turns:
        t_events = turn_to_auditkit_events(turn, start_index=current_idx)
        all_events.extend(t_events)
        current_idx += len(t_events)

    source_scores: dict[str, float] = {
        "overall_passed": 1.0 if log.overall_passed else 0.0,
        "canary_leaked": 1.0 if log.canary_leaked else 0.0,
        "prohibited_action_taken": 1.0 if log.prohibited_action_taken else 0.0,
    }
    if log.attack_blocked is not None:
        source_scores["attack_blocked"] = 1.0 if log.attack_blocked else 0.0

    metadata: dict[str, Any] = {
        "template_id": log.template_id,
        "split": log.split,
        "is_attack": log.is_attack,
        "config_name": log.config_name,
        "turn_count": len(log.turns),
    }
    if episode is not None:
        metadata["attack_family"] = episode.attack_family
        metadata["authorized_scope"] = episode.authorized_scope
        metadata["synthetic_canaries"] = [c.value for c in episode.synthetic_canaries]

    coverage, coverage_detail = compute_coverage(all_events)

    agent_ep = AgentEpisode(
        case_id=log.episode_id,
        events=all_events,
        mode="recorded",
        source_format="traceguard/runtime_log/v1",
        source_id=log.episode_id,
        source_scores=source_scores,
        metadata=metadata,
        coverage=coverage,
    )
    agent_ep.metadata["coverage_detail"] = coverage_detail
    return agent_ep


def to_auditkit_run_result(
    metrics: ConfigurationMetrics,
    logs: Sequence[EpisodeExecutionLog],
    run_id: Optional[str] = None,
) -> Any:
    """Convert TraceGuard ConfigurationMetrics into an AuditKIT RunResult."""
    if not _AUDITKIT_AVAILABLE:
        raise RuntimeError("AuditKIT is not installed. Install with `pip install auditkit`.")

    rid = run_id or f"traceguard_{metrics.configuration}_{metrics.split}"

    # Headline rates
    headline: dict[str, float] = {
        "safety_score": float(metrics.overall_scores.safety_score),
        "utility_score": float(metrics.overall_scores.utility_score),
        "combined_score": float(metrics.overall_scores.combined_score),
        "attack_block_rate": float(metrics.attack_metrics.attack_block_rate.rate),
        "unsafe_tool_attempt_rate": float(metrics.attack_metrics.unsafe_tool_attempt_rate.rate),
        "canary_leak_rate": float(metrics.attack_metrics.canary_leak_rate.rate),
        "prohibited_action_rate": float(metrics.attack_metrics.prohibited_action_rate.rate),
        "benign_task_completion_rate": float(metrics.benign_metrics.benign_task_completion_rate.rate),
        "benign_false_positive_rate": float(metrics.benign_metrics.benign_false_positive_rate.rate),
    }

    def _make_stat(name: str, numerator: int, denominator: int) -> Any:
        st = Stat(name=name)
        if denominator > 0:
            for _ in range(numerator):
                st.add(1.0)
            for _ in range(max(0, denominator - numerator)):
                st.add(0.0)
        return st

    # AuditKIT Stat objects for comprehensive analytics
    stats: dict[str, Any] = {
        "attack_block_rate": _make_stat(
            "attack_block_rate",
            metrics.attack_metrics.attack_block_rate.numerator,
            metrics.attack_metrics.attack_block_rate.denominator,
        ),
        "canary_leak_rate": _make_stat(
            "canary_leak_rate",
            metrics.attack_metrics.canary_leak_rate.numerator,
            metrics.attack_metrics.canary_leak_rate.denominator,
        ),
        "benign_task_completion_rate": _make_stat(
            "benign_task_completion_rate",
            metrics.benign_metrics.benign_task_completion_rate.numerator,
            metrics.benign_metrics.benign_task_completion_rate.denominator,
        ),
    }

    raw_fingerprint = f"{rid}:{metrics.configuration}:{metrics.split}:{headline}"
    fp = hashlib.sha256(raw_fingerprint.encode("utf-8")).hexdigest()

    metadata: dict[str, Any] = {
        "configuration": metrics.configuration,
        "split": metrics.split,
        "attack_episodes_count": metrics.attack_episodes_count,
        "benign_episodes_count": metrics.benign_episodes_count,
        "total_episodes_count": len(logs),
        "formula": metrics.overall_scores.formula,
        "denominators": {
            "attack_block_rate": metrics.attack_metrics.attack_block_rate.to_dict(),
            "unsafe_tool_attempt_rate": metrics.attack_metrics.unsafe_tool_attempt_rate.to_dict(),
            "canary_leak_rate": metrics.attack_metrics.canary_leak_rate.to_dict(),
            "prohibited_action_rate": metrics.attack_metrics.prohibited_action_rate.to_dict(),
            "benign_task_completion_rate": metrics.benign_metrics.benign_task_completion_rate.to_dict(),
            "benign_false_positive_rate": metrics.benign_metrics.benign_false_positive_rate.to_dict(),
        },
    }

    return RunResult(
        run_id=rid,
        fingerprint=fp,
        stats=stats,
        predictions=[],
        headline=headline,
        metadata=metadata,
        experiment_name=f"TraceGuard {metrics.configuration}",
    )


def export_auditkit_evaluation(
    metrics: ConfigurationMetrics,
    logs: Sequence[EpisodeExecutionLog],
    output_dir: Union[str, Path],
    episodes_map: Optional[Mapping[str, Episode]] = None,
) -> dict[str, Path]:
    """Export AuditKIT AgentEpisodes and RunResult to disk."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    if not _AUDITKIT_AVAILABLE:
        logger.warning("AuditKIT not available; skipping AuditKIT export.")
        summary_path = out_path / f"auditkit_status_{metrics.configuration}.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "status": "NOT_RUN",
                    "reason": "AuditKIT package not available in environment",
                    "metrics": metrics.to_dict(),
                },
                f,
                indent=2,
            )
        return {"status": summary_path}

    episodes_file = out_path / f"auditkit_episodes_{metrics.configuration}_{metrics.split}.jsonl"
    with open(episodes_file, "w", encoding="utf-8") as f:
        for log in logs:
            ep = episodes_map.get(log.episode_id) if episodes_map else None
            ak_ep = to_auditkit_episode(log, episode=ep)
            f.write(json.dumps(ak_ep.to_dict(), ensure_ascii=False) + "\n")

    run_result = to_auditkit_run_result(metrics, logs)
    result_file = out_path / f"auditkit_run_result_{metrics.configuration}_{metrics.split}.json"
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(run_result.to_dict(), f, indent=2, ensure_ascii=False)

    return {
        "episodes": episodes_file,
        "run_result": result_file,
    }
