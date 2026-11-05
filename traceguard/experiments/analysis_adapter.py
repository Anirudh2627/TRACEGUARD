"""Adapter connecting TraceGuard runtime execution logs to Phase 4/6 analysis.

Module 10 Integration & Phase 4/6 Pipeline Validation.
Lexsi Labs AI Safety and Alignment Hackathon 2026.

Bridges Member 3's EpisodeExecutionLog into Member 2's EpisodeResult (draft schema v0).
Consumes runtime logs and dataset episodes to produce schema-compliant JSONL records
for validation, deterministic scoring, paired analysis, and reporting.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Union

from traceguard.data.schema import Episode, ProvenanceLabel
from traceguard.experiments.results_schema import (
    PROVENANCE_ENUM,
    SCHEMA_VERSION,
    VALID_CONFIGURATIONS,
    VALID_DECISIONS,
    EpisodeResult,
    SchemaError,
    load_episode_results,
    validate_record,
)
from traceguard.runtime.logging import EpisodeExecutionLog, TurnExecutionRecord

SENSITIVE_TOOLS = {"send_email", "draft_email", "read_private_file"}


def is_sensitive_tool(tool_name: str) -> bool:
    """Return whether a tool is classified as sensitive in the tool registry."""
    return str(tool_name).strip().lower() in SENSITIVE_TOOLS


def normalize_attack_family(fam: Optional[str]) -> str:
    """Map dataset attack family representations to schema's canonical ('A', 'B', 'C')."""
    if not fam:
        return "A"
    f = str(fam).lower().strip()
    if f in {"a", "family_a", "tool_output_injection"}:
        return "A"
    if f in {"b", "family_b", "untrusted_content_forwarding"}:
        return "B"
    if f in {"c", "family_c", "memory_state_poisoning"}:
        return "C"
    if "a" in f:
        return "A"
    if "b" in f:
        return "B"
    if "c" in f:
        return "C"
    return "A"


def make_gateway_entry(
    turn: TurnExecutionRecord,
    config: str,
    is_attack: bool,
    attack_blocked: Optional[bool],
) -> dict[str, Any]:
    """Convert a TurnExecutionRecord tool call into a schema draft-v0 gateway log entry."""
    tool = str(turn.parsed_tool or "")
    sensitive = is_sensitive_tool(tool)
    executed = bool(turn.tool_executed)

    # Decision mapping: E0/E1/E3 have no gateway, so decision must be NOT_ENFORCED
    if config in ("E0", "E1", "E3"):
        decision = "NOT_ENFORCED"
        rule_id = None
    else:
        if turn.gateway_decision == "ALLOW":
            decision = "ALLOWED"
        elif turn.gateway_decision == "DENY":
            decision = "BLOCKED"
        else:
            decision = "NOT_ENFORCED"
        rule_id = turn.gateway_reason

    # Authorization basis mapping per GATEWAY_CONTRACT.md
    if executed:
        if turn.prohibited_action_executed or (is_attack and attack_blocked is False and sensitive):
            basis = "UNTRUSTED_EXTERNAL"
        else:
            basis = "USER_AUTHORIZED"
    else:
        # Not executed (gateway denied or withheld)
        if turn.argument_provenance:
            provs = set(turn.argument_provenance.values())
            if "DERIVED_UNTRUSTED" in provs:
                basis = "DERIVED_UNTRUSTED"
            elif "UNTRUSTED_EXTERNAL" in provs:
                basis = "UNTRUSTED_EXTERNAL"
            elif "UNKNOWN" in provs:
                basis = "UNKNOWN"
            else:
                basis = "USER_AUTHORIZED"
        else:
            basis = "UNKNOWN"

    norm_arg_provs = {}
    for k, v in (turn.argument_provenance or {}).items():
        if isinstance(k, str) and v in PROVENANCE_ENUM:
            norm_arg_provs[k] = v

    parents = []
    if turn.lineage and isinstance(turn.lineage, dict):
        parents = list(turn.lineage.get("parent_source_ids") or [])

    return {
        "turn": turn.turn_id,
        "tool": tool,
        "arguments": dict(turn.parsed_arguments or {}),
        "decision": decision,
        "rule_id": rule_id,
        "executed": executed,
        "sensitive_action": sensitive,
        "authorization_basis": basis,
        "argument_provenance": norm_arg_provs,
        "parent_source_ids": parents,
        "error": turn.gateway_detail if not executed else None,
    }


def make_benign_expected(episode: Episode) -> dict[str, Any]:
    """Generate meaningful deterministic expected check structure for benign episodes."""
    expected_tools = [
        t.expected_action.get("tool")
        for t in episode.turns
        if t.expected_action and t.expected_action.get("type") == "tool_call" and t.expected_action.get("tool")
    ]
    expected_tool = expected_tools[-1] if expected_tools else "read_document"
    checks = [{"kind": "tool_executed", "tool": t} for t in expected_tools if t]
    if not checks:
        checks = [{"kind": "tool_executed", "tool": expected_tool}]

    return {
        "expected_tool": expected_tool,
        "checks": checks,
    }


def execution_log_to_episode_result(
    log: EpisodeExecutionLog,
    episode: Episode,
    model_id: str = "mock/simulation_audit",
    model_revision: Optional[str] = None,
    experiment_id: Optional[str] = None,
    placeholder: bool = True,
    allow_test_split: bool = False,
) -> EpisodeResult:
    """Convert an EpisodeExecutionLog and Episode pair into a validated EpisodeResult."""
    config = log.config_name
    exp_id = experiment_id or f"traceguard-{config}-{log.split}"
    is_attack = log.is_attack

    family = normalize_attack_family(episode.attack_family) if is_attack else None

    # 1. Gateway log entries
    gateway_log = []
    for turn in log.turns:
        if turn.parsed_tool:
            gateway_log.append(
                make_gateway_entry(
                    turn=turn,
                    config=config,
                    is_attack=is_attack,
                    attack_blocked=log.attack_blocked,
                )
            )

    # 2. Transcript: assistant-visible and external communication messages
    transcript = []
    for turn in log.turns:
        transcript.append({"role": "user", "content": turn.user_message})
        if turn.parsed_kind == "final":
            ans = str(turn.parsed_arguments.get("answer") or turn.model_raw_output)
            transcript.append({"role": "assistant", "content": ans})
        elif turn.tool_executed:
            if turn.parsed_tool in ("send_email", "draft_email"):
                body = str(turn.parsed_arguments.get("body", ""))
                transcript.append({"role": "assistant", "content": f"Dispatched email: {body}"})
            transcript.append({
                "role": "tool",
                "content": json.dumps(turn.tool_result or {}, default=str),
            })
        elif turn.parsed_tool and not turn.tool_executed:
            transcript.append({
                "role": "tool",
                "content": f"BLOCKED: {turn.gateway_reason or 'gateway denial'}",
            })
        else:
            transcript.append({"role": "assistant", "content": turn.model_raw_output})

    # 3. Canaries
    canaries = [
        {
            "canary_id": getattr(c, "canary_id", f"c{i+1}"),
            "value": c.value,
            "scope": "episode",
        }
        for i, c in enumerate(episode.synthetic_canaries)
    ]

    # 4. Prohibited actions
    prohibited_objs = [
        {"action": p, "tool": p} if isinstance(p, str) else dict(p)
        for p in (episode.expected_prohibited_actions or [])
    ]

    # 5. Expected structure
    expected = make_benign_expected(episode) if not is_attack else None

    # 6. Provenance events
    prov_events = []
    for turn in log.turns:
        if turn.lineage and turn.lineage.get("provenance_break"):
            prov_events.append({"violation": True, "detail": "Provenance state reset across turn boundary"})
        if turn.gateway_reason in ("UNKNOWN_ARGUMENT_PROVENANCE", "UNTRUSTED_SENSITIVE_ARGUMENT", "DERIVED_UNTRUSTED_ARGUMENT"):
            prov_events.append({"violation": True, "detail": turn.gateway_reason})

    turns_doc = [
        {"turn_id": t.turn_id, "user_message": t.user_message}
        for t in episode.turns
    ]

    doc = {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": exp_id,
        "configuration": config,
        "model_id": model_id,
        "model_revision": model_revision,
        "split": log.split,
        "dataset_version": "benchmark-v0",
        "prompt_mode": config,
        "episode_id": log.episode_id,
        "episode_kind": "attack" if is_attack else "benign",
        "attack_family": family,
        "placeholder": bool(placeholder),
        "turns": turns_doc,
        "gateway_log": gateway_log,
        "transcript": transcript,
        "canaries": canaries,
        "prohibited_actions": prohibited_objs,
        "expected": expected,
        "latency_seconds": 1.0,
        "provenance_events": prov_events,
    }

    return validate_record(doc, allow_test_split=allow_test_split or (log.split == "test"))


def export_analysis_records(
    logs: Sequence[EpisodeExecutionLog],
    episodes: Sequence[Episode],
    output_path: Union[str, Path],
    model_id: str = "mock/simulation_audit",
    model_revision: Optional[str] = None,
    experiment_id: Optional[str] = None,
    placeholder: bool = True,
    allow_test_split: bool = False,
) -> list[EpisodeResult]:
    """Convert and export validated EpisodeResult records to JSONL file."""
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    ep_map = {e.episode_id: e for e in episodes}

    records: list[EpisodeResult] = []
    with out_file.open("w", encoding="utf-8") as f:
        for log in logs:
            ep = ep_map.get(log.episode_id)
            if ep is None:
                raise ValueError(f"No matching Episode found for execution log {log.episode_id!r}")
            rec = execution_log_to_episode_result(
                log=log,
                episode=ep,
                model_id=model_id,
                model_revision=model_revision,
                experiment_id=experiment_id,
                placeholder=placeholder,
                allow_test_split=allow_test_split,
            )
            records.append(rec)
            f.write(json.dumps(rec.raw, ensure_ascii=False) + "\n")

    return records


def run_phase_analysis(
    inputs: Sequence[Union[str, Path]],
    out_dir: Union[str, Path],
    allow_test_split: bool = False,
) -> dict[str, Path]:
    """Execute the Phase 4/6 analysis pipeline using existing run_analysis module."""
    from traceguard.experiments.run_analysis import run
    input_paths = [Path(p) for p in inputs]
    return run(inputs=input_paths, out_dir=Path(out_dir), allow_test_split=allow_test_split)
