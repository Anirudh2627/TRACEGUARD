"""Structured execution logging for TraceGuard runtime multi-turn episodes.

Module 6 — Runtime Defense & Multi-Turn Episode Runner.
Member 2: Data & Interpretability Lead.

Provides immutable, lossless, JSON-serializable records for each conversational
turn and complete multi-turn episode executions. Tracks raw model output, parsed
action, argument provenance, gateway decisions, canary exposures, and policy
violations.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Optional, Sequence


@dataclass
class TurnExecutionRecord:
    """Execution record for a single conversational turn."""

    turn_id: int
    user_message: str
    model_raw_output: str
    parsed_kind: Optional[str] = None
    parsed_tool: Optional[str] = None
    parsed_arguments: dict[str, Any] = field(default_factory=dict)
    parse_reason_code: Optional[str] = None
    argument_provenance: dict[str, str] = field(default_factory=dict)
    gateway_decision: str = "NONE"  # "ALLOW", "DENY", "PASSTHROUGH", "NONE"
    gateway_reason: Optional[str] = None
    gateway_detail: Optional[str] = None
    tool_executed: bool = False
    tool_result: Optional[dict[str, Any]] = None
    canary_exposed: bool = False
    canary_details: list[str] = field(default_factory=list)
    prohibited_action_attempted: bool = False
    prohibited_action_executed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "turn_id": self.turn_id,
            "user_message": self.user_message,
            "model_raw_output": self.model_raw_output,
            "parsed_kind": self.parsed_kind,
            "parsed_tool": self.parsed_tool,
            "parsed_arguments": dict(self.parsed_arguments),
            "parse_reason_code": self.parse_reason_code,
            "argument_provenance": dict(self.argument_provenance),
            "gateway_decision": self.gateway_decision,
            "gateway_reason": self.gateway_reason,
            "gateway_detail": self.gateway_detail,
            "tool_executed": self.tool_executed,
            "tool_result": self.tool_result,
            "canary_exposed": self.canary_exposed,
            "canary_details": list(self.canary_details),
            "prohibited_action_attempted": self.prohibited_action_attempted,
            "prohibited_action_executed": self.prohibited_action_executed,
        }


@dataclass
class EpisodeExecutionLog:
    """Comprehensive execution log for a complete multi-turn episode."""

    episode_id: str
    template_id: str
    split: str
    is_attack: bool
    config_name: str
    turns: list[TurnExecutionRecord] = field(default_factory=list)
    overall_passed: bool = False
    attack_blocked: Optional[bool] = None
    canary_leaked: bool = False
    prohibited_action_taken: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "template_id": self.template_id,
            "split": self.split,
            "is_attack": self.is_attack,
            "config_name": self.config_name,
            "overall_passed": self.overall_passed,
            "attack_blocked": self.attack_blocked,
            "canary_leaked": self.canary_leaked,
            "prohibited_action_taken": self.prohibited_action_taken,
            "metadata": dict(self.metadata),
            "turns": [t.to_dict() for t in self.turns],
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize log to a deterministic JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
