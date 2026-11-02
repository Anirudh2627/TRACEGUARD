"""Shared dataset schemas for TraceGuard multi-turn audit episodes.

Module 1 — Shared Schema & Project Setup (Member 2: Data & Interpretability Lead).

This module defines the canonical typed structures for:
- Episodes (TraceGuard test cases, both attack and benign)
- Turns (multi-turn conversational interactions)
- SourceRecords (untrusted content, policy, or configuration with provenance labels)
- ProvenanceLabels (the 6 fixed trust/provenance labels)
- CanarySpecs (synthetic canary tracking)
- ExpectedOutcomes (safe behavior criteria, prohibited actions, expected outputs)

The model must NOT be able to create, modify, or upgrade provenance labels;
provenance is strictly metadata supplied by the runtime/dataset.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence, Union


class ProvenanceLabel(str, Enum):
    """The six fixed provenance labels defined in the TraceGuard project brief.

    Model outputs must NEVER be able to forge or elevate these labels.
    """

    SYSTEM_POLICY = "SYSTEM_POLICY"
    SYSTEM_CONFIG = "SYSTEM_CONFIG"
    USER_AUTHORIZED = "USER_AUTHORIZED"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    DERIVED_UNTRUSTED = "DERIVED_UNTRUSTED"
    UNKNOWN = "UNKNOWN"


PROVENANCE_LABELS: frozenset[str] = frozenset(p.value for p in ProvenanceLabel)

ALLOWED_SPLITS: frozenset[str] = frozenset({"dev", "test", "smoke"})


def validate_provenance_label(label: str | ProvenanceLabel) -> ProvenanceLabel:
    """Validate and normalize a provenance label string or enum."""
    val = label.value if isinstance(label, ProvenanceLabel) else str(label)
    if val not in PROVENANCE_LABELS:
        raise ValueError(
            f"Invalid provenance label {val!r}; expected one of {sorted(PROVENANCE_LABELS)}"
        )
    return ProvenanceLabel(val)


@dataclass(frozen=True)
class CanarySpec:
    """Synthetic canary used to detect unauthorized exfiltration or instruction leakage."""

    value: str
    canary_id: Optional[str] = None
    canary_type: str = "generic"
    description: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.value or not isinstance(self.value, str):
            raise ValueError("CanarySpec value must be a non-empty string")
        if self.canary_id is None:
            object.__setattr__(self, "canary_id", self.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "canary_id": self.canary_id,
            "canary_type": self.canary_type,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Union[str, Mapping[str, Any]]) -> CanarySpec:
        if isinstance(data, str):
            return cls(value=data, canary_id=data)
        if not isinstance(data, Mapping):
            raise ValueError(f"Expected CanarySpec dict or string, got {type(data).__name__}")
        return cls(
            value=str(data.get("value") or data.get("canary_id") or ""),
            canary_id=data.get("canary_id"),
            canary_type=str(data.get("canary_type", "generic")),
            description=data.get("description"),
        )


@dataclass(frozen=True)
class SourceRecord:
    """A data item (email, doc, note, tool result) with associated provenance metadata."""

    source_id: str
    source_type: str
    provenance: ProvenanceLabel
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    parent_source_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.source_id or not isinstance(self.source_id, str):
            raise ValueError("SourceRecord source_id must be a non-empty string")
        if not self.source_type or not isinstance(self.source_type, str):
            raise ValueError("SourceRecord source_type must be a non-empty string")
        norm_prov = validate_provenance_label(self.provenance)
        object.__setattr__(self, "provenance", norm_prov)
        if not isinstance(self.parent_source_ids, list):
            object.__setattr__(self, "parent_source_ids", list(self.parent_source_ids))
        if not isinstance(self.metadata, dict):
            object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "provenance": self.provenance.value,
            "content": self.content,
        }
        if self.metadata:
            d["metadata"] = dict(self.metadata)
        if self.parent_source_ids:
            d["parent_source_ids"] = list(self.parent_source_ids)
        return d

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SourceRecord:
        if not isinstance(data, Mapping):
            raise ValueError(f"Expected SourceRecord mapping, got {type(data).__name__}")
        for req in ("source_id", "source_type", "provenance"):
            if req not in data:
                raise ValueError(f"SourceRecord missing required field {req!r}")
        return cls(
            source_id=str(data["source_id"]),
            source_type=str(data["source_type"]),
            provenance=validate_provenance_label(data["provenance"]),
            content=str(data.get("content", "")),
            metadata=dict(data.get("metadata") or {}),
            parent_source_ids=list(data.get("parent_source_ids") or []),
        )


@dataclass(frozen=True)
class ExpectedOutcome:
    """Expected safe behavior specification for an episode or turn."""

    safe_behavior: str = ""
    final_fields: dict[str, Any] = field(default_factory=dict)
    prohibited_actions: list[str] = field(default_factory=list)
    trust_labels: dict[str, str] = field(default_factory=dict)
    authorized_scope: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.final_fields, dict):
            object.__setattr__(self, "final_fields", dict(self.final_fields))
        if not isinstance(self.prohibited_actions, list):
            object.__setattr__(self, "prohibited_actions", list(self.prohibited_actions))
        if not isinstance(self.trust_labels, dict):
            object.__setattr__(self, "trust_labels", dict(self.trust_labels))
        if not isinstance(self.authorized_scope, list):
            object.__setattr__(self, "authorized_scope", list(self.authorized_scope))
        for target, label in self.trust_labels.items():
            validate_provenance_label(label)

    def to_dict(self) -> dict[str, Any]:
        return {
            "safe_behavior": self.safe_behavior,
            "final_fields": dict(self.final_fields),
            "prohibited_actions": list(self.prohibited_actions),
            "trust_labels": dict(self.trust_labels),
            "authorized_scope": list(self.authorized_scope),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExpectedOutcome:
        if not isinstance(data, Mapping):
            raise ValueError(f"Expected ExpectedOutcome mapping, got {type(data).__name__}")
        return cls(
            safe_behavior=str(
                data.get("safe_behavior") or data.get("expected_safe_behavior") or ""
            ),
            final_fields=dict(
                data.get("final_fields") or data.get("expected_final_fields") or {}
            ),
            prohibited_actions=list(
                data.get("prohibited_actions") or data.get("expected_prohibited_actions") or []
            ),
            trust_labels=dict(
                data.get("trust_labels") or data.get("expected_trust_labels") or {}
            ),
            authorized_scope=list(data.get("authorized_scope") or []),
        )


@dataclass(frozen=True)
class Turn:
    """Represents a single conversational turn within an episode."""

    turn_id: int
    user_message: str
    source_records: list[SourceRecord] = field(default_factory=list)
    expected_action: Optional[dict[str, Any]] = None
    expected_prohibited_actions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.turn_id, int):
            try:
                object.__setattr__(self, "turn_id", int(self.turn_id))
            except (ValueError, TypeError):
                raise ValueError("Turn turn_id must be an integer")
        if not isinstance(self.user_message, str):
            raise ValueError("Turn user_message must be a string")
        if not isinstance(self.source_records, list):
            object.__setattr__(self, "source_records", list(self.source_records))
        if not isinstance(self.expected_prohibited_actions, list):
            object.__setattr__(
                self, "expected_prohibited_actions", list(self.expected_prohibited_actions)
            )
        if not isinstance(self.metadata, dict):
            object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "turn_id": self.turn_id,
            "user_message": self.user_message,
        }
        if self.source_records:
            d["source_records"] = [s.to_dict() for s in self.source_records]
        if self.expected_action is not None:
            d["expected_action"] = dict(self.expected_action)
        if self.expected_prohibited_actions:
            d["expected_prohibited_actions"] = list(self.expected_prohibited_actions)
        if self.metadata:
            d["metadata"] = dict(self.metadata)
        return d

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Turn:
        if not isinstance(data, Mapping):
            raise ValueError(f"Expected Turn mapping, got {type(data).__name__}")
        if "turn_id" not in data or "user_message" not in data:
            raise ValueError("Turn requires 'turn_id' and 'user_message'")
        sources = [
            SourceRecord.from_dict(s) if isinstance(s, Mapping) else s
            for s in (data.get("source_records") or [])
        ]
        return cls(
            turn_id=int(data["turn_id"]),
            user_message=str(data["user_message"]),
            source_records=sources,
            expected_action=dict(data["expected_action"])
            if data.get("expected_action") is not None
            else None,
            expected_prohibited_actions=list(data.get("expected_prohibited_actions") or []),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(frozen=True)
class Episode:
    """Represents a complete TraceGuard multi-turn test case (attack or benign)."""

    episode_id: str
    template_id: str
    split: str
    initial_user_task: str
    attack_family: Optional[str] = None
    is_attack: bool = True
    turns: list[Turn] = field(default_factory=list)
    source_records: list[SourceRecord] = field(default_factory=list)
    authorized_scope: list[str] = field(default_factory=list)
    synthetic_canaries: list[CanarySpec] = field(default_factory=list)
    expected_trust_labels: dict[str, str] = field(default_factory=dict)
    expected_safe_behavior: str = ""
    expected_final_fields: dict[str, Any] = field(default_factory=dict)
    expected_prohibited_actions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.episode_id or not isinstance(self.episode_id, str) or not self.episode_id.strip():
            raise ValueError("Episode episode_id must be a non-empty string")
        if not self.template_id or not isinstance(self.template_id, str) or not self.template_id.strip():
            raise ValueError("Episode template_id must be a non-empty string")
        if self.split not in ALLOWED_SPLITS:
            raise ValueError(
                f"Invalid split {self.split!r}; expected one of {sorted(ALLOWED_SPLITS)}"
            )
        if not isinstance(self.initial_user_task, str):
            raise ValueError("Episode initial_user_task must be a string")

        # Normalize collections to lists/dicts
        if not isinstance(self.turns, list):
            object.__setattr__(self, "turns", list(self.turns))
        if not isinstance(self.source_records, list):
            object.__setattr__(self, "source_records", list(self.source_records))
        if not isinstance(self.authorized_scope, list):
            object.__setattr__(self, "authorized_scope", list(self.authorized_scope))
        if not isinstance(self.synthetic_canaries, list):
            object.__setattr__(self, "synthetic_canaries", list(self.synthetic_canaries))
        if not isinstance(self.expected_trust_labels, dict):
            object.__setattr__(self, "expected_trust_labels", dict(self.expected_trust_labels))
        if not isinstance(self.expected_final_fields, dict):
            object.__setattr__(self, "expected_final_fields", dict(self.expected_final_fields))
        if not isinstance(self.expected_prohibited_actions, list):
            object.__setattr__(
                self, "expected_prohibited_actions", list(self.expected_prohibited_actions)
            )
        if not isinstance(self.metadata, dict):
            object.__setattr__(self, "metadata", dict(self.metadata))

        # Validate trust labels
        for target, label in self.expected_trust_labels.items():
            validate_provenance_label(label)

        # Normalize canaries to CanarySpec
        canaries: list[CanarySpec] = []
        for c in self.synthetic_canaries:
            if isinstance(c, CanarySpec):
                canaries.append(c)
            elif isinstance(c, str):
                canaries.append(CanarySpec(value=c))
            elif isinstance(c, Mapping):
                canaries.append(CanarySpec.from_dict(c))
            else:
                raise ValueError(f"Invalid canary format: {c!r}")
        object.__setattr__(self, "synthetic_canaries", canaries)

    @property
    def expected_outcome(self) -> ExpectedOutcome:
        """Helper view of the episode's expected safe behavior specification."""
        return ExpectedOutcome(
            safe_behavior=self.expected_safe_behavior,
            final_fields=dict(self.expected_final_fields),
            prohibited_actions=list(self.expected_prohibited_actions),
            trust_labels=dict(self.expected_trust_labels),
            authorized_scope=list(self.authorized_scope),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert Episode to a JSON-serializable dictionary."""
        d: dict[str, Any] = {
            "episode_id": self.episode_id,
            "template_id": self.template_id,
            "split": self.split,
            "initial_user_task": self.initial_user_task,
            "is_attack": self.is_attack,
        }
        if self.attack_family is not None:
            d["attack_family"] = self.attack_family
        d["turns"] = [t.to_dict() for t in self.turns]
        if self.source_records:
            d["source_records"] = [s.to_dict() for s in self.source_records]
        if self.authorized_scope:
            d["authorized_scope"] = list(self.authorized_scope)
        if self.synthetic_canaries:
            d["synthetic_canaries"] = [
                c.value
                if (
                    c.canary_id == c.value
                    and c.canary_type == "generic"
                    and not c.description
                )
                else c.to_dict()
                for c in self.synthetic_canaries
            ]
        if self.expected_trust_labels:
            d["expected_trust_labels"] = dict(self.expected_trust_labels)
        if self.expected_safe_behavior:
            d["expected_safe_behavior"] = self.expected_safe_behavior
        if self.expected_final_fields:
            d["expected_final_fields"] = dict(self.expected_final_fields)
        if self.expected_prohibited_actions:
            d["expected_prohibited_actions"] = list(self.expected_prohibited_actions)
        if self.metadata:
            d["metadata"] = dict(self.metadata)
        return d

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize episode to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Episode:
        """Deserialize an Episode from a dictionary."""
        if not isinstance(data, Mapping):
            raise ValueError(f"Expected Episode mapping, got {type(data).__name__}")

        for req in ("episode_id", "template_id", "split"):
            if req not in data:
                raise ValueError(f"Episode missing required field {req!r}")

        outcome_data = data.get("expected_outcome") or {}
        safe_behavior = str(
            data.get("expected_safe_behavior")
            or outcome_data.get("safe_behavior")
            or outcome_data.get("expected_safe_behavior")
            or ""
        )
        final_fields = dict(
            data.get("expected_final_fields")
            or outcome_data.get("final_fields")
            or outcome_data.get("expected_final_fields")
            or {}
        )
        prohibited_actions = list(
            data.get("expected_prohibited_actions")
            or outcome_data.get("prohibited_actions")
            or outcome_data.get("expected_prohibited_actions")
            or []
        )
        trust_labels = dict(
            data.get("expected_trust_labels")
            or outcome_data.get("trust_labels")
            or outcome_data.get("expected_trust_labels")
            or {}
        )
        auth_scope = list(
            data.get("authorized_scope")
            or outcome_data.get("authorized_scope")
            or []
        )

        turns = [
            Turn.from_dict(t) if isinstance(t, Mapping) else t
            for t in (data.get("turns") or [])
        ]
        source_records = [
            SourceRecord.from_dict(s) if isinstance(s, Mapping) else s
            for s in (data.get("source_records") or [])
        ]
        raw_canaries = data.get("synthetic_canaries") or []
        canaries = [
            CanarySpec.from_dict(c) if isinstance(c, (Mapping, str)) else c
            for c in raw_canaries
        ]

        attack_family = data.get("attack_family")
        is_attack = bool(
            data.get("is_attack", attack_family is not None and attack_family != "benign")
        )

        return cls(
            episode_id=str(data["episode_id"]),
            template_id=str(data["template_id"]),
            split=str(data["split"]),
            initial_user_task=str(data.get("initial_user_task", "")),
            attack_family=str(attack_family) if attack_family is not None else None,
            is_attack=is_attack,
            turns=turns,
            source_records=source_records,
            authorized_scope=auth_scope,
            synthetic_canaries=canaries,
            expected_trust_labels=trust_labels,
            expected_safe_behavior=safe_behavior,
            expected_final_fields=final_fields,
            expected_prohibited_actions=prohibited_actions,
            metadata=dict(data.get("metadata") or {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> Episode:
        """Deserialize an Episode from a JSON string."""
        return cls.from_dict(json.loads(json_str))
