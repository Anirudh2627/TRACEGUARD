"""Provenance tracking and propagation for TraceGuard runtime defense.

Module 6 — Runtime Defense & Multi-Turn Episode Runner.
Member 2: Data & Interpretability Lead.

Tracks data origins, taint propagation, and trust labels across conversational
turns and tool calls. Supports both:
- turn-local provenance (E2a): provenance resets / is isolated per turn.
- persistent provenance (E2b): provenance accumulates and persists across turns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Union

from traceguard.data.schema import (
    PROVENANCE_LABELS,
    ProvenanceLabel,
    SourceRecord,
    validate_provenance_label,
)


def combine_provenance(
    labels: Sequence[Union[ProvenanceLabel, str]],
) -> ProvenanceLabel:
    """Conservatively combine multiple provenance labels.

    Lattice / Priority rules (trust is never elevated):
    1. If any input is UNTRUSTED_EXTERNAL or DERIVED_UNTRUSTED:
       - If all inputs are UNTRUSTED_EXTERNAL: returns UNTRUSTED_EXTERNAL.
       - Otherwise: returns DERIVED_UNTRUSTED (tainted composition).
    2. Else if any input is UNKNOWN:
       - Returns UNKNOWN.
    3. Else if all inputs are trusted:
       - If any input is USER_AUTHORIZED: returns USER_AUTHORIZED.
       - Else if all are SYSTEM_CONFIG: returns SYSTEM_CONFIG.
       - Else if all are SYSTEM_POLICY: returns SYSTEM_POLICY.
       - Otherwise: returns USER_AUTHORIZED.
    4. If labels is empty: returns UNKNOWN.
    """
    if not labels:
        return ProvenanceLabel.UNKNOWN

    normalized = [validate_provenance_label(l) for l in labels]

    untrusted_count = 0
    derived_count = 0
    unknown_count = 0

    for l in normalized:
        if l == ProvenanceLabel.DERIVED_UNTRUSTED:
            derived_count += 1
        elif l == ProvenanceLabel.UNTRUSTED_EXTERNAL:
            untrusted_count += 1
        elif l == ProvenanceLabel.UNKNOWN:
            unknown_count += 1

    # Any untrusted input taints the whole combination
    if derived_count > 0 or (untrusted_count > 0 and len(normalized) > untrusted_count):
        return ProvenanceLabel.DERIVED_UNTRUSTED
    if untrusted_count > 0:
        return ProvenanceLabel.UNTRUSTED_EXTERNAL

    # Unknown input prevents trust elevation
    if unknown_count > 0:
        return ProvenanceLabel.UNKNOWN

    # Only trusted labels remain
    if any(l == ProvenanceLabel.USER_AUTHORIZED for l in normalized):
        return ProvenanceLabel.USER_AUTHORIZED
    if all(l == ProvenanceLabel.SYSTEM_CONFIG for l in normalized):
        return ProvenanceLabel.SYSTEM_CONFIG
    if all(l == ProvenanceLabel.SYSTEM_POLICY for l in normalized):
        return ProvenanceLabel.SYSTEM_POLICY

    return ProvenanceLabel.USER_AUTHORIZED


@dataclass
class TrackedEntity:
    """A tracked textual entity or token with an immutable provenance label."""

    value: str
    provenance: ProvenanceLabel
    source_id: Optional[str] = None
    turn_id: int = 0
    is_transient: bool = False  # If True, cleared in turn-local mode


class ProvenanceTracker:
    """Runtime tracker for data provenance across multi-turn interactions.

    Maintains mappings from source records, text fragments, tool outputs,
    and identifiers to their associated ProvenanceLabel.

    Modes:
    - "persistent" (E2b): Tracked entities and taints persist across all turns.
    - "turn_local" (E2a): Transient entities and prior-turn outputs are cleared
      at each new turn, simulating lack of cross-turn memory.
    """

    def __init__(self, mode: str = "persistent") -> None:
        if mode not in {"persistent", "turn_local"}:
            raise ValueError(
                f"Invalid provenance mode {mode!r}; expected 'persistent' or 'turn_local'"
            )
        self.mode: str = mode
        self.current_turn_id: int = 0

        # Permanent records (e.g. system config, policy, verified sources)
        self._sources: dict[str, SourceRecord] = {}
        # Tracked entities/tokens
        self._tracked_entities: list[TrackedEntity] = []
        # Tool outputs: (turn_id, tool_name) -> ProvenanceLabel
        self._tool_outputs: list[dict[str, Any]] = []

    def set_turn(self, turn_id: int) -> None:
        """Advance to a specific turn ID."""
        self.current_turn_id = turn_id
        if self.mode == "turn_local":
            # In turn-local mode, clear transient entities from prior turns
            self._tracked_entities = [
                e
                for e in self._tracked_entities
                if not e.is_transient or e.turn_id == turn_id
            ]

    def new_turn(self) -> None:
        """Advance turn counter and apply turn-local reset if applicable."""
        self.set_turn(self.current_turn_id + 1)

    def register_source_record(
        self, record: SourceRecord, turn_id: Optional[int] = None
    ) -> None:
        """Register a source record and index its textual tokens and provenance."""
        t_id = self.current_turn_id if turn_id is None else turn_id
        self._sources[record.source_id] = record

        # Register the source_id itself
        is_transient = (self.mode == "turn_local") and (
            record.provenance
            in {
                ProvenanceLabel.UNTRUSTED_EXTERNAL,
                ProvenanceLabel.DERIVED_UNTRUSTED,
                ProvenanceLabel.UNKNOWN,
            }
        )
        self._tracked_entities.append(
            TrackedEntity(
                value=record.source_id,
                provenance=record.provenance,
                source_id=record.source_id,
                turn_id=t_id,
                is_transient=is_transient,
            )
        )

        # Extract tokens/entities from content if present
        if record.content:
            self._index_content(record.content, record.provenance, record.source_id, t_id, is_transient)

    def _index_content(
        self,
        content: str,
        provenance: ProvenanceLabel,
        source_id: str,
        turn_id: int,
        is_transient: bool,
    ) -> None:
        """Extract and index significant keywords, email addresses, and URLs."""
        # Email addresses
        emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", content)
        for email in emails:
            self._tracked_entities.append(
                TrackedEntity(
                    value=email.lower(),
                    provenance=provenance,
                    source_id=source_id,
                    turn_id=turn_id,
                    is_transient=is_transient,
                )
            )

        # URL-like / domain strings
        urls = re.findall(r"https?://[^\s'\"<>]+|[\w\.-]+\.(?:com|org|net|io|example)", content)
        for url in urls:
            self._tracked_entities.append(
                TrackedEntity(
                    value=url.lower(),
                    provenance=provenance,
                    source_id=source_id,
                    turn_id=turn_id,
                    is_transient=is_transient,
                )
            )

        # Whole content snippet tracking
        self._tracked_entities.append(
            TrackedEntity(
                value=content,
                provenance=provenance,
                source_id=source_id,
                turn_id=turn_id,
                is_transient=is_transient,
            )
        )

    def register_user_text(self, text: str, turn_id: Optional[int] = None) -> None:
        """Register text provided directly by the user as USER_AUTHORIZED."""
        t_id = self.current_turn_id if turn_id is None else turn_id
        self._tracked_entities.append(
            TrackedEntity(
                value=text,
                provenance=ProvenanceLabel.USER_AUTHORIZED,
                source_id="user_prompt",
                turn_id=t_id,
                is_transient=False,
            )
        )
        # Also index user emails/tokens
        emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text)
        for email in emails:
            self._tracked_entities.append(
                TrackedEntity(
                    value=email.lower(),
                    provenance=ProvenanceLabel.USER_AUTHORIZED,
                    source_id="user_prompt",
                    turn_id=t_id,
                    is_transient=False,
                )
            )

    def record_tool_output(
        self,
        tool_name: str,
        output_content: Any,
        input_provenances: Sequence[ProvenanceLabel],
        turn_id: Optional[int] = None,
    ) -> ProvenanceLabel:
        """Record the execution and output provenance of a tool call."""
        t_id = self.current_turn_id if turn_id is None else turn_id
        output_prov = combine_provenance(input_provenances)

        is_transient = (self.mode == "turn_local") and (
            output_prov
            in {
                ProvenanceLabel.UNTRUSTED_EXTERNAL,
                ProvenanceLabel.DERIVED_UNTRUSTED,
                ProvenanceLabel.UNKNOWN,
            }
        )

        entry = {
            "turn_id": t_id,
            "tool": tool_name,
            "provenance": output_prov,
            "is_transient": is_transient,
        }
        self._tool_outputs.append(entry)

        if isinstance(output_content, str) and output_content:
            self._index_content(
                output_content,
                output_prov,
                source_id=f"tool_out_{tool_name}_{t_id}",
                turn_id=t_id,
                is_transient=is_transient,
            )
        elif isinstance(output_content, Mapping):
            import json
            content_str = json.dumps(output_content)
            self._index_content(
                content_str,
                output_prov,
                source_id=f"tool_out_{tool_name}_{t_id}",
                turn_id=t_id,
                is_transient=is_transient,
            )

        return output_prov

    def resolve_argument_provenance(
        self,
        value: Any,
        user_message: str = "",
        authorized_scopes: Sequence[str] = (),
        verified_user_email: Optional[str] = None,
        default: ProvenanceLabel = ProvenanceLabel.UNKNOWN,
        arg_name: Optional[str] = None,
    ) -> ProvenanceLabel:
        """Resolve the provenance of an argument value passed to a tool.

        Checks (in priority order):
        1. Verified system configuration or authorized scope match -> SYSTEM_CONFIG.
        2. Exact user message match / explicit user instruction -> USER_AUTHORIZED.
        3. Match against known source record IDs -> SourceRecord.provenance.
        4. Match against tracked entities/tokens (untrusted, derived, etc.).
        5. Authorized composed payload (subject/body) -> USER_AUTHORIZED.
        6. Default fallback -> UNKNOWN.
        """
        if value is None:
            return ProvenanceLabel.UNKNOWN

        val_str = str(value).strip()
        val_lower = val_str.lower()

        # 1. System configuration / verified items
        if verified_user_email and val_lower == verified_user_email.strip().lower():
            return ProvenanceLabel.SYSTEM_CONFIG
        if authorized_scopes:
            for scope in authorized_scopes:
                if val_str == scope or val_str.startswith(f"{scope}:"):
                    return ProvenanceLabel.SYSTEM_CONFIG
                if scope.startswith("email_recipient:") and val_lower == scope[len("email_recipient:") :].strip().lower():
                    return ProvenanceLabel.SYSTEM_CONFIG
                if scope.startswith("private_files:") and val_lower == scope[len("private_files:") :].strip().lower():
                    return ProvenanceLabel.SYSTEM_CONFIG
                if scope.startswith("private_file:") and val_lower == scope[len("private_file:") :].strip().lower():
                    return ProvenanceLabel.SYSTEM_CONFIG

        # 2. Direct user message containment
        if user_message and val_str in user_message:
            return ProvenanceLabel.USER_AUTHORIZED
        if user_message and "@" in val_str and val_lower in user_message.lower():
            return ProvenanceLabel.USER_AUTHORIZED

        # 3. Known source record ID lookup
        # In turn-local mode, only check source records from the current turn or permanent config
        if val_str in self._sources:
            src = self._sources[val_str]
            # Check turn-local constraint
            if self.mode == "turn_local" and src.provenance in {
                ProvenanceLabel.UNTRUSTED_EXTERNAL,
                ProvenanceLabel.DERIVED_UNTRUSTED,
            }:
                # If this source was from a prior turn and not in current entities
                matching = [
                    e
                    for e in self._tracked_entities
                    if e.value == val_str and e.turn_id == self.current_turn_id
                ]
                if not matching:
                    return ProvenanceLabel.UNKNOWN
            return src.provenance

        # 4. Tracked entities lookup
        # Find all entities that match this value or contain this value
        matched_labels: list[ProvenanceLabel] = []
        for entity in reversed(self._tracked_entities):
            # In turn_local mode, ignore entities from previous turns if transient
            if self.mode == "turn_local" and entity.is_transient and entity.turn_id != self.current_turn_id:
                continue

            # Exact match (case insensitive for emails/strings)
            if entity.value.lower() == val_lower:
                matched_labels.append(entity.provenance)
            # Substring containment for rich content
            elif len(entity.value) > len(val_str) and val_str in entity.value:
                matched_labels.append(entity.provenance)
            elif len(val_str) > len(entity.value) and entity.value in val_str and len(entity.value) > 4:
                matched_labels.append(entity.provenance)

        if matched_labels:
            # Combine all matched labels conservatively (least trust)
            combined = combine_provenance(matched_labels)
            if combined in {
                ProvenanceLabel.UNTRUSTED_EXTERNAL,
                ProvenanceLabel.DERIVED_UNTRUSTED,
            }:
                return combined
            if arg_name in {"subject", "body"} and user_message:
                return ProvenanceLabel.USER_AUTHORIZED
            return combined

        # 5. Composed non-target payload for an authorized user instruction
        if arg_name in {"subject", "body"} and user_message:
            return ProvenanceLabel.USER_AUTHORIZED

        return default

    def describe(self) -> dict[str, Any]:
        """Return diagnostic metrics of the tracker's current state."""
        return {
            "mode": self.mode,
            "current_turn_id": self.current_turn_id,
            "registered_sources_count": len(self._sources),
            "tracked_entities_count": len(self._tracked_entities),
            "tool_outputs_count": len(self._tool_outputs),
        }
