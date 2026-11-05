"""Authorization ledger and policy checking for TraceGuard runtime defense.

Module 6 — Runtime Defense & Multi-Turn Episode Runner.
Member 2: Data & Interpretability Lead.

Maintains the explicit ledger of user-authorized and system-authorized actions
and resources. Prevents prompt injections or model self-authorizations from
granting privileges.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Union

from traceguard.data.schema import Episode, ProvenanceLabel, validate_provenance_label
from traceguard.runtime.userinput import split_user_text

# Non-sensitive tools that have general system authorization by default
DEFAULT_NON_SENSITIVE_TOOLS: frozenset[str] = frozenset(
    {
        "search_emails",
        "read_email",
        "search_documents",
        "read_document",
        "retrieve_notes",
        "save_note",
    }
)

# Sensitive tools requiring explicit user or system authorization
SENSITIVE_TOOLS: frozenset[str] = frozenset(
    {"draft_email", "send_email", "read_private_file"}
)


@dataclass(frozen=True)
class AuthorizationEntry:
    """An explicit permission entry in the authorization ledger."""

    action: str
    resource: Optional[str] = None
    source: str = "user"
    turn_id: int = 0
    provenance: ProvenanceLabel = ProvenanceLabel.USER_AUTHORIZED
    max_uses: Optional[int] = None  # None = unlimited; 1 = single use ("email me")

    def __post_init__(self) -> None:
        if not self.action or not isinstance(self.action, str):
            raise ValueError("AuthorizationEntry action must be a non-empty string")
        validate_provenance_label(self.provenance)
        if self.max_uses is not None and self.max_uses < 1:
            raise ValueError("AuthorizationEntry max_uses must be >= 1 or None")

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "action": self.action,
            "resource": self.resource,
            "source": self.source,
            "turn_id": self.turn_id,
            "provenance": self.provenance.value,
        }
        if self.max_uses is not None:
            d["max_uses"] = self.max_uses
        return d


class AuthorizationLedger:
    """Ledger of authorized tool actions and resources.

    Security Invariant:
    Only inputs with provenance USER_AUTHORIZED, SYSTEM_CONFIG, or SYSTEM_POLICY
    can grant authorization. Model text, prompt injections, or untrusted external
    documents can NEVER authorize sensitive actions.
    """

    def __init__(self) -> None:
        self._entries: list[AuthorizationEntry] = []
        self._uses: list[int] = []  # executions consumed per entry (parallel list)
        self.verified_user_emails: set[str] = set()

    def is_verified_user_email(self, email: Optional[str]) -> bool:
        """Return True if the email belongs to the authenticated user."""
        if not email:
            return False
        return email.strip().lower() in self.verified_user_emails

    @property
    def entries(self) -> list[AuthorizationEntry]:
        """Return a copy of the recorded authorization entries."""
        return list(self._entries)

    def record_authorization(
        self,
        action: str,
        resource: Optional[str] = None,
        source: str = "user",
        turn_id: int = 0,
        provenance: Union[ProvenanceLabel, str] = ProvenanceLabel.USER_AUTHORIZED,
        max_uses: Optional[int] = None,
    ) -> bool:
        """Record an authorized action and optional resource in the ledger.

        Returns True if authorization was granted, False if rejected due to
        insufficient provenance trust.
        """
        prov = validate_provenance_label(provenance)

        # REJECT any authorization attempt from untrusted, derived, or unknown sources
        if prov in {
            ProvenanceLabel.UNTRUSTED_EXTERNAL,
            ProvenanceLabel.DERIVED_UNTRUSTED,
            ProvenanceLabel.UNKNOWN,
        }:
            # Untrusted sources cannot authorize actions
            return False

        res_norm = resource.strip().lower() if resource else None
        entry = AuthorizationEntry(
            action=action.strip(),
            resource=res_norm,
            source=source,
            turn_id=turn_id,
            provenance=prov,
            max_uses=max_uses,
        )
        self._entries.append(entry)
        self._uses.append(0)
        return True

    def _has_capacity(self, index: int) -> bool:
        limit = self._entries[index].max_uses
        return limit is None or self._uses[index] < limit

    def consume(self, action: str, resource: Optional[str] = None) -> bool:
        """Record one executed use of an authorization (call after execution).

        Consumes capacity from the first limited entry that authorizes the call.
        Returns True if a limited entry was consumed.
        """
        action_clean = action.strip()
        res_norm = resource.strip().lower() if resource else None
        for i, e in enumerate(self._entries):
            if e.max_uses is None or not self._has_capacity(i):
                continue
            if e.action != action_clean and e.action != "*":
                continue
            if e.resource == "*" or e.resource == res_norm:
                self._uses[i] += 1
                return True
        return False

    def is_authorized(self, action: str, resource: Optional[str] = None) -> bool:
        """Check if an action (and optional target resource) is authorized."""
        action_clean = action.strip()
        res_norm = resource.strip().lower() if resource else None

        matching_entries = [
            e
            for i, e in enumerate(self._entries)
            if (e.action == action_clean or e.action == "*") and self._has_capacity(i)
        ]
        if not matching_entries:
            return False

        # If caller provided no resource, check if action is permitted at all
        if res_norm is None:
            return True

        # Check if any matching entry explicitly authorizes this resource
        for entry in matching_entries:
            if entry.resource == "*":
                return True
            if entry.resource is not None:
                if entry.resource == res_norm:
                    return True
                # Prefix/scope matching (e.g. "invoices:2026" matches "invoices:2026/doc1")
                if res_norm.startswith(f"{entry.resource}:") or res_norm.startswith(
                    f"{entry.resource}/"
                ):
                    return True
            elif entry.resource is None:
                # Tools that do not have scope restrictions allow any resource if resource is None
                if action_clean not in {
                    "search_documents",
                    "read_document",
                    "read_private_file",
                    "send_email",
                    "draft_email",
                }:
                    return True

        return False

    def initialize_from_episode(
        self,
        episode: Episode,
        current_turn_id: int = 0,
        user_message: str = "",
    ) -> None:
        """Initialize authorization ledger from episode configuration and scopes."""
        # 1. Authorize standard unscoped non-sensitive tools
        for tool in ("search_emails", "read_email", "retrieve_notes", "save_note"):
            self.record_authorization(
                action=tool,
                resource=None,
                source="system_policy",
                turn_id=0,
                provenance=ProvenanceLabel.SYSTEM_POLICY,
            )

        # 2. Authorize document scopes and scoped recipients from episode.authorized_scope
        has_doc_scopes = False
        for scope in episode.authorized_scope:
            if scope.startswith("email_recipient:"):
                recip = scope[len("email_recipient:") :].strip()
                self.record_authorization(
                    action="send_email",
                    resource=recip,
                    source="system_config",
                    turn_id=0,
                    provenance=ProvenanceLabel.SYSTEM_CONFIG,
                )
                self.record_authorization(
                    action="draft_email",
                    resource=recip,
                    source="system_config",
                    turn_id=0,
                    provenance=ProvenanceLabel.SYSTEM_CONFIG,
                )
            elif scope.startswith("private_files:") or scope.startswith("private_file:"):
                prefix = "private_files:" if scope.startswith("private_files:") else "private_file:"
                p = scope[len(prefix) :].strip()
                self.record_authorization(
                    action="read_private_file",
                    resource=p,
                    source="system_config",
                    turn_id=0,
                    provenance=ProvenanceLabel.SYSTEM_CONFIG,
                )
            else:
                has_doc_scopes = True
                self.record_authorization(
                    action="search_documents",
                    resource=scope,
                    source="system_config",
                    turn_id=0,
                    provenance=ProvenanceLabel.SYSTEM_CONFIG,
                )
                self.record_authorization(
                    action="read_document",
                    resource=scope,
                    source="system_config",
                    turn_id=0,
                    provenance=ProvenanceLabel.SYSTEM_CONFIG,
                )

        # If no document scopes were specified, allow document tools generally
        if not has_doc_scopes:
            self.record_authorization(
                action="search_documents",
                resource="*",
                source="system_policy",
                turn_id=0,
                provenance=ProvenanceLabel.SYSTEM_POLICY,
            )
            self.record_authorization(
                action="read_document",
                resource="*",
                source="system_policy",
                turn_id=0,
                provenance=ProvenanceLabel.SYSTEM_POLICY,
            )

        # 3. Authorize verified email recipients from metadata
        meta = episode.metadata or {}
        verified_email = meta.get("verified_user_email")
        if verified_email:
            self.verified_user_emails.add(str(verified_email).strip().lower())
            # "Email me a summary" authorizes ONE send to the verified address.
            self.record_authorization(
                action="send_email",
                resource=str(verified_email),
                source="system_config",
                turn_id=0,
                provenance=ProvenanceLabel.SYSTEM_CONFIG,
                max_uses=1,
            )
            self.record_authorization(
                action="draft_email",
                resource=str(verified_email),
                source="system_config",
                turn_id=0,
                provenance=ProvenanceLabel.SYSTEM_CONFIG,
            )

        verified_recipients = meta.get("verified_recipient") or meta.get(
            "verified_recipients"
        )
        if verified_recipients:
            recips = (
                [verified_recipients]
                if isinstance(verified_recipients, str)
                else list(verified_recipients)
            )
            for recip in recips:
                self.record_authorization(
                    action="send_email",
                    resource=str(recip),
                    source="system_config",
                    turn_id=0,
                    provenance=ProvenanceLabel.SYSTEM_CONFIG,
                )
                self.record_authorization(
                    action="draft_email",
                    resource=str(recip),
                    source="system_config",
                    turn_id=0,
                    provenance=ProvenanceLabel.SYSTEM_CONFIG,
                )

        # 4. Check initial user task and turn message for explicit user authorization
        self.grant_user_directives(episode.initial_user_task, turn_id=0)
        if user_message:
            self.grant_user_directives(user_message, turn_id=current_turn_id)

    def grant_user_directives(self, text: str, turn_id: int = 0) -> None:
        """Extract explicit user authorizations from a verified user message."""
        if not text:
            return

        # Quoted / pasted material is data, never an instruction (brief rule 12).
        text, _pasted = split_user_text(text)
        text_lower = text.lower()

        # Check for explicit email sending / drafting instructions
        email_matches = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text)
        if any(w in text_lower for w in ("send email", "send an email", "email to", "send to")):
            for email in email_matches:
                self.record_authorization(
                    action="send_email",
                    resource=email,
                    source="user_instruction",
                    turn_id=turn_id,
                    provenance=ProvenanceLabel.USER_AUTHORIZED,
                )

        if any(w in text_lower for w in ("draft email", "draft an email", "prepare draft", "create draft")):
            for email in email_matches:
                self.record_authorization(
                    action="draft_email",
                    resource=email,
                    source="user_instruction",
                    turn_id=turn_id,
                    provenance=ProvenanceLabel.USER_AUTHORIZED,
                )

        # Check for explicit private file read authorization
        if "read private file" in text_lower or "access private file" in text_lower:
            file_matches = re.findall(r"[\w/_\.-]+\.(?:txt|pdf|csv|json|key|dat)", text)
            for path in file_matches:
                self.record_authorization(
                    action="read_private_file",
                    resource=path,
                    source="user_instruction",
                    turn_id=turn_id,
                    provenance=ProvenanceLabel.USER_AUTHORIZED,
                )
