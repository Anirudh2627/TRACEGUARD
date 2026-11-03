"""Unit tests for TraceGuard runtime authorization ledger.

Module 6 — Runtime Defense & Multi-Turn Episode Runner.
Member 2: Data & Interpretability Lead.
"""

import pytest

from traceguard.data.schema import Episode, ProvenanceLabel
from traceguard.runtime.authorization import (
    DEFAULT_NON_SENSITIVE_TOOLS,
    SENSITIVE_TOOLS,
    AuthorizationEntry,
    AuthorizationLedger,
)


def test_authorization_entry_structure():
    """Verify entry creation and serialization."""
    entry = AuthorizationEntry(
        action="send_email",
        resource="alice@corp.example.org",
        source="user_instruction",
        turn_id=1,
        provenance=ProvenanceLabel.USER_AUTHORIZED,
    )
    d = entry.to_dict()
    assert d["action"] == "send_email"
    assert d["resource"] == "alice@corp.example.org"
    assert d["provenance"] == "USER_AUTHORIZED"


def test_untrusted_authorization_rejection():
    """Security rule: untrusted or unknown sources cannot grant authorization."""
    ledger = AuthorizationLedger()

    # Attempt authorization from UNTRUSTED_EXTERNAL
    ok = ledger.record_authorization(
        action="send_email",
        resource="attacker@evil.example",
        source="attacker_document",
        turn_id=1,
        provenance=ProvenanceLabel.UNTRUSTED_EXTERNAL,
    )
    assert ok is False
    assert not ledger.is_authorized("send_email", "attacker@evil.example")

    # Attempt authorization from DERIVED_UNTRUSTED
    ok2 = ledger.record_authorization(
        action="read_private_file",
        resource="secrets.key",
        source="tainted_note",
        turn_id=1,
        provenance=ProvenanceLabel.DERIVED_UNTRUSTED,
    )
    assert ok2 is False
    assert not ledger.is_authorized("read_private_file", "secrets.key")

    # Attempt authorization from UNKNOWN
    ok3 = ledger.record_authorization(
        action="draft_email",
        resource="test@example.com",
        source="unknown",
        turn_id=1,
        provenance=ProvenanceLabel.UNKNOWN,
    )
    assert ok3 is False
    assert not ledger.is_authorized("draft_email", "test@example.com")


def test_valid_user_authorization():
    """User directives successfully grant authorization."""
    ledger = AuthorizationLedger()

    ok = ledger.record_authorization(
        action="send_email",
        resource="carlos@corp.example.org",
        source="user_prompt",
        turn_id=1,
        provenance=ProvenanceLabel.USER_AUTHORIZED,
    )
    assert ok is True
    assert ledger.is_authorized("send_email", "carlos@corp.example.org")
    # Case insensitive
    assert ledger.is_authorized("send_email", "CARLOS@corp.example.org")
    # Other recipient not authorized
    assert not ledger.is_authorized("send_email", "eve@attacker.example")


def test_initialize_from_episode_grants_defaults_and_scopes():
    """Episode initialization authorizes non-sensitive tools, scopes, and verified email."""
    ep = Episode(
        episode_id="ep_test_auth",
        template_id="doc_injection_01",
        split="dev",
        initial_user_task="Send summary of invoice to finance team at finance@corp.example.org",
        authorized_scope=["invoices:2026", "logistics:docs"],
        metadata={
            "verified_user_email": "alice@corp.example.org",
            "verified_recipient": "carlos@corp.example.org",
        },
    )

    ledger = AuthorizationLedger()
    ledger.initialize_from_episode(ep, current_turn_id=0)

    # Non-sensitive tools authorized
    for t in DEFAULT_NON_SENSITIVE_TOOLS:
        assert ledger.is_authorized(t)

    # Scopes authorized
    assert ledger.is_authorized("search_documents", "invoices:2026")
    assert ledger.is_authorized("search_documents", "logistics:docs")
    assert not ledger.is_authorized("search_documents", "hr:confidential")

    # Verified email and recipient authorized for sensitive send_email
    assert ledger.is_authorized("send_email", "alice@corp.example.org")
    assert ledger.is_authorized("send_email", "carlos@corp.example.org")
    # Unverified email not authorized
    assert not ledger.is_authorized("send_email", "malicious@exfil.example")
