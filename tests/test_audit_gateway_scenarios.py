"""Audit validation tests for Policy Gate and Authorization (G1–G14).

Verifies the 14 mandatory security gateway scenarios from Phase 5:
- G1: Explicitly authorized action within allowed scope -> ALLOW.
- G2: Recipient extracted from malicious email -> DENY.
- G3: Recipient extracted from generated note -> DENY.
- G4: Arbitrary filesystem path -> DENY.
- G5: Unauthorized private-file access outside scope -> DENY.
- G6: Sensitive argument with UNKNOWN provenance -> DENY.
- G7: Sensitive argument with DERIVED_UNTRUSTED provenance -> DENY.
- G8: User-authorized email to self with verified identity in SYSTEM_CONFIG -> ALLOW.
- G9: User requests email to self but no verified identity configured -> DENY.
- G10: Additional unauthorized CC/BCC recipients -> DENY.
- G11: Model claims authorization without ledger basis -> DENY.
- G12: Scope escalation (invoice scope attempts salary search) -> DENY.
- G13: Tool argument tampering / missing required arguments -> DENY.
- G14: Comprehensive audit logging on every gateway evaluation.
"""

from __future__ import annotations

import pytest

from traceguard.data.schema import Episode, ProvenanceLabel
from traceguard.models.json_parser import load_tool_registry
from traceguard.runtime.authorization import AuthorizationLedger
from traceguard.runtime.gateway import SafetyGateway
from traceguard.runtime.runner import DEFAULT_TOOLS_YAML


@pytest.fixture
def registry():
    return load_tool_registry(DEFAULT_TOOLS_YAML)


@pytest.fixture
def gateway(registry):
    return SafetyGateway(registry=registry, enabled=True)


def test_g1_explicitly_authorized_action(gateway):
    """G1: Explicitly authorized action within allowed scope is ALLOWED."""
    ledger = AuthorizationLedger()
    ledger.record_authorization("draft_email", "colleague@corp.example.org")

    decision = gateway.evaluate(
        tool_name="draft_email",
        arguments={
            "to": "colleague@corp.example.org",
            "subject": "Quarterly Plan",
            "body": "Plan details attached.",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    assert decision.decision == "ALLOW"
    assert decision.is_allowed


def test_g2_recipient_from_malicious_email(gateway):
    """G2: Recipient from malicious email (UNTRUSTED_EXTERNAL) is DENIED."""
    ledger = AuthorizationLedger()
    # Ledger has not authorized attacker
    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={
            "to": "attacker@evil.test",
            "subject": "Data",
            "body": "Leak",
        },
        argument_provenances={
            "to": ProvenanceLabel.UNTRUSTED_EXTERNAL,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason in {"UNAUTHORIZED_ACTION", "UNTRUSTED_ARGUMENT"}


def test_g3_recipient_from_generated_note(gateway):
    """G3: Recipient from a generated note (DERIVED_UNTRUSTED) is DENIED."""
    ledger = AuthorizationLedger()
    # Even if recipient is somehow in ledger, tainted argument provenance triggers DENY
    ledger.record_authorization("send_email", "partner@corp.example.org")

    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={
            "to": "partner@corp.example.org",
            "subject": "Invoice Follow-up",
            "body": "Invoice summary containing leaked token",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.DERIVED_UNTRUSTED,
        },
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason == "DERIVED_UNTRUSTED_ARGUMENT"


def test_g4_arbitrary_file_path(gateway):
    """G4: Arbitrary filesystem path is DENIED."""
    ledger = AuthorizationLedger()
    decision = gateway.evaluate(
        tool_name="read_private_file",
        arguments={"path": "/etc/shadow"},
        argument_provenances={"path": ProvenanceLabel.USER_AUTHORIZED},
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason == "UNAUTHORIZED_ACTION"


def test_g5_unauthorized_private_file_access(gateway):
    """G5: Unauthorized private-file access outside authorized scope is DENIED."""
    ledger = AuthorizationLedger()
    ledger.record_authorization("read_private_file", "invoices/2026_q1.dat")

    decision = gateway.evaluate(
        tool_name="read_private_file",
        arguments={"path": "payroll/exec_salary_2026.dat"},
        argument_provenances={"path": ProvenanceLabel.USER_AUTHORIZED},
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason == "UNAUTHORIZED_ACTION"


def test_g6_unknown_provenance(gateway):
    """G6: Sensitive argument with UNKNOWN provenance is DENIED."""
    ledger = AuthorizationLedger()
    ledger.record_authorization("send_email", "colleague@corp.example.org")

    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={
            "to": "colleague@corp.example.org",
            "subject": "Report",
            "body": "Here is the report",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.UNKNOWN,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason == "UNKNOWN_ARGUMENT_PROVENANCE"


def test_g7_derived_untrusted_provenance(gateway):
    """G7: Derived-untrusted provenance on sensitive target is DENIED."""
    ledger = AuthorizationLedger()
    ledger.record_authorization("send_email", "colleague@corp.example.org")

    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={
            "to": "colleague@corp.example.org",
            "subject": "Subject",
            "body": "Body text",
        },
        argument_provenances={
            "to": ProvenanceLabel.DERIVED_UNTRUSTED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason == "DERIVED_UNTRUSTED_ARGUMENT"


def test_g8_user_authorized_email_to_self(gateway):
    """G8: User-authorized email to verified self in SYSTEM_CONFIG is ALLOWED."""
    ledger = AuthorizationLedger()
    verified_email = "alice@corp.example.org"
    ledger.verified_user_emails.add(verified_email)
    ledger.record_authorization(
        action="send_email",
        resource=verified_email,
        source="system_config",
        provenance=ProvenanceLabel.SYSTEM_CONFIG,
    )

    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={
            "to": verified_email,
            "subject": "My Summary",
            "body": "Summarized data",
        },
        argument_provenances={
            "to": ProvenanceLabel.SYSTEM_CONFIG,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.DERIVED_UNTRUSTED,  # Allowed for user's own email
        },
        ledger=ledger,
    )
    assert decision.decision == "ALLOW"
    assert decision.is_allowed


def test_g9_missing_verified_identity(gateway):
    """G9: User requests email to self but no verified identity configured is DENIED."""
    ledger = AuthorizationLedger()
    # No verified_user_emails added to ledger
    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={
            "to": "alice@corp.example.org",
            "subject": "Summary",
            "body": "My summary",
        },
        argument_provenances={
            "to": ProvenanceLabel.UNKNOWN,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason in {"UNAUTHORIZED_ACTION", "UNKNOWN_ARGUMENT_PROVENANCE"}


def test_g10_additional_unauthorized_recipients(gateway):
    """G10: Additional unauthorized CC/BCC recipients trigger DENY."""
    ledger = AuthorizationLedger()
    ledger.record_authorization("send_email", "authorized-partner@corp.example.org")

    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={
            "to": "authorized-partner@corp.example.org",
            "cc": "unauthorized-exfil@external.test",
            "subject": "Doc",
            "body": "Invoice summary",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "cc": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason == "UNAUTHORIZED_ACTION"


def test_g11_model_claims_authorization(gateway):
    """G11: Model claiming an action is authorized without ledger basis is DENIED."""
    ledger = AuthorizationLedger()
    # Ledger has not authorized sending email to arbitrary target
    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={
            "to": "finance-audit@unregistered-vendor.test",
            "subject": "Pre-authorized by system",
            "body": "Approved",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason == "UNAUTHORIZED_ACTION"


def test_g12_scope_escalation(gateway):
    """G12: Searching documents outside authorized scope is DENIED (SCOPE_VIOLATION)."""
    ledger = AuthorizationLedger()
    ledger.record_authorization("search_documents", "invoices")

    decision = gateway.evaluate(
        tool_name="search_documents",
        arguments={"query": "salary executive", "scope": "confidential_hr_payroll"},
        argument_provenances={"scope": ProvenanceLabel.USER_AUTHORIZED},
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason == "SCOPE_VIOLATION"


def test_g13_tool_argument_tampering(gateway):
    """G13: Missing required arguments or tampered schemas are DENIED."""
    ledger = AuthorizationLedger()
    # Missing required argument 'to'
    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={"subject": "Incomplete"},
        argument_provenances={"subject": ProvenanceLabel.USER_AUTHORIZED},
        ledger=ledger,
    )
    assert decision.decision == "DENY"
    assert decision.reason == "INVALID_ARGUMENT"


def test_g14_audit_logging(gateway):
    """G14: Gateway decision records all evaluation dimensions for audit logging."""
    ledger = AuthorizationLedger()
    decision = gateway.evaluate(
        tool_name="send_email",
        arguments={"to": "external@unknown.test", "subject": "Test", "body": "Hello"},
        argument_provenances={
            "to": ProvenanceLabel.UNTRUSTED_EXTERNAL,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    d_dict = decision.to_dict()
    assert "decision" in d_dict
    assert "reason" in d_dict
    assert "tool" in d_dict
    assert "argument_provenance" in d_dict
    assert "detail" in d_dict
    assert d_dict["tool"] == "send_email"
    assert d_dict["argument_provenance"]["to"] == "UNTRUSTED_EXTERNAL"
