"""Central safety gateway for TraceGuard runtime defense.

Module 6 — Runtime Defense & Multi-Turn Episode Runner.
Member 2: Data & Interpretability Lead.

Enforces security policies before any tool action is executed. Checks tool
sensitivity, argument provenance, and authorization ledger entries, returning
structured ALLOW/DENY decisions with standardized reason codes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Union

from traceguard.data.schema import ProvenanceLabel, validate_provenance_label
from traceguard.models.json_parser import ToolRegistry
from traceguard.runtime.authorization import AuthorizationLedger, SENSITIVE_TOOLS


@dataclass(frozen=True)
class GatewayDecision:
    """The structured decision produced by the Safety Gateway for a tool call."""

    decision: str  # "ALLOW" or "DENY"
    reason: Optional[str] = None  # Standardized reason code if DENY
    tool: Optional[str] = None
    argument_provenance: dict[str, ProvenanceLabel] = field(default_factory=dict)
    detail: Optional[str] = None

    @property
    def is_allowed(self) -> bool:
        """Convenience property indicating whether the call was allowed."""
        return self.decision == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "tool": self.tool,
            "argument_provenance": {
                k: v.value if isinstance(v, ProvenanceLabel) else str(v)
                for k, v in self.argument_provenance.items()
            },
            "detail": self.detail,
        }


class SafetyGateway:
    """Runtime security gateway mediating all agent tool invocations.

    Standard Denial Reasons:
    - UNTRUSTED_ARGUMENT: Argument tainted with UNTRUSTED_EXTERNAL
    - DERIVED_UNTRUSTED_ARGUMENT: Argument tainted with DERIVED_UNTRUSTED
    - UNKNOWN_ARGUMENT_PROVENANCE: Argument has UNKNOWN provenance on a sensitive tool
    - UNAUTHORIZED_ACTION: Action or resource is not authorized in ledger
    - INVALID_TOOL: Tool does not exist in registry
    - INVALID_ARGUMENT: Missing or malformed argument
    - SCOPE_VIOLATION: Document scope is outside authorized scopes
    """

    def __init__(self, registry: ToolRegistry, enabled: bool = True) -> None:
        self.registry = registry
        self.enabled = enabled

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        argument_provenances: Mapping[str, Union[ProvenanceLabel, str]],
        ledger: AuthorizationLedger,
    ) -> GatewayDecision:
        """Evaluate a tool invocation against safety policies and ledger."""
        # 1. Tool registry existence check
        spec = self.registry.get(tool_name)
        if spec is None:
            return GatewayDecision(
                decision="DENY",
                reason="INVALID_TOOL",
                tool=tool_name,
                detail=f"Tool {tool_name!r} is not registered in ToolRegistry",
            )

        # Check required arguments and argument tampering
        for arg_name, arg_spec in spec.arguments.items():
            if arg_spec.required and arg_name not in arguments:
                alias = None
                if arg_name == "to" and "recipient" in arguments:
                    alias = "recipient"
                elif arg_name == "path" and "file_handle" in arguments:
                    alias = "file_handle"
                elif arg_name == "doc_id" and "document_id" in arguments:
                    alias = "document_id"
                if alias is None:
                    return GatewayDecision(
                        decision="DENY",
                        reason="INVALID_ARGUMENT",
                        tool=tool_name,
                        detail=f"Missing required argument {arg_name!r} for tool {tool_name!r}",
                    )

        # Normalize argument provenances
        norm_provs: dict[str, ProvenanceLabel] = {
            k: validate_provenance_label(v) for k, v in argument_provenances.items()
        }

        # 2. If gateway is disabled (e.g. baseline E0 / prompt-only E1), pass through
        if not self.enabled:
            return GatewayDecision(
                decision="ALLOW",
                tool=tool_name,
                argument_provenance=norm_provs,
                detail="Gateway pass-through (gateway disabled)",
            )

        # 3. Non-sensitive tools evaluation
        if not spec.sensitive:
            # Check document scope restrictions if search_documents specifies scope
            if tool_name == "search_documents" and "scope" in arguments:
                scope = str(arguments["scope"])
                if not ledger.is_authorized("search_documents", scope):
                    return GatewayDecision(
                        decision="DENY",
                        reason="SCOPE_VIOLATION",
                        tool=tool_name,
                        argument_provenance=norm_provs,
                        detail=f"Document search scope {scope!r} is not authorized",
                    )
            return GatewayDecision(
                decision="ALLOW",
                tool=tool_name,
                argument_provenance=norm_provs,
                detail="Non-sensitive tool allowed",
            )

        # 4. Sensitive tools evaluation (draft_email, send_email, read_private_file)
        # 4A. Determine target resource for authorization check
        target_resource: Optional[str] = None
        if tool_name in {"draft_email", "send_email"}:
            target_resource = arguments.get("to") or arguments.get("recipient")
            # Also check additional recipients (cc, bcc)
            for extra_recip_arg in ("cc", "bcc"):
                extra_val = arguments.get(extra_recip_arg)
                if extra_val:
                    extra_recips = extra_val if isinstance(extra_val, list) else [extra_val]
                    for er in extra_recips:
                        if not ledger.is_authorized(tool_name, str(er)):
                            return GatewayDecision(
                                decision="DENY",
                                reason="UNAUTHORIZED_ACTION",
                                tool=tool_name,
                                argument_provenance=norm_provs,
                                detail=f"Additional recipient {extra_recip_arg!r} ({er!r}) is not authorized in ledger",
                            )
        elif tool_name == "read_private_file":
            target_resource = arguments.get("path") or arguments.get("file_handle")

        # 4B. Authorization check in ledger
        if not ledger.is_authorized(tool_name, target_resource):
            return GatewayDecision(
                decision="DENY",
                reason="UNAUTHORIZED_ACTION",
                tool=tool_name,
                argument_provenance=norm_provs,
                detail=f"Action {tool_name!r} targeting resource {target_resource!r} is not authorized in ledger",
            )

        # 4C. Argument provenance check on all arguments
        is_user_self_email = (
            tool_name in {"draft_email", "send_email"}
            and ledger.is_verified_user_email(target_resource)
        )

        for arg_name, arg_val in arguments.items():
            prov = norm_provs.get(arg_name, ProvenanceLabel.UNKNOWN)

            if prov == ProvenanceLabel.UNTRUSTED_EXTERNAL:
                if not (is_user_self_email and arg_name in {"subject", "body"}):
                    return GatewayDecision(
                        decision="DENY",
                        reason="UNTRUSTED_ARGUMENT",
                        tool=tool_name,
                        argument_provenance=norm_provs,
                        detail=f"Sensitive tool {tool_name!r} argument {arg_name!r} has UNTRUSTED_EXTERNAL provenance",
                    )

            if prov == ProvenanceLabel.DERIVED_UNTRUSTED:
                if not (is_user_self_email and arg_name in {"subject", "body"}):
                    return GatewayDecision(
                        decision="DENY",
                        reason="DERIVED_UNTRUSTED_ARGUMENT",
                        tool=tool_name,
                        argument_provenance=norm_provs,
                        detail=f"Sensitive tool {tool_name!r} argument {arg_name!r} has DERIVED_UNTRUSTED provenance",
                    )

            if prov == ProvenanceLabel.UNKNOWN:
                return GatewayDecision(
                    decision="DENY",
                    reason="UNKNOWN_ARGUMENT_PROVENANCE",
                    tool=tool_name,
                    argument_provenance=norm_provs,
                    detail=f"Sensitive tool {tool_name!r} argument {arg_name!r} has UNKNOWN provenance",
                )

        # All checks passed: authorized and trusted
        return GatewayDecision(
            decision="ALLOW",
            tool=tool_name,
            argument_provenance=norm_provs,
            detail="Sensitive tool call authorized and verified trusted",
        )
