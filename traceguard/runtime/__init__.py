"""TraceGuard Runtime Defense and Multi-Turn Episode Runner package.

Module 6 — Runtime Defense & Multi-Turn Episode Runner.
Member 2: Data & Interpretability Lead.
"""

from traceguard.runtime.authorization import (
    DEFAULT_NON_SENSITIVE_TOOLS,
    SENSITIVE_TOOLS,
    AuthorizationEntry,
    AuthorizationLedger,
)
from traceguard.runtime.gateway import GatewayDecision, SafetyGateway
from traceguard.runtime.logging import EpisodeExecutionLog, TurnExecutionRecord
from traceguard.runtime.provenance import (
    ProvenanceTracker,
    TrackedEntity,
    combine_provenance,
)
from traceguard.runtime.runner import EpisodeRunner
from traceguard.runtime.tools import MockToolExecutor, ToolResult

__all__ = [
    "AuthorizationEntry",
    "AuthorizationLedger",
    "DEFAULT_NON_SENSITIVE_TOOLS",
    "EpisodeExecutionLog",
    "EpisodeRunner",
    "GatewayDecision",
    "MockToolExecutor",
    "ProvenanceTracker",
    "SENSITIVE_TOOLS",
    "SafetyGateway",
    "ToolResult",
    "TrackedEntity",
    "TurnExecutionRecord",
    "combine_provenance",
]
