"""TraceGuard logs must be consumable by AuditKIT's own agent evaluation.

Runs the real ``auditkit.AgentEvalRunner`` (recorded mode) over episodes produced
by the TraceGuard adapter. TraceGuard's deterministic scorer remains the
authority; this only proves the exchange format is readable by AuditKIT.
"""

from __future__ import annotations

import pytest

pytest.importorskip("auditkit")

from auditkit import AgentCase, AgentEvalRunner, AgentEvalSpec  # noqa: E402

from traceguard.experiments.auditkit_adapter import to_auditkit_episode  # noqa: E402
from traceguard.experiments.evaluation import Evaluator  # noqa: E402

TOOLS = [
    "search_emails", "read_email", "search_documents", "read_document",
    "retrieve_notes", "save_note", "draft_email", "send_email", "read_private_file",
]


@pytest.fixture(scope="module")
def evaluated():
    ev = Evaluator()
    attack, benign = ev.load_episodes(split="dev")
    episodes = attack + benign
    _, logs = ev.evaluate_configuration("E2b", split="dev")
    by_id = {e.episode_id: e for e in episodes}
    ak_eps = [to_auditkit_episode(log, by_id.get(log.episode_id)) for log in logs]
    cases = [
        AgentCase(id=e.episode_id, task=e.initial_user_task, allowed_tools=TOOLS)
        for e in episodes
    ]
    spec = AgentEvalSpec(
        cases=cases, mode="recorded", episodes=ak_eps,
        scorers=["tool_call_validity"], name="traceguard-E2b-dev",
    )
    return AgentEvalRunner().run(spec), len(episodes)


def test_auditkit_evaluation_completes_for_every_episode(evaluated):
    result, n = evaluated
    assert len(result.rows) == n
    assert {r.status for r in result.rows} == {"completed"}


def test_auditkit_reads_tool_calls_with_full_coverage(evaluated):
    result, _ = evaluated
    for row in result.rows:
        assert row.coverage["tool_call_names"] == "observed"
        assert row.coverage["tool_call_arguments"] == "observed"
        assert row.ineligible == {}


def test_traceguard_scores_are_carried_through_unchanged(evaluated):
    result, _ = evaluated
    scores = result.rows[0].provenance["source_scores"]
    assert set(scores) >= {"overall_passed", "canary_leaked", "prohibited_action_taken"}


def test_tool_call_validity_metric_is_computed(evaluated):
    result, _ = evaluated
    assert all("tool_call_validity" in r.diagnostics for r in result.rows)
