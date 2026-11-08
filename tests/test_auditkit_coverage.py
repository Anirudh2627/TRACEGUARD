"""AuditKIT coverage must be computed from the events actually emitted.

Regression tests for: successful calls, gateway-denied calls, missing result
events, and correct call-result pairing. A denied call never produces a result
event, so it must never be reported as a completed call-result pair.
"""

from __future__ import annotations

import pytest

pytest.importorskip("auditkit")

from traceguard.experiments.auditkit_adapter import (  # noqa: E402
    compute_coverage,
    to_auditkit_episode,
    turn_to_auditkit_events,
)
from traceguard.runtime.logging import EpisodeExecutionLog, TurnExecutionRecord  # noqa: E402

OBSERVED, UNAVAILABLE = "observed", "unavailable"


def _turn(turn_id, tool=None, args=None, decision="ALLOW", executed=True, result=None):
    return TurnExecutionRecord(
        turn_id=turn_id,
        user_message=f"user turn {turn_id}",
        model_raw_output="{}",
        parsed_kind="tool_call" if tool else "final",
        parsed_tool=tool,
        parsed_arguments=args or {},
        argument_provenance={},
        gateway_decision=decision,
        gateway_reason="x",
        tool_executed=bool(tool) and executed,
        tool_result=result if result is not None else ({"ok": True} if executed and tool else None),
    )


def _events(*turns):
    out, idx = [], 0
    for t in turns:
        evs = turn_to_auditkit_events(t, start_index=idx)
        out.extend(evs)
        idx += len(evs)
    return out


def _log(*turns):
    return EpisodeExecutionLog(
        episode_id="ep_cov", template_id="t", split="dev", is_attack=False,
        config_name="E2b", turns=list(turns), overall_passed=True,
        attack_blocked=None, canary_leaked=False, prohibited_action_taken=False,
    )


# ------------------------------------------------------------ successful call
def test_successful_call_is_fully_observed_and_paired():
    cov, detail = compute_coverage(
        _events(_turn(1, "read_email", {"email_id": "eml_1"}))
    )
    assert cov == {
        "tool_call_names": OBSERVED,
        "tool_call_arguments": OBSERVED,
        "tool_results": OBSERVED,
        "call_result_pairing": OBSERVED,
    }
    assert detail == {"n_tool_calls": 1, "n_paired": 1, "n_denied": 0, "n_allowed_missing_result": 0}


# ------------------------------------------------------------ denied call
def test_denied_call_is_not_reported_as_a_completed_pair():
    cov, detail = compute_coverage(
        _events(_turn(1, "send_email", {"to": "x@evil.test"}, decision="DENY", executed=False))
    )
    assert cov["tool_call_names"] == OBSERVED          # the attempt itself was observed
    assert cov["tool_call_arguments"] == OBSERVED
    assert cov["tool_results"] == UNAVAILABLE          # nothing executed
    assert cov["call_result_pairing"] == UNAVAILABLE   # no result to pair with
    assert detail["n_denied"] == 1 and detail["n_paired"] == 0


def test_denied_call_does_not_inflate_pairing_next_to_a_real_pair():
    events = _events(
        _turn(1, "read_email", {"email_id": "eml_1"}),
        _turn(2, "send_email", {"to": "x@evil.test"}, decision="DENY", executed=False),
    )
    cov, detail = compute_coverage(events)
    assert cov["call_result_pairing"] == OBSERVED      # the real pair counts
    assert detail == {"n_tool_calls": 2, "n_paired": 1, "n_denied": 1, "n_allowed_missing_result": 0}


# ------------------------------------------------------------ missing result
def test_allowed_call_with_missing_result_event_is_not_paired():
    events = [e for e in _events(_turn(1, "read_email", {"email_id": "eml_1"}))
              if e.type != "tool_result"]
    cov, detail = compute_coverage(events)
    assert cov["call_result_pairing"] == UNAVAILABLE
    assert cov["tool_results"] == UNAVAILABLE
    assert detail["n_allowed_missing_result"] == 1 and detail["n_paired"] == 0


def test_one_missing_result_downgrades_pairing_even_if_another_call_paired():
    events = _events(
        _turn(1, "read_email", {"email_id": "eml_1"}),
        _turn(2, "read_document", {"doc_id": "doc_1"}),
    )
    events = [e for e in events if not (e.type == "tool_result" and e.turn_id == 2)]
    cov, detail = compute_coverage(events)
    assert cov["call_result_pairing"] == UNAVAILABLE
    assert detail["n_paired"] == 1 and detail["n_allowed_missing_result"] == 1


# ------------------------------------------------------------ pairing correctness
def test_pairing_is_by_call_id_not_by_position():
    events = _events(_turn(1, "read_email", {"email_id": "eml_1"}))
    for e in events:
        if e.type == "tool_result":
            e.call_id = "some_other_call"                # result points at a different call
    cov, detail = compute_coverage(events)
    assert cov["call_result_pairing"] == UNAVAILABLE
    assert detail["n_paired"] == 0


def test_result_and_call_share_the_same_call_id_in_the_emitted_events():
    events = _events(_turn(1, "read_email", {"email_id": "eml_1"}))
    call = next(e for e in events if e.type == "tool_call")
    result = next(e for e in events if e.type == "tool_result")
    assert call.call_id and call.call_id == result.call_id


def test_two_executed_calls_pair_one_to_one():
    cov, detail = compute_coverage(
        _events(
            _turn(1, "read_email", {"email_id": "eml_1"}),
            _turn(2, "read_document", {"doc_id": "doc_1"}),
        )
    )
    assert cov["call_result_pairing"] == OBSERVED
    assert detail["n_paired"] == 2 and detail["n_tool_calls"] == 2


# ------------------------------------------------------------ no calls
def test_episode_without_tool_calls_claims_nothing():
    cov, detail = compute_coverage(_events(_turn(1, None)))
    assert set(cov.values()) == {UNAVAILABLE}
    assert detail["n_tool_calls"] == 0


def test_call_without_arguments_dict_is_not_argument_observed():
    events = _events(_turn(1, "read_email", {"email_id": "eml_1"}))
    for e in events:
        if e.type == "tool_call":
            e.payload["arguments"] = None
    cov, _ = compute_coverage(events)
    assert cov["tool_call_names"] == OBSERVED
    assert cov["tool_call_arguments"] == UNAVAILABLE


# ------------------------------------------------------------ end to end through the episode
def test_episode_object_carries_computed_coverage_and_detail():
    ep = to_auditkit_episode(
        _log(
            _turn(1, "read_email", {"email_id": "eml_1"}),
            _turn(2, "send_email", {"to": "x@evil.test"}, decision="DENY", executed=False),
        )
    )
    assert ep.coverage["call_result_pairing"] == OBSERVED
    assert ep.metadata["coverage_detail"]["n_denied"] == 1


def test_denied_only_episode_object_does_not_claim_pairing():
    ep = to_auditkit_episode(
        _log(_turn(1, "send_email", {"to": "x@evil.test"}, decision="DENY", executed=False))
    )
    assert ep.coverage["call_result_pairing"] == UNAVAILABLE
    assert ep.coverage["tool_results"] == UNAVAILABLE
