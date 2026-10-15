
import pytest

from app.security.attack_trace import trace_attacks


def make_event(
    tool_name,
    decision,
    execution_attempted,
    reason,
    session_id=None,
    event_id=None,
):
    event = {
        "tool_name": tool_name,
        "decision": decision,
        "execution_attempted": execution_attempted,
        "reason": reason,
        "timestamp": "2026-10-15T04:00:00+00:00",
    }

    if session_id is not None:
        event["session_id"] = session_id

    if event_id is not None:
        event["event_id"] = event_id

    return event


def test_report_read_then_blocked_send_creates_trace():
    events = [
        make_event(
            "read_report", "ALLOW", True, "Approved report read."
        ),
        make_event(
            "send_external",
            "BLOCK",
            False,
            "multi_step_attack: suspicious sequence.",
        ),
    ]

    traces = trace_attacks(events)

    assert len(traces) == 1
    assert traces[0]["category"] == "report_read_then_external_send"
    assert len(traces[0]["events"]) == 2
    assert traces[0]["events"][0]["tool_name"] == "read_report"
    assert traces[0]["events"][1]["tool_name"] == "send_external"
    assert traces[0]["events"][1]["execution_attempted"] is False


def test_blocked_send_without_prior_read_creates_no_trace():
    events = [
        make_event(
            "send_external",
            "BLOCK",
            False,
            "External sending is disabled.",
        )
    ]

    assert trace_attacks(events) == []


def test_unrelated_calculation_does_not_create_trace():
    events = [
        make_event(
            "calculate_total", "ALLOW", True, "Calculation succeeded."
        ),
        make_event("read_report", "ALLOW", True, "Approved report read."),
    ]

    assert trace_attacks(events) == []


def test_trace_includes_risk_information():
    events = [
        make_event("read_report", "ALLOW", True, "Read approved."),
        make_event("send_external", "BLOCK", False, "Blocked."),
    ]

    trace = trace_attacks(events)[0]

    assert trace["severity"] == "high"
    assert trace["events"][-1]["risk_score"] >= 35
    assert trace["events"][-1]["risk_level"] in {"MEDIUM", "HIGH"}


def test_invalid_events_input_is_rejected():
    with pytest.raises(ValueError, match="events must be a list"):
        trace_attacks("not a list")


def test_invalid_window_size_is_rejected():
    with pytest.raises(ValueError, match="window_size must be positive"):
        trace_attacks([], window_size=0)


def test_different_sessions_do_not_create_a_false_trace():
    events = [
        make_event(
            "read_report",
            "ALLOW",
            True,
            "Report read in session A.",
            session_id="session-A",
        ),
        make_event(
            "send_external",
            "BLOCK",
            False,
            "Blocked send in session B.",
            session_id="session-B",
        ),
    ]

    assert trace_attacks(events) == []


def test_duplicate_blocked_event_does_not_create_duplicate_trace():
    report_read = make_event(
        "read_report",
        "ALLOW",
        True,
        "Approved report read.",
        session_id="session-A",
        event_id="read-1",
    )

    blocked_send = make_event(
        "send_external",
        "BLOCK",
        False,
        "Blocked external send.",
        session_id="session-A",
        event_id="send-1",
    )

    events = [report_read, blocked_send, blocked_send.copy()]

    traces = trace_attacks(events)

    assert len(traces) == 1
    assert traces[0]["events"][-1]["tool_name"] == "send_external"
