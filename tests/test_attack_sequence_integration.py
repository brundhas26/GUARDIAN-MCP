
"""Integration tests for multi-step detection in the runtime gateway."""

from app.gateway import runtime
from app.security.attack_sequence import AttackSequenceDetector


def test_report_read_then_external_send_is_blocked_before_execution(
    monkeypatch,
):
    # Give this test isolated sequence history.
    monkeypatch.setattr(
        runtime,
        "ATTACK_SEQUENCE_DETECTOR",
        AttackSequenceDetector(),
    )

    # Keep the test from writing to the real audit file.
    monkeypatch.setattr(runtime, "record_decision", lambda **kwargs: {})

    executed = []

    # Simulate an external tool so we can prove it never runs.
    monkeypatch.setitem(
        runtime.TOOL_REGISTRY,
        "send_external",
        lambda **kwargs: executed.append(True),
    )

    read_result = runtime.execute_tool(
        "read_report",
        {"filename": "summary.txt"},
        session_id="test-session",
    )

    assert read_result["decision"] == "ALLOW"

    send_result = runtime.execute_tool(
        "send_external",
        {"content": "report contents"},
        session_id="test-session",
    )

    assert send_result["decision"] == "BLOCK"
    assert send_result["category"] == "multi_step_attack"
    assert send_result["executed"] is False
    assert executed == []


def test_external_send_after_read_in_another_session_is_not_sequence_flagged(
    monkeypatch,
):
    monkeypatch.setattr(
        runtime,
        "ATTACK_SEQUENCE_DETECTOR",
        AttackSequenceDetector(),
    )
    monkeypatch.setattr(runtime, "record_decision", lambda **kwargs: {})

    executed = []

    monkeypatch.setitem(
        runtime.TOOL_REGISTRY,
        "send_external",
        lambda **kwargs: executed.append(True),
    )

    read_result = runtime.execute_tool(
        "read_report",
        {"filename": "summary.txt"},
        session_id="session-A",
    )

    assert read_result["decision"] == "ALLOW"

    send_result = runtime.execute_tool(
        "send_external",
        {"content": "test"},
        session_id="session-B",
    )

    # It should not be classified as a multi-step attack across sessions.
    # The existing policy must still deny this prohibited tool.
    assert send_result["decision"] == "BLOCK"
    assert send_result["category"] != "multi_step_attack"
    assert send_result["executed"] is False
    assert executed == []
