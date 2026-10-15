
"""Tests for GUARDIAN's session-aware attack sequence detector."""

import pytest

from app.security.attack_sequence import AttackSequenceDetector


def test_report_read_then_external_send_is_blocked():
    detector = AttackSequenceDetector()

    detector.observe({
        "tool_name": "read_report",
        "decision": "ALLOW",
        "execution_attempted": True,
    }, session_id="session-1")

    result = detector.observe({
        "tool_name": "send_external",
        "decision": "ALLOW",
        "execution_attempted": False,
    }, session_id="session-1")

    assert result["decision"] == "BLOCK"
    assert result["category"] == "multi_step_attack"
    assert result["severity"] == "high"


def test_calculation_alone_is_not_flagged():
    detector = AttackSequenceDetector()

    result = detector.observe({
        "tool_name": "calculate_total",
        "decision": "ALLOW",
        "execution_attempted": True,
    })

    assert result["decision"] == "ALLOW"


def test_external_send_without_prior_read_is_not_flagged():
    detector = AttackSequenceDetector()

    result = detector.observe({
        "tool_name": "send_external",
        "decision": "BLOCK",
        "execution_attempted": False,
    })

    assert result["decision"] == "ALLOW"


def test_sessions_are_isolated():
    detector = AttackSequenceDetector()

    detector.observe({
        "tool_name": "read_report",
        "decision": "ALLOW",
        "execution_attempted": True,
    }, session_id="session-A")

    result = detector.observe({
        "tool_name": "send_external",
        "decision": "ALLOW",
        "execution_attempted": False,
    }, session_id="session-B")

    assert result["decision"] == "ALLOW"


def test_invalid_event_is_rejected():
    detector = AttackSequenceDetector()

    with pytest.raises(ValueError):
        detector.observe("not an event")


def test_session_can_be_cleared():
    detector = AttackSequenceDetector()

    detector.observe({
        "tool_name": "read_report",
        "decision": "ALLOW",
        "execution_attempted": True,
    }, session_id="session-1")

    detector.clear_session("session-1")

    result = detector.observe({
        "tool_name": "send_external",
        "decision": "ALLOW",
        "execution_attempted": False,
    }, session_id="session-1")

    assert result["decision"] == "ALLOW"
