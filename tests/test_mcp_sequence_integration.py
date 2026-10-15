import pytest

from app.mcp_server import local_server


def test_mcp_server_uses_attack_sequence_detector(monkeypatch):
    """Verify that a successful MCP report read is recorded by the detector."""

    observed_events = []

    def fake_observe(event, session_id="default"):
        observed_events.append(
            {
                "event": event.copy(),
                "session_id": session_id,
            }
        )
        return {
            "decision": "ALLOW",
            "category": "none",
            "severity": "low",
            "reason": "Test event recorded.",
        }

    monkeypatch.setattr(
        local_server.ATTACK_SEQUENCE_DETECTOR,
        "observe",
        fake_observe,
    )

    local_server.observe_sequence(
        tool_name="read_report",
        decision="ALLOW",
        execution_attempted=True,
    )

    assert len(observed_events) == 1
    assert observed_events[0]["event"]["tool_name"] == "read_report"
    assert observed_events[0]["event"]["decision"] == "ALLOW"
    assert observed_events[0]["event"]["execution_attempted"] is True
    assert observed_events[0]["session_id"] == "mcp-local-server"


def test_mcp_server_sequence_check_blocks_detected_external_send(monkeypatch):
    """Verify that a detected sequence is passed to the blocking handler."""

    def fake_observe(event, session_id="default"):
        assert event["tool_name"] == "send_external"
        assert event["execution_attempted"] is False
        return {
            "decision": "BLOCK",
            "category": "multi_step_attack",
            "severity": "high",
            "reason": "Suspicious report-read followed by external-send sequence.",
        }

    def fake_record_block(tool_name, category, reason):
        raise RuntimeError(
            f"BLOCKED:{tool_name}:{category}:{reason}"
        )

    monkeypatch.setattr(
        local_server.ATTACK_SEQUENCE_DETECTOR,
        "observe",
        fake_observe,
    )
    monkeypatch.setattr(local_server, "record_block", fake_record_block)

    with pytest.raises(RuntimeError, match="BLOCKED:send_external:multi_step_attack"):
        local_server.check_external_send_sequence()
