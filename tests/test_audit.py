
import json

from app.audit import logger


def test_audit_event_is_written_and_verifies(tmp_path, monkeypatch):
    audit_file = tmp_path / "events.jsonl"
    monkeypatch.setattr(logger, "AUDIT_FILE", audit_file)

    event = logger.record_decision(
        tool_name="calculate_total",
        decision="ALLOW",
        reason="Tool and arguments are permitted by policy",
        execution_attempted=True,
    )

    assert event["tool_name"] == "calculate_total"
    assert event["decision"] == "ALLOW"
    assert event["execution_attempted"] is True
    assert event["event_id"]
    assert logger.verify_audit_log() is True


def test_blocked_request_is_recorded(tmp_path, monkeypatch):
    audit_file = tmp_path / "events.jsonl"
    monkeypatch.setattr(logger, "AUDIT_FILE", audit_file)

    event = logger.record_decision(
        tool_name="read_report",
        decision="BLOCK",
        reason="Filename is not permitted",
        execution_attempted=False,
    )

    assert event["decision"] == "BLOCK"
    assert event["execution_attempted"] is False
    assert logger.verify_audit_log() is True


def test_tampered_event_fails_verification(tmp_path, monkeypatch):
    audit_file = tmp_path / "events.jsonl"
    monkeypatch.setattr(logger, "AUDIT_FILE", audit_file)

    logger.record_decision(
        tool_name="calculate_total",
        decision="ALLOW",
        reason="Approved",
        execution_attempted=True,
    )

    event = json.loads(audit_file.read_text(encoding="utf-8"))
    event["reason"] = "Changed after recording"
    audit_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

    assert logger.verify_audit_log() is False
