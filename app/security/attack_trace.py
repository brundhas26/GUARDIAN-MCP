
"""AttackTrace: build session-aware investigation timelines from audit events."""

import json
from pathlib import Path
from typing import Any

from app.audit.logger import AUDIT_FILE
from app.security.risk_scoring import calculate_risk


def load_audit_events(log_path: Path | str = AUDIT_FILE) -> list[dict[str, Any]]:
    """Load valid JSON audit events from a JSONL file."""
    path = Path(log_path)

    if not path.exists():
        return []

    events = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in audit log at line {line_number}."
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"Audit event at line {line_number} must be an object."
                )

            events.append(event)

    return events


def _session_key(event: dict[str, Any]) -> str:
    """Return a session grouping key, with a legacy fallback."""
    session_id = event.get("session_id")

    if isinstance(session_id, str) and session_id.strip():
        return f"session:{session_id}"

    # Older audit events may not contain session IDs.
    # Their session cannot be reliably determined.
    return "legacy:session-unknown"


def _make_timeline_event(
    event: dict[str, Any],
    step_number: int,
    suspicious_sequence: bool = False,
) -> dict[str, Any]:
    """Convert an audit event into a timeline entry with a risk assessment."""
    tool_name = event.get("tool_name", "unknown")
    decision = event.get("decision", "UNKNOWN")
    reason = event.get("reason", "No reason recorded.")

    risk_decision = (
        decision if decision in {"ALLOW", "BLOCK"} else "BLOCK"
    )

    risk = calculate_risk(
        tool_name=tool_name,
        arguments={},
        decision=risk_decision,
        suspicious_sequence=suspicious_sequence,
    )

    return {
        "step": step_number,
        "timestamp": event.get("timestamp"),
        "session_id": event.get("session_id"),
        "tool_name": tool_name,
        "decision": decision,
        "reason": reason,
        "execution_attempted": event.get("execution_attempted", False),
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
    }


def trace_attacks(
    events: list[dict[str, Any]],
    window_size: int = 10,
) -> list[dict[str, Any]]:
    """Find report-read then blocked-send sequences within matching sessions."""
    if not isinstance(events, list):
        raise ValueError("events must be a list.")

    if not isinstance(window_size, int) or isinstance(window_size, bool):
        raise ValueError("window_size must be an integer.")

    if window_size < 1:
        raise ValueError("window_size must be positive.")

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Every event must be a dictionary.")

    # Keep each session's events separate so unrelated sessions are not mixed.
    session_events: dict[str, list[dict[str, Any]]] = {}

    for original_index, event in enumerate(events):
        session_key = _session_key(event)

        session_events.setdefault(session_key, []).append(
            {
                "_original_index": original_index,
                "event": event,
            }
        )

    traces = []
    traced_block_ids = set()

    for session_key, indexed_events in session_events.items():
        for position, item in enumerate(indexed_events):
            blocked_event = item["event"]

            if (
                blocked_event.get("tool_name") != "send_external"
                or blocked_event.get("decision") != "BLOCK"
            ):
                continue

            blocked_id = blocked_event.get("event_id")

            # Deduplicate when an event has a stable audit event ID.
            if blocked_id is not None and blocked_id in traced_block_ids:
                continue

            start = max(0, position - window_size + 1)
            recent_events = indexed_events[start:position]

            # Find the closest successful report read in this same session.
            read_item = None

            for previous_item in reversed(recent_events):
                previous_event = previous_item["event"]

                if (
                    previous_event.get("tool_name") == "read_report"
                    and previous_event.get("decision") == "ALLOW"
                    and previous_event.get("execution_attempted") is True
                ):
                    read_item = previous_item
                    break

            if read_item is None:
                continue

            read_event = read_item["event"]

            # Only show the two events that establish this sequence.
            timeline = [
                _make_timeline_event(read_event, 1),
                _make_timeline_event(
                    blocked_event,
                    2,
                    suspicious_sequence=True,
                ),
            ]

            original_index = item["_original_index"]

            traces.append(
                {
                    "trace_id": f"attack-trace-{original_index + 1}",
                    "category": "report_read_then_external_send",
                    "severity": "high",
                    "session_id": (
                        blocked_event.get("session_id")
                        if blocked_event.get("session_id") is not None
                        else read_event.get("session_id")
                    ),
                    "session_correlation": (
                        "session_id"
                        if session_key.startswith("session:")
                        else "legacy_session_unknown"
                    ),
                    "summary": (
                        "A report was read successfully in the same session, "
                        "followed by a blocked external-send request."
                    ),
                    "events": timeline,
                }
            )

            if blocked_id is not None:
                traced_block_ids.add(blocked_id)

    return traces
