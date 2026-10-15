
"""Session-aware multi-step attack detection for GUARDIAN MCP."""

from collections import deque
from typing import Any


class AttackSequenceDetector:
    """Detect suspicious tool-call sequences separately per session."""

    def __init__(self, max_events: int = 100) -> None:
        if not isinstance(max_events, int) or isinstance(max_events, bool):
            raise ValueError("max_events must be an integer.")

        if max_events < 1:
            raise ValueError("max_events must be positive.")

        self.max_events = max_events
        self._sessions: dict[str, deque[dict[str, Any]]] = {}

    def observe(
        self,
        event: dict[str, Any],
        session_id: str = "default",
    ) -> dict[str, Any]:
        """Record an event and check for a report-read/external-send sequence."""

        if not isinstance(event, dict):
            raise ValueError("event must be a dictionary.")

        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be non-empty text.")

        tool_name = event.get("tool_name")
        decision = event.get("decision")
        execution_attempted = event.get("execution_attempted")

        if not isinstance(tool_name, str) or not isinstance(decision, str):
            raise ValueError("Event must contain tool_name and decision text.")

        history = self._sessions.setdefault(
            session_id,
            deque(maxlen=self.max_events),
        )

        # Detect before appending the current event: the current request must
        # not count as a successful prior action.
        successful_read_exists = any(
            previous.get("tool_name") == "read_report"
            and previous.get("decision") == "ALLOW"
            and previous.get("execution_attempted") is True
            for previous in history
        )

        if (
            successful_read_exists
            and tool_name == "send_external"
        ):
            return {
                "decision": "BLOCK",
                "category": "multi_step_attack",
                "severity": "high",
                "reason": (
                    "This session previously read a report and is now "
                    "attempting an external send."
                ),
            }

        history.append(dict(event))

        return {
            "decision": "ALLOW",
            "category": "none",
            "severity": "low",
            "reason": "No configured suspicious sequence detected.",
        }

    def clear_session(self, session_id: str) -> None:
        """Clear tracked events for a session."""
        self._sessions.pop(session_id, None)
