
"""Human-in-the-loop approval management for GUARDIAN MCP."""

from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from uuid import uuid4


class HumanApprovalManager:
    """Manage approval requests without executing tools."""

    def __init__(self):
        self._requests = {}
        self._lock = RLock()

    def create_request(
        self,
        tool_name,
        arguments,
        reason,
        risk_score=0,
        risk_level="HIGH",
        session_id="default",
    ):
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("tool_name must be a non-empty string.")
        if not isinstance(arguments, dict):
            raise ValueError("arguments must be a dictionary.")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be a non-empty string.")
        if (
            not isinstance(risk_score, int)
            or isinstance(risk_score, bool)
            or not 0 <= risk_score <= 100
        ):
            raise ValueError("risk_score must be an integer from 0 to 100.")
        if not isinstance(risk_level, str) or not risk_level.strip():
            raise ValueError("risk_level must be a non-empty string.")
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string.")

        request = {
            "request_id": str(uuid4()),
            "tool_name": tool_name,
            "arguments": deepcopy(arguments),
            "reason": reason,
            "risk_score": risk_score,
            "risk_level": risk_level.upper(),
            "session_id": session_id,
            "status": "PENDING",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reviewed_at": None,
            "reviewer": None,
            "review_comment": None,
        }

        with self._lock:
            self._requests[request["request_id"]] = request

        return deepcopy(request)

    def list_pending(self):
        with self._lock:
            return [
                deepcopy(request)
                for request in self._requests.values()
                if request["status"] == "PENDING"
            ]

    def get_request(self, request_id):
        with self._lock:
            request = self._requests.get(request_id)
            return deepcopy(request) if request is not None else None

    def approve(self, request_id, reviewer, comment=""):
        return self._review(request_id, reviewer, "APPROVED", comment)

    def reject(self, request_id, reviewer, comment=""):
        return self._review(request_id, reviewer, "REJECTED", comment)

    def consume_approved_request(
        self,
        request_id,
        tool_name,
        arguments,
        session_id,
    ):
        """Consume one approval for the exact action and session reviewed."""
        with self._lock:
            request = self._requests.get(request_id)

            if request is None:
                return {
                    "decision": "BLOCK",
                    "reason": "Approval request was not found.",
                }

            if request["status"] != "APPROVED":
                return {
                    "decision": "BLOCK",
                    "reason": "Request has not been approved or was already used.",
                }

            if (
                request["tool_name"] != tool_name
                or request["arguments"] != arguments
                or request["session_id"] != session_id
            ):
                return {
                    "decision": "BLOCK",
                    "reason": "Approved action does not match this request.",
                }

            request["status"] = "CONSUMED"
            request["consumed_at"] = datetime.now(timezone.utc).isoformat()

            return {
                "decision": "ALLOW",
                "reason": "Approved request consumed for the matching action.",
            }

    def _review(self, request_id, reviewer, status, comment):
        if not isinstance(reviewer, str) or not reviewer.strip():
            raise ValueError("reviewer must be a non-empty string.")
        if not isinstance(comment, str):
            raise ValueError("comment must be a string.")

        with self._lock:
            request = self._requests.get(request_id)

            if request is None:
                raise KeyError("Approval request was not found.")
            if request["status"] != "PENDING":
                raise ValueError("This request has already been reviewed.")

            request["status"] = status
            request["reviewed_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            request["reviewer"] = reviewer.strip()
            request["review_comment"] = comment.strip()

            return deepcopy(request)
