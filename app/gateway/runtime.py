
"""GUARDIAN MCP runtime security gateway with human approval."""

from pathlib import Path

from app.audit.logger import record_decision
from app.policy.engine import authorize_tool
from app.security.intent_guard import check_intent
from app.security.attack_classifier import classify_attack
from app.security.information_flow import InformationFlowTracker
from app.security.attack_sequence import AttackSequenceDetector
from app.security.risk_scoring import calculate_risk
from app.security.human_approval import HumanApprovalManager
from app.security.desktop_notifications import notify_security_block


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = PROJECT_ROOT / "data" / "reports"

FLOW_TRACKER = InformationFlowTracker()
ATTACK_SEQUENCE_DETECTOR = AttackSequenceDetector()
APPROVAL_MANAGER = HumanApprovalManager()

REPORT_LABELS = {
    "public.txt": "public",
    "summary.txt": "internal",
}

TOOL_REGISTRY = {
    "read_report": None,
    "calculate_total": None,
}

TASK_MAPPING = {
    "calculate_total": "calculate",
    "read_report": "read_public_report",
}


def read_report(filename):
    """Read a report from the reports directory."""
    report_path = REPORTS_DIR / filename

    if not report_path.is_file():
        return {"error": "Report does not exist"}

    try:
        return {"content": report_path.read_text(encoding="utf-8")}
    except OSError:
        return {"error": "Report could not be read"}


def calculate_total(numbers):
    """Calculate the sum of validated numbers."""
    return {"total": sum(numbers)}


TOOL_REGISTRY["read_report"] = read_report
TOOL_REGISTRY["calculate_total"] = calculate_total


def get_data_sensitivity(tool_name, arguments):
    """Determine the configured sensitivity for a tool request."""
    if tool_name == "read_report":
        return REPORT_LABELS.get(
            arguments.get("filename", ""),
            "confidential",
        )
    return "public"


def add_risk(result, tool_name, arguments, suspicious_sequence=False):
    """Attach an explainable risk assessment to a decision."""
    risk = calculate_risk(
        tool_name=tool_name,
        arguments=arguments,
        decision=result["decision"],
        data_sensitivity=get_data_sensitivity(tool_name, arguments),
        suspicious_sequence=suspicious_sequence,
    )

    result["risk_score"] = risk["risk_score"]
    result["risk_level"] = risk["risk_level"]
    result["risk_reasons"] = risk["reasons"]
    return result


def blocked_response(
    category,
    reason,
    severity="medium",
    tool_name="unknown",
    arguments=None,
    suspicious_sequence=False,
    session_id="default",
):
    """Return a blocked response, audit it, and calculate its risk."""
    if arguments is None:
        arguments = {}

    record_decision(
        tool_name=str(tool_name),
        decision="BLOCK",
        reason=f"{category}: {reason}",
        execution_attempted=False,
        session_id=session_id,
    )

    # Notify the user when a request is blocked.
    notify_security_block(
        str(tool_name),
        f"{category}: {reason}",
    )

    response = {
        "decision": "BLOCK",
        "category": category,
        "severity": severity,
        "reason": reason,
        "executed": False,
        "result": None,
    }

    return add_risk(
        response,
        str(tool_name),
        arguments,
        suspicious_sequence=suspicious_sequence,
    )


def pending_approval_response(
    tool_name,
    arguments,
    reason,
    session_id,
):
    """Create an approval request without executing the tool."""

    # Calculate the proposed action's risk without executing it.
    # The risk scorer accepts ALLOW or BLOCK, not PENDING.
    risk = calculate_risk(
        tool_name=tool_name,
        arguments=arguments,
        decision="ALLOW",
        data_sensitivity=get_data_sensitivity(tool_name, arguments),
    )

    request = APPROVAL_MANAGER.create_request(
        tool_name=tool_name,
        arguments=arguments,
        reason=reason,
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        session_id=session_id,
    )

    # The audit logger does not support PENDING.
    # Record the paused execution as BLOCK in the audit trail.
    record_decision(
        tool_name=tool_name,
        decision="BLOCK",
        reason=(
            f"Human approval required; execution paused. "
            f"Approval request ID: {request['request_id']}"
        ),
        execution_attempted=False,
        session_id=session_id,
    )

    # The gateway response accurately identifies the pending request.
    return {
        "decision": "PENDING",
        "category": "human_approval",
        "severity": "high",
        "reason": reason,
        "executed": False,
        "result": None,
        "approval_request_id": request["request_id"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "risk_reasons": risk["reasons"],
    }


def execute_tool(
    tool_name,
    arguments,
    task=None,
    session_id="default",
    require_approval=False,
    approval_request_id=None,
):
    """Validate a tool request before execution and enforce approval."""

    if not isinstance(session_id, str) or not session_id.strip():
        session_id = "default"

    if not isinstance(arguments, dict):
        return blocked_response(
            "invalid_arguments",
            "Tool arguments must be a dictionary.",
            tool_name=str(tool_name),
            session_id=session_id,
        )

    if not isinstance(require_approval, bool):
        return blocked_response(
            "invalid_arguments",
            "require_approval must be True or False.",
            tool_name=str(tool_name),
            arguments=arguments,
            session_id=session_id,
        )

    if approval_request_id is not None and (
        not isinstance(approval_request_id, str)
        or not approval_request_id.strip()
    ):
        return blocked_response(
            "invalid_approval",
            "Approval request ID must be a non-empty string.",
            tool_name=str(tool_name),
            arguments=arguments,
            session_id=session_id,
        )

    # External sending remains prohibited.
    if tool_name == "send_external":
        sequence_decision = ATTACK_SEQUENCE_DETECTOR.observe(
            {
                "tool_name": "send_external",
                "decision": "BLOCK",
                "execution_attempted": False,
            },
            session_id=session_id,
        )

        if sequence_decision["decision"] == "BLOCK":
            return blocked_response(
                sequence_decision["category"],
                sequence_decision["reason"],
                sequence_decision["severity"],
                tool_name=tool_name,
                arguments=arguments,
                suspicious_sequence=True,
                session_id=session_id,
            )

    # Only registered tools can be executed.
    if not isinstance(tool_name, str) or tool_name not in TOOL_REGISTRY:
        classification = classify_attack(
            tool_name,
            arguments,
            "Unknown or prohibited tool.",
        )

        return blocked_response(
            classification["category"],
            classification["explanation"],
            classification["severity"],
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
        )

    expected_task = TASK_MAPPING.get(tool_name)
    if task is None:
        task = expected_task

    # Check intent.
    intent_decision = check_intent(task, tool_name, arguments)

    if intent_decision["decision"] != "ALLOW":
        return blocked_response(
            intent_decision.get("category", "intent_violation"),
            intent_decision.get("reason", "Intent check failed."),
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
        )

    # Enforce policy even when an approval exists.
    policy_decision = authorize_tool(tool_name, arguments)

    if policy_decision["decision"] != "ALLOW":
        reason = policy_decision.get(
            "reason",
            "The tool request was denied by policy.",
        )
        classification = classify_attack(tool_name, arguments, reason)

        return blocked_response(
            classification["category"],
            reason,
            classification["severity"],
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
        )

    # Check information-flow rules before reading a report.
    if tool_name == "read_report":
        filename = arguments.get("filename", "")
        label = REPORT_LABELS.get(filename, "confidential")
        data_id = f"report:{filename}"

        label_result = FLOW_TRACKER.label_data(data_id, label)

        if label_result["decision"] != "ALLOW":
            return blocked_response(
                "information_flow",
                label_result["reason"],
                "high",
                tool_name=tool_name,
                arguments=arguments,
                session_id=session_id,
            )

        flow_decision = FLOW_TRACKER.check_flow(
            data_id,
            destination="local",
            maximum_label="internal",
        )

        if flow_decision["decision"] != "ALLOW":
            return blocked_response(
                "information_flow",
                flow_decision["reason"],
                "high",
                tool_name=tool_name,
                arguments=arguments,
                session_id=session_id,
            )

    # Pause a valid request if human approval is required.
    if approval_request_id is None and require_approval:
        return pending_approval_response(
            tool_name=tool_name,
            arguments=arguments,
            reason="Human approval is required before tool execution.",
            session_id=session_id,
        )

    # Validate and consume approval for the exact requested action.
    if approval_request_id is not None:
        approval = APPROVAL_MANAGER.consume_approved_request(
            request_id=approval_request_id,
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
        )

        if approval["decision"] != "ALLOW":
            return blocked_response(
                "human_approval",
                approval["reason"],
                "high",
                tool_name=tool_name,
                arguments=arguments,
                session_id=session_id,
            )

    # Execute only after the required checks have passed.
    try:
        result = TOOL_REGISTRY[tool_name](**arguments)

    except Exception:
        record_decision(
            tool_name=tool_name,
            decision="ERROR",
            reason="Tool execution failed.",
            execution_attempted=True,
            session_id=session_id,
        )

        response = {
            "decision": "ERROR",
            "category": "execution_error",
            "severity": "medium",
            "reason": "Tool execution failed.",
            "executed": True,
            "result": None,
        }
        return add_risk(response, tool_name, arguments)

    if isinstance(result, dict) and "error" in result:
        record_decision(
            tool_name=tool_name,
            decision="ERROR",
            reason=result["error"],
            execution_attempted=True,
            session_id=session_id,
        )

        response = {
            "decision": "ERROR",
            "category": "execution_error",
            "severity": "medium",
            "reason": result["error"],
            "executed": True,
            "result": result,
        }
        return add_risk(response, tool_name, arguments)

    record_decision(
        tool_name=tool_name,
        decision="ALLOW",
        reason=(
            "Intent, policy, information-flow, and applicable "
            "approval checks passed."
        ),
        execution_attempted=True,
        session_id=session_id,
    )

    # Remember successful reads for attack-sequence detection.
    if tool_name == "read_report":
        ATTACK_SEQUENCE_DETECTOR.observe(
            {
                "tool_name": "read_report",
                "decision": "ALLOW",
                "execution_attempted": True,
            },
            session_id=session_id,
        )

    response = {
        "decision": "ALLOW",
        "category": "none",
        "severity": "low",
        "reason": (
            "Intent, policy, information-flow, and applicable "
            "approval checks passed."
        ),
        "executed": True,
        "result": result,
    }

    return add_risk(response, tool_name, arguments)
