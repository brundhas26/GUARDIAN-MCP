
"""GUARDIAN MCP server with runtime security and sequence detection."""

from pathlib import Path

from mcp.server.mcpserver import MCPServer

from app.audit.logger import record_decision
from app.policy.engine import authorize_tool
from app.security.intent_guard import check_intent
from app.security.attack_classifier import classify_attack
from app.security.information_flow import InformationFlowTracker
from app.security.attack_sequence import AttackSequenceDetector


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = PROJECT_ROOT / "data" / "reports"

FLOW_TRACKER = InformationFlowTracker()
ATTACK_SEQUENCE_DETECTOR = AttackSequenceDetector()

REPORT_LABELS = {
    "public.txt": "public",
    "summary.txt": "internal",
}

server = MCPServer(
    name="guardian-protected-tools",
    instructions="Local tools protected by GUARDIAN MCP.",
)

TASK_MAPPING = {
    "read_report": "read_public_report",
    "calculate_total": "calculate",
}

# Sequence history is scoped to this server process.
MCP_SESSION_ID = "mcp-local-server"


def record_block(tool_name: str, category: str, reason: str) -> None:
    """Audit a blocked request and stop execution."""
    full_reason = f"{category}: {reason}"

    record_decision(
        tool_name=tool_name,
        decision="BLOCK",
        reason=full_reason,
        execution_attempted=False,
    )

    raise ValueError(f"GUARDIAN BLOCK: {full_reason}")


def guardian_check(tool_name: str, arguments: dict) -> None:
    """Check intent and policy before tool execution."""
    task = TASK_MAPPING.get(tool_name, "")

    intent_decision = check_intent(task, tool_name, arguments)

    if intent_decision["decision"] != "ALLOW":
        reason = intent_decision.get(
            "reason",
            "Intent check failed.",
        )
        classification = classify_attack(tool_name, arguments, reason)

        record_block(
            tool_name,
            classification["category"],
            reason,
        )

    policy_decision = authorize_tool(tool_name, arguments)

    if policy_decision["decision"] != "ALLOW":
        reason = policy_decision.get(
            "reason",
            "The request was denied by policy.",
        )
        classification = classify_attack(tool_name, arguments, reason)

        record_block(
            tool_name,
            classification["category"],
            reason,
        )


def check_report_information_flow(filename: str) -> None:
    """Check report sensitivity before accessing its contents."""
    label = REPORT_LABELS.get(filename, "confidential")
    data_id = f"report:{filename}"

    label_result = FLOW_TRACKER.label_data(data_id, label)

    if label_result["decision"] != "ALLOW":
        record_block(
            "read_report",
            "information_flow",
            label_result["reason"],
        )

    flow_decision = FLOW_TRACKER.check_flow(
        data_id,
        destination="local",
        maximum_label="internal",
    )

    if flow_decision["decision"] != "ALLOW":
        record_block(
            "read_report",
            "information_flow",
            flow_decision["reason"],
        )


def observe_sequence(
    tool_name: str,
    decision: str,
    execution_attempted: bool,
) -> None:
    """Record an event for multi-step attack detection."""
    ATTACK_SEQUENCE_DETECTOR.observe(
        {
            "tool_name": tool_name,
            "decision": decision,
            "execution_attempted": execution_attempted,
        },
        session_id=MCP_SESSION_ID,
    )


def check_external_send_sequence() -> None:
    """Block an external send following an approved report read."""
    sequence_decision = ATTACK_SEQUENCE_DETECTOR.observe(
        {
            "tool_name": "send_external",
            "decision": "BLOCK",
            "execution_attempted": False,
        },
        session_id=MCP_SESSION_ID,
    )

    if sequence_decision["decision"] == "BLOCK":
        record_block(
            "send_external",
            sequence_decision["category"],
            sequence_decision["reason"],
        )


@server.tool()
def read_report(filename: str) -> str:
    """Read an approved report through GUARDIAN."""
    arguments = {"filename": filename}

    guardian_check("read_report", arguments)
    check_report_information_flow(filename)

    report_path = REPORTS_DIR / filename

    if not report_path.is_file():
        record_block(
            "read_report",
            "execution_error",
            "Report does not exist.",
        )

    try:
        content = report_path.read_text(encoding="utf-8")
    except OSError:
        record_block(
            "read_report",
            "execution_error",
            "Report could not be read.",
        )

    record_decision(
        tool_name="read_report",
        decision="ALLOW",
        reason="Intent, policy, and information-flow checks passed.",
        execution_attempted=True,
    )

    observe_sequence(
        tool_name="read_report",
        decision="ALLOW",
        execution_attempted=True,
    )

    return content


@server.tool()
def calculate_total(numbers: list[float]) -> float:
    """Calculate a sum through GUARDIAN."""
    arguments = {"numbers": numbers}

    guardian_check("calculate_total", arguments)

    try:
        result = sum(numbers)
    except (TypeError, ValueError):
        record_block(
            "calculate_total",
            "invalid_arguments",
            "The numbers must contain valid numeric values.",
        )

    record_decision(
        tool_name="calculate_total",
        decision="ALLOW",
        reason="Intent and policy checks passed.",
        execution_attempted=True,
    )

    observe_sequence(
        tool_name="calculate_total",
        decision="ALLOW",
        execution_attempted=True,
    )

    return result


@server.tool()
def send_external(content: str) -> str:
    """Simulate an external send request without transmitting data."""
    # Check the sequence first so a prior report read can trigger
    # the multi-step attack detector.
    check_external_send_sequence()

    # Even if no suspicious sequence is detected, normal security
    # checks still apply. External sending remains denied by policy.
    guardian_check(
        "send_external",
        {"content": content},
    )

    # Defensive fallback: this tool must never transmit anything.
    record_block(
        "send_external",
        "policy_denied",
        "External sending is disabled by GUARDIAN policy.",
    )


if __name__ == "__main__":
    server.run(transport="stdio")
