
"""IntentGuard: explicit task-scope checks for GUARDIAN MCP."""

from typing import Any


# Explicit mapping between declared task types and permitted tools.
TASK_TOOL_RULES = {
    "calculate": {"calculate_total"},
    "read_public_report": {"read_report"},
}


def check_intent(
    task: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """
    Check whether a tool request matches the declared task.

    This is an explicit rule-based check, not a general-purpose
    natural-language intent detector.
    """
    if not isinstance(task, str) or not task.strip():
        return {
            "decision": "BLOCK",
            "category": "intent_violation",
            "reason": "A declared task is required.",
        }

    if not isinstance(tool_name, str) or not tool_name.strip():
        return {
            "decision": "BLOCK",
            "category": "intent_violation",
            "reason": "A valid tool name is required.",
        }

    if not isinstance(arguments, dict):
        return {
            "decision": "BLOCK",
            "category": "intent_violation",
            "reason": "Tool arguments must be a dictionary.",
        }

    allowed_tools = TASK_TOOL_RULES.get(task)

    if allowed_tools is None:
        return {
            "decision": "BLOCK",
            "category": "intent_violation",
            "reason": "The declared task is not recognized.",
        }

    if tool_name not in allowed_tools:
        return {
            "decision": "BLOCK",
            "category": "intent_violation",
            "reason": (
                f"Tool '{tool_name}' is outside the declared "
                f"task scope '{task}'."
            ),
        }

    return {
        "decision": "ALLOW",
        "category": "none",
        "reason": "The requested tool matches the declared task.",
    }
