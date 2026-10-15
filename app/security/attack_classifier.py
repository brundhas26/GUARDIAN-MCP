"""Rule-based attack classification for GUARDIAN MCP."""

from typing import Any


def classify_attack(
    tool_name: str,
    arguments: dict[str, Any],
    reason: str = "",
) -> dict[str, str]:
    """Identify common suspicious tool-call patterns."""

    combined_text = f"{tool_name} {arguments} {reason}".lower()

    # 1. Detect possible path traversal attempts.
    path_patterns = (
        "../",
        "..\\",
        "%2e%2e",
        "/etc/passwd",
        "c:\\windows\\",
    )

    if any(pattern in combined_text for pattern in path_patterns):
        return {
            "category": "path_traversal",
            "severity": "high",
            "explanation": "Possible attempt to access files outside the permitted directory.",
        }

    # 2. Detect prohibited tools.
    if tool_name in {"send_external", "delete_file"}:
        return {
            "category": "unauthorized_tool",
            "severity": "high",
            "explanation": "The requested tool is prohibited by the configured policy.",
        }

    # 3. Detect invalid calculation arguments.
    if tool_name == "calculate_total":
        numbers = arguments.get("numbers")

        if not isinstance(numbers, list) or not numbers:
            return {
                "category": "invalid_arguments",
                "severity": "medium",
                "explanation": "The calculation requires a non-empty list of numbers.",
            }

        if any(
            isinstance(number, bool)
            or not isinstance(number, (int, float))
            for number in numbers
        ):
            return {
                "category": "invalid_arguments",
                "severity": "medium",
                "explanation": "The calculation contains a non-numeric value.",
            }

    # 4. Categorize other policy rejections.
    if reason and any(
        phrase in reason.lower()
        for phrase in ("not permitted", "not allowed", "not authorized")
    ):
        return {
            "category": "policy_violation",
            "severity": "medium",
            "explanation": "The request appears to violate a security policy.",
        }

    # 5. No recognized pattern.
    return {
        "category": "unclassified",
        "severity": "low",
        "explanation": "No known attack pattern was identified by this basic classifier.",
    }
