
"""Risk scoring module for GUARDIAN MCP."""

from typing import Any


def calculate_risk(
    tool_name: str,
    arguments: dict[str, Any],
    decision: str = "ALLOW",
    data_sensitivity: str = "public",
    suspicious_sequence: bool = False,
) -> dict[str, Any]:
    """Calculate an explainable risk score from 0 to 100."""

    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name must be non-empty text.")

    if not isinstance(arguments, dict):
        raise ValueError("arguments must be a dictionary.")

    if decision not in {"ALLOW", "BLOCK"}:
        raise ValueError("decision must be ALLOW or BLOCK.")

    sensitivity_scores = {
        "public": 0,
        "internal": 15,
        "confidential": 30,
        "restricted": 40,
    }

    if data_sensitivity not in sensitivity_scores:
        raise ValueError("Unknown data sensitivity level.")

    score = 0
    reasons = []

    # Blocked requests are riskier than ordinary permitted requests.
    if decision == "BLOCK":
        score += 30
        reasons.append("Request was blocked by a security control.")

    # Tool-specific risk.
    if tool_name == "send_external":
        score += 25
        reasons.append("External-send tool carries data-exfiltration risk.")
    elif tool_name not in {"read_report", "calculate_total"}:
        score += 20
        reasons.append("Tool is not in the recognized safe-tool list.")

    # Sensitive data increases potential impact.
    sensitivity_score = sensitivity_scores[data_sensitivity]
    if sensitivity_score:
        score += sensitivity_score
        reasons.append(
            f"Data sensitivity is {data_sensitivity}."
        )

    # Suspicious multi-step activity is a strong signal.
    if suspicious_sequence:
        score += 35
        reasons.append("Suspicious multi-step activity was detected.")

    # Basic argument-level warning for path traversal patterns.
    filename = arguments.get("filename")
    if isinstance(filename, str) and (
        ".." in filename or "/" in filename or "\\" in filename
    ):
        score += 25
        reasons.append("Filename contains a possible path-traversal pattern.")

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons.append("No configured risk indicators were detected.")

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
    }
