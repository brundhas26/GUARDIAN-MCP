
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_FILE = PROJECT_ROOT / "config" / "policy.yaml"


def load_policy():
    """Load the security policy from the YAML configuration file."""
    with POLICY_FILE.open("r", encoding="utf-8") as file:
        policy = yaml.safe_load(file)

    if not isinstance(policy, dict):
        raise ValueError("Policy must be a YAML mapping.")

    if policy.get("default_effect") != "deny":
        raise ValueError("The policy must use default-deny behavior.")

    if not isinstance(policy.get("tools"), dict):
        raise ValueError("Policy must contain a tools mapping.")

    for tool_name, rule in policy["tools"].items():
        if not isinstance(rule, dict):
            raise ValueError(f"Invalid rule for tool: {tool_name}")

        if rule.get("effect") not in {"allow", "deny"}:
            raise ValueError(f"Invalid effect for tool: {tool_name}")

    return policy


def authorize_tool(tool_name, arguments):
    """Return an authorization decision without executing the tool."""

    if not isinstance(tool_name, str) or not tool_name:
        return {
            "decision": "BLOCK",
            "reason": "Invalid tool name",
        }

    if not isinstance(arguments, dict):
        return {
            "decision": "BLOCK",
            "reason": "Tool arguments must be a dictionary",
        }

    try:
        policy = load_policy()
    except (OSError, ValueError, yaml.YAMLError):
        return {
            "decision": "BLOCK",
            "reason": "Security policy could not be loaded safely",
        }

    rule = policy["tools"].get(tool_name)

    if rule is None:
        return {
            "decision": "BLOCK",
            "reason": "Tool is not explicitly permitted",
        }

    if rule["effect"] == "deny":
        return {
            "decision": "BLOCK",
            "reason": "Tool is prohibited by policy",
        }

    if tool_name == "read_report":
        filename = arguments.get("filename")

        if not isinstance(filename, str):
            return {
                "decision": "BLOCK",
                "reason": "A valid filename is required",
            }

        if filename not in rule.get("allowed_filenames", []):
            return {
                "decision": "BLOCK",
                "reason": "Filename is not permitted",
            }

        if Path(filename).name != filename or "/" in filename or "\\" in filename:
            return {
                "decision": "BLOCK",
                "reason": "Path traversal or directory access is prohibited",
            }

    elif tool_name == "calculate_total":
        numbers = arguments.get("numbers")

        if not isinstance(numbers, list) or not numbers:
            return {
                "decision": "BLOCK",
                "reason": "A non-empty numbers list is required",
            }

        if any(
            isinstance(number, bool)
            or not isinstance(number, (int, float))
            for number in numbers
        ):
            return {
                "decision": "BLOCK",
                "reason": "Only numeric values are permitted",
            }

        if len(numbers) > 100:
            return {
                "decision": "BLOCK",
                "reason": "Too many numbers",
            }

        if any(abs(number) > 1_000_000_000 for number in numbers):
            return {
                "decision": "BLOCK",
                "reason": "A number exceeds the permitted limit",
            }

    return {
        "decision": "ALLOW",
        "reason": "Tool and arguments are permitted by policy",
    }
