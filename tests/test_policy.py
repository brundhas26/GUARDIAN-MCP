
from app.policy.engine import authorize_tool


def test_allowed_public_report():
    result = authorize_tool(
        "read_report",
        {"filename": "public.txt"},
    )
    assert result["decision"] == "ALLOW"


def test_unapproved_report_is_blocked():
    result = authorize_tool(
        "read_report",
        {"filename": "secret.txt"},
    )
    assert result["decision"] == "BLOCK"


def test_path_traversal_is_blocked():
    result = authorize_tool(
        "read_report",
        {"filename": "../../secret.txt"},
    )
    assert result["decision"] == "BLOCK"


def test_external_sending_is_blocked():
    result = authorize_tool(
        "send_external",
        {"destination": "example.invalid"},
    )
    assert result["decision"] == "BLOCK"


def test_unknown_tool_is_blocked():
    result = authorize_tool(
        "run_unknown_command",
        {},
    )
    assert result["decision"] == "BLOCK"


def test_valid_calculation_is_allowed():
    result = authorize_tool(
        "calculate_total",
        {"numbers": [10, 20, 30]},
    )
    assert result["decision"] == "ALLOW"


def test_invalid_calculation_is_blocked():
    result = authorize_tool(
        "calculate_total",
        {"numbers": ["10", "20"]},
    )
    assert result["decision"] == "BLOCK"
