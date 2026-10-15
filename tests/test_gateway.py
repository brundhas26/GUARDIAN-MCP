
from app.gateway.runtime import execute_tool


def test_approved_report_executes():
    result = execute_tool(
        "read_report",
        {"filename": "public.txt"},
    )

    assert result["decision"] == "ALLOW"
    assert result["executed"] is True
    assert "harmless public report" in result["result"]["content"]


def test_secret_report_never_executes():
    result = execute_tool(
        "read_report",
        {"filename": "secret.txt"},
    )

    assert result["decision"] == "BLOCK"
    assert result["executed"] is False
    assert result["result"] is None


def test_path_traversal_never_executes():
    result = execute_tool(
        "read_report",
        {"filename": "../../secret.txt"},
    )

    assert result["decision"] == "BLOCK"
    assert result["executed"] is False


def test_approved_calculation_executes():
    result = execute_tool(
        "calculate_total",
        {"numbers": [10, 20, 30]},
    )

    assert result["decision"] == "ALLOW"
    assert result["executed"] is True
    assert result["result"]["total"] == 60


def test_prohibited_tool_never_executes():
    result = execute_tool(
        "send_external",
        {"destination": "example.invalid"},
    )

    assert result["decision"] == "BLOCK"
    assert result["executed"] is False
