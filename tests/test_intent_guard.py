
from app.security.intent_guard import check_intent


def test_matching_tool_is_allowed():
    result = check_intent(
        "calculate",
        "calculate_total",
        {"numbers": [10, 20, 30]},
    )

    assert result["decision"] == "ALLOW"


def test_tool_outside_task_scope_is_blocked():
    result = check_intent(
        "calculate",
        "read_report",
        {"filename": "public.txt"},
    )

    assert result["decision"] == "BLOCK"
    assert result["category"] == "intent_violation"


def test_unknown_task_is_blocked():
    result = check_intent(
        "unknown_task",
        "calculate_total",
        {"numbers": [10, 20, 30]},
    )

    assert result["decision"] == "BLOCK"


def test_missing_task_is_blocked():
    result = check_intent(
        "",
        "calculate_total",
        {"numbers": [10, 20, 30]},
    )

    assert result["decision"] == "BLOCK"
