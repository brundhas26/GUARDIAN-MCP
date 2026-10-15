import pytest

from app.security.attack_classifier import classify_attack


def test_path_traversal_is_classified():
    result = classify_attack(
        "read_report",
        {"filename": "../../secret.txt"},
    )

    assert result["category"] == "path_traversal"
    assert result["severity"] == "high"


def test_prohibited_tool_is_classified():
    result = classify_attack("delete_file", {})

    assert result["category"] == "unauthorized_tool"
    assert result["severity"] == "high"


def test_invalid_calculation_is_classified():
    result = classify_attack(
        "calculate_total",
        {"numbers": "not-a-list"},
    )

    assert result["category"] == "invalid_arguments"
    assert result["severity"] == "medium"


def test_non_numeric_calculation_is_classified():
    result = classify_attack(
        "calculate_total",
        {"numbers": [10, "hello", 30]},
    )

    assert result["category"] == "invalid_arguments"


def test_unknown_pattern_is_unclassified():
    result = classify_attack("read_report", {"filename": "public.txt"})

    assert result["category"] == "unclassified"
    assert result["severity"] == "low"
