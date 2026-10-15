
import pytest

from app.security.risk_scoring import calculate_risk


def test_safe_calculation_has_low_risk():
    result = calculate_risk(
        tool_name="calculate_total",
        arguments={"numbers": [10, 20]},
        decision="ALLOW",
        data_sensitivity="public",
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"


def test_blocked_external_send_has_medium_risk():
    result = calculate_risk(
        tool_name="send_external",
        arguments={"content": "test"},
        decision="BLOCK",
        data_sensitivity="public",
    )

    assert result["risk_score"] == 55
    assert result["risk_level"] == "MEDIUM"


def test_suspicious_sequence_has_high_risk():
    result = calculate_risk(
        tool_name="send_external",
        arguments={"content": "test"},
        decision="BLOCK",
        data_sensitivity="internal",
        suspicious_sequence=True,
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "HIGH"


def test_path_traversal_increases_risk():
    result = calculate_risk(
        tool_name="read_report",
        arguments={"filename": "../../secret.txt"},
    )

    assert result["risk_score"] == 25
    assert result["risk_level"] == "LOW"
    assert any("path-traversal" in reason for reason in result["reasons"])


def test_unknown_sensitivity_is_rejected():
    with pytest.raises(ValueError, match="Unknown data sensitivity"):
        calculate_risk(
            tool_name="read_report",
            arguments={"filename": "public.txt"},
            data_sensitivity="unknown",
        )


def test_risk_score_never_exceeds_100():
    result = calculate_risk(
        tool_name="send_external",
        arguments={"filename": "../../secret.txt"},
        decision="BLOCK",
        data_sensitivity="restricted",
        suspicious_sequence=True,
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "HIGH"
