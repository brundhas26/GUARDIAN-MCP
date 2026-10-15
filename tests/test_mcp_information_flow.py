
"""Pytest checks for GUARDIAN MCP information-flow protection."""

from app.security.information_flow import InformationFlowTracker


def test_approved_internal_report_is_accessible():
    """Appropriately labelled internal data should be permitted."""
    tracker = InformationFlowTracker()
    tracker.label_data("summary-report", "internal")

    result = tracker.check_flow(
        "summary-report",
        destination="local",
        maximum_label="internal",
    )

    assert result["decision"] == "ALLOW"


def test_confidential_data_is_blocked_from_internal_destination():
    """Confidential data must not flow to an internal-only destination."""
    tracker = InformationFlowTracker()
    tracker.label_data("confidential-report", "confidential")

    result = tracker.check_flow(
        "confidential-report",
        destination="local",
        maximum_label="internal",
    )

    assert result["decision"] == "BLOCK"
    assert result["reason"] == (
        "Data sensitivity exceeds the destination limit."
    )


def test_unlabelled_data_is_blocked():
    """Data without a sensitivity label must be blocked."""
    tracker = InformationFlowTracker()

    result = tracker.check_flow(
        "unknown-report",
        destination="local",
        maximum_label="internal",
    )

    assert result["decision"] == "BLOCK"
    assert result["reason"] == "Data has no recorded sensitivity label."


def test_unapproved_destination_is_blocked():
    """Data must not flow to an unapproved destination."""
    tracker = InformationFlowTracker()
    tracker.label_data("public-report", "public")

    result = tracker.check_flow(
        "public-report",
        destination="external",
        maximum_label="internal",
    )

    assert result["decision"] == "BLOCK"
    assert result["reason"] == "Destination is not approved."
