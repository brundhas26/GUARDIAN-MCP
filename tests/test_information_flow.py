
from app.security.information_flow import InformationFlowTracker


def test_confidential_data_is_labelled():
    tracker = InformationFlowTracker()

    result = tracker.label_data("report1", "confidential")

    assert result["decision"] == "ALLOW"
    assert result["label"] == "confidential"


def test_confidential_data_cannot_flow_to_internal_destination():
    tracker = InformationFlowTracker()
    tracker.label_data("report1", "confidential")

    result = tracker.check_flow("report1", "local", "internal")

    assert result["decision"] == "BLOCK"


def test_unlabelled_data_is_blocked():
    tracker = InformationFlowTracker()

    result = tracker.check_flow("unknown_report", "local")

    assert result["decision"] == "BLOCK"


def test_public_data_can_flow_to_internal_destination():
    tracker = InformationFlowTracker()
    tracker.label_data("public_report", "public")

    result = tracker.check_flow("public_report", "local", "internal")

    assert result["decision"] == "ALLOW"


def test_unapproved_destination_is_blocked():
    tracker = InformationFlowTracker()
    tracker.label_data("report1", "public")

    result = tracker.check_flow("report1", "external", "restricted")

    assert result["decision"] == "BLOCK"
