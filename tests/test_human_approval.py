
import pytest

from app.security.human_approval import HumanApprovalManager


@pytest.fixture
def manager():
    return HumanApprovalManager()


def create_request(manager):
    return manager.create_request(
        tool_name="send_external",
        arguments={"destination": "external"},
        reason="Sensitive action requires review",
        risk_score=90,
        risk_level="HIGH",
        session_id="test-session",
    )


def test_new_request_is_pending(manager):
    request = create_request(manager)

    assert request["status"] == "PENDING"
    assert len(manager.list_pending()) == 1


def test_approval_records_reviewer(manager):
    request = create_request(manager)

    result = manager.approve(
        request["request_id"],
        "security_reviewer",
        "Reviewed the request",
    )

    assert result["status"] == "APPROVED"
    assert result["reviewer"] == "security_reviewer"
    assert len(manager.list_pending()) == 0


def test_rejection_records_reviewer(manager):
    request = create_request(manager)

    result = manager.reject(
        request["request_id"],
        "security_reviewer",
        "Destination is untrusted",
    )

    assert result["status"] == "REJECTED"
    assert result["reviewer"] == "security_reviewer"
    assert len(manager.list_pending()) == 0


def test_request_cannot_be_reviewed_twice(manager):
    request = create_request(manager)
    manager.approve(request["request_id"], "reviewer")

    with pytest.raises(ValueError):
        manager.reject(request["request_id"], "reviewer")


def test_unknown_request_cannot_be_approved(manager):
    with pytest.raises(KeyError):
        manager.approve("unknown-request", "reviewer")


def test_invalid_reviewer_is_rejected(manager):
    request = create_request(manager)

    with pytest.raises(ValueError):
        manager.approve(request["request_id"], "")


def test_request_arguments_are_copied(manager):
    arguments = {"destination": "external"}

    request = manager.create_request(
        "send_external",
        arguments,
        "Requires review",
    )
    arguments["destination"] = "changed"

    assert request["arguments"]["destination"] == "external"


def test_approval_does_not_execute_a_tool(manager):
    request = create_request(manager)
    result = manager.approve(request["request_id"], "reviewer")

    # The approval manager records a decision; it has no tool executor.
    assert result["status"] == "APPROVED"
    assert "executed" not in result
