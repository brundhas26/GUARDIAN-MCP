from unittest.mock import patch

import pytest

from app.mcp_server import local_server


def test_confidential_report_is_blocked_before_file_read():
    with patch.dict(local_server.REPORT_LABELS, {"summary.txt": "confidential"}):
        with patch.object(local_server, "record_decision") as audit, patch.object(
            local_server.Path, "read_text", side_effect=AssertionError("File must not be read")
        ):
            with pytest.raises(ValueError, match="GUARDIAN BLOCK"):
                local_server.read_report("summary.txt")

            assert audit.call_args.kwargs["decision"] == "BLOCK"
            assert audit.call_args.kwargs["execution_attempted"] is False

