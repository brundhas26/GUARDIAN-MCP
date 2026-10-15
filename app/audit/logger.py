
import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUDIT_FILE = PROJECT_ROOT / "data" / "audit" / "events.jsonl"

_lock = threading.Lock()
GENESIS_HASH = "0" * 64


def _calculate_hash(event: dict) -> str:
    """Calculate a deterministic SHA-256 hash for an audit event."""
    payload = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _last_hash() -> str:
    """Return the previous event hash, or the genesis hash for an empty log."""
    if not AUDIT_FILE.exists():
        return GENESIS_HASH

    last_line = None

    with AUDIT_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                last_line = line

    if last_line is None:
        return GENESIS_HASH

    previous_event = json.loads(last_line)
    return previous_event["event_hash"]


def record_decision(
    tool_name: str,
    decision: str,
    reason: str,
    execution_attempted: bool = False,
    session_id: str | None = None,
) -> dict:
    """Append a security decision to a hash-chained audit log."""
    if decision not in {"ALLOW", "BLOCK", "ERROR"}:
        raise ValueError("Unsupported audit decision.")

    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("A valid tool name is required.")

    if not isinstance(reason, str):
        raise ValueError("The reason must be text.")

    if not isinstance(execution_attempted, bool):
        raise ValueError("execution_attempted must be a boolean.")

    if session_id is not None and (
        not isinstance(session_id, str) or not session_id.strip()
    ):
        raise ValueError("session_id must be a non-empty string or None.")

    with _lock:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_name": tool_name,
            "decision": decision,
            "reason": reason,
            "execution_attempted": execution_attempted,
            "session_id": session_id,
            "previous_hash": _last_hash(),
        }

        event["event_hash"] = _calculate_hash(event)

        with AUDIT_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")

        return event


def verify_audit_log() -> bool:
    """Verify the hash chain and event contents in the audit log."""
    if not AUDIT_FILE.exists():
        return True

    expected_previous_hash = GENESIS_HASH

    try:
        with AUDIT_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                event = json.loads(line)

                if not isinstance(event, dict):
                    return False

                if event.get("previous_hash") != expected_previous_hash:
                    return False

                stored_hash = event.get("event_hash")
                unhashed_event = {
                    key: value
                    for key, value in event.items()
                    if key != "event_hash"
                }

                if stored_hash != _calculate_hash(unhashed_event):
                    return False

                expected_previous_hash = stored_hash

    except (OSError, ValueError, KeyError, TypeError):
        return False

    return True
