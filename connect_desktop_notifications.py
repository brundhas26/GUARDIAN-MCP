from pathlib import Path

runtime_path = Path("app/gateway/runtime.py")
source = runtime_path.read_text(encoding="utf-8")

import_line = "from app.security.human_approval import HumanApprovalManager"
notification_import = (
    "from app.security.desktop_notifications import notify_security_block"
)

if notification_import not in source:
    if import_line not in source:
        print("ERROR: Expected import location was not found.")
        print("No changes made.")
        raise SystemExit(1)

    source = source.replace(
        import_line,
        import_line + "\n" + notification_import,
        1,
    )

anchor = '''    record_decision(
        tool_name=str(tool_name),
        decision="BLOCK",
        reason=f"{category}: {reason}",
        execution_attempted=False,
        session_id=session_id,
    )

    response = {'''

replacement = '''    record_decision(
        tool_name=str(tool_name),
        decision="BLOCK",
        reason=f"{category}: {reason}",
        execution_attempted=False,
        session_id=session_id,
    )

    # Notify the user when a request is blocked.
    notify_security_block(
        str(tool_name),
        f"{category}: {reason}",
    )

    response = {'''

if "notify_security_block(" not in source:
    if anchor not in source:
        print("ERROR: Expected blocking function was not found.")
        print("No changes made to the gateway file.")
        raise SystemExit(1)

    source = source.replace(anchor, replacement, 1)

runtime_path.write_text(source, encoding="utf-8")
print("Desktop notifications connected to blocked requests.")
print("Existing gateway security checks have been preserved.")