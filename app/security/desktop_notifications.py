"""Windows desktop notifications for GUARDIAN MCP."""

import os

try:
    from winotify import Notification, audio
except ImportError:
    Notification = None
    audio = None


def notify_security_block(tool_name: str, reason: str) -> None:
    """Show a notification when GUARDIAN MCP blocks a tool request."""

    if os.name != "nt" or Notification is None:
        print("Notification unavailable: Windows or winotify is missing.")
        return

    try:
        notification = Notification(
            app_id="GUARDIAN MCP",
            title="Security Threat Blocked!",
            msg=(
                f"Blocked tool: {str(tool_name)[:80]}\n"
                f"Reason: {' '.join(str(reason).split())[:160]}"
            ),
            duration="long",
        )

        if audio is not None:
            notification.set_audio(audio.Default, loop=False)

        notification.show()
        print("Security notification sent.")

    except Exception as error:
        print(f"Could not display notification: {error}")