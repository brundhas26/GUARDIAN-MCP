from winotify import Notification, audio

notification = Notification(
    app_id="GUARDIAN MCP",
    title="Security Threat Blocked!",
    msg="GUARDIAN MCP detected a suspicious action. The request was blocked.",
    duration="long"
)

notification.set_audio(audio.Default, loop=False)
notification.show()

print("Desktop notification sent successfully.")