from pathlib import Path

dashboard_path = Path("dashboard/app.py")
source = dashboard_path.read_text(encoding="utf-8")

anchor = 'df["decision"] = df["decision"].astype(str).str.upper()'

if "SECURITY ALERTS - USER NOTIFICATIONS" in source:
    print("Security Alerts section already exists. No changes made.")
    raise SystemExit(0)

if anchor not in source:
    print("ERROR: Expected dashboard location was not found.")
    print("No changes made. The dashboard is unchanged.")
    raise SystemExit(1)

notification_code = r'''

# --------------------------------------------------
# SECURITY ALERTS - USER NOTIFICATIONS
# --------------------------------------------------

st.divider()
st.header("Security Alerts")
st.caption(
    "Important security decisions recorded by the GUARDIAN MCP gateway."
)

alert_events = [
    event for event in events
    if str(event.get("decision", "")).upper() in {"BLOCK", "ERROR"}
]

if not alert_events:
    st.success("No blocked or error events are recorded in the audit log.")
else:
    st.error(
        f"{len(alert_events)} security event(s) require attention."
    )

    for event in reversed(alert_events[-10:]):
        decision = str(event.get("decision", "UNKNOWN")).upper()
        tool_name = str(event.get("tool_name", "Unknown tool"))
        reason = str(event.get("reason") or "No reason recorded")
        timestamp = str(event.get("timestamp", "Timestamp unavailable"))
        event_id = str(event.get("event_id", "ID unavailable"))
        attempted = event.get("execution_attempted", None)

        with st.container(border=True):
            st.markdown(f"### {decision}: `{tool_name}`")

            if decision == "BLOCK":
                st.warning("GUARDIAN MCP blocked this tool request.")
            else:
                st.error("A tool execution error was recorded.")

            st.write(f"**Reason:** {reason}")
            st.write(f"**Time (UTC):** {timestamp}")

            if attempted is True:
                st.write("**Execution attempted:** Yes")
            elif attempted is False:
                st.write("**Execution attempted:** No")
            else:
                st.write("**Execution attempted:** Not recorded")

            st.caption(f"Audit event ID: {event_id}")

            with st.expander("What should I do?"):
                st.write(
                    "Review the reason and related events before retrying. "
                    "If this action was unexpected, investigate the session "
                    "in the Attack Investigation Timeline."
                )

'''

updated = source.replace(anchor, anchor + notification_code, 1)
dashboard_path.write_text(updated, encoding="utf-8")

print("Security Alerts section added successfully.")
print("Existing dashboard features have been preserved.")