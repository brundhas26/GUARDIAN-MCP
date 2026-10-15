
import importlib.util
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st


# --------------------------------------------------
# PROJECT SETUP
# --------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[1]
APP_DIR = ROOT_DIR / "app"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Ensure the project's app package is loaded correctly.
existing_app = sys.modules.get("app")

if existing_app is not None and not hasattr(existing_app, "__path__"):
    del sys.modules["app"]

if "app" not in sys.modules:
    package_init = APP_DIR / "__init__.py"

    package_spec = importlib.util.spec_from_file_location(
        "app",
        package_init,
        submodule_search_locations=[str(APP_DIR)],
    )

    if package_spec is None or package_spec.loader is None:
        raise ImportError(f"Cannot load application package: {APP_DIR}")

    package_module = importlib.util.module_from_spec(package_spec)
    sys.modules["app"] = package_module
    package_spec.loader.exec_module(package_module)

from app.audit.logger import AUDIT_FILE, verify_audit_log
from app.security.attack_trace import trace_attacks
from app.security.risk_scoring import calculate_risk
from app.gateway.runtime import execute_tool, APPROVAL_MANAGER


st.set_page_config(
    page_title="GUARDIAN MCP | Security Center",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ GUARDIAN MCP")
st.subheader("Runtime Security Center")
st.caption(
    "A clear view of tool access, blocked actions, incident risk, and audit integrity."
)

# Subtle styling: restrained colors and spacing, keeping the native Streamlit UI.
st.markdown(
    """
    <style>
    .block-container {padding-top: 1.8rem; padding-bottom: 2.5rem; max-width: 1450px;}
    div[data-testid="stMetric"] {
        background: rgba(120, 130, 150, 0.07);
        border: 1px solid rgba(120, 130, 150, 0.22);
        padding: 14px 16px;
        border-radius: 10px;
    }
    div[data-testid="stMetricLabel"] p {font-size: 0.9rem;}
    div[data-testid="stMetricValue"] {font-weight: 650;}
    div[data-testid="stVerticalBlockBorderWrapper"] {border-radius: 10px;}
    h1, h2, h3 {letter-spacing: -0.02em;}
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# AUDIT LOG LOADER
# --------------------------------------------------

@st.cache_data(ttl=3)
def load_events():
    events = []

    if not AUDIT_FILE.exists():
        return events

    with AUDIT_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if isinstance(event, dict):
                    events.append(event)

            except json.JSONDecodeError:
                continue

    return events


if st.button("🔄 Refresh security data"):
    load_events.clear()
    st.rerun()


# --------------------------------------------------
# HUMAN APPROVAL CONSOLE
# --------------------------------------------------

st.divider()
st.header("👤 Human Approval Console")

st.write(
    "Sensitive operations can be paused for human review. "
    "The tool must not execute until an authorized approval is recorded."
)

st.warning(
    "This console demonstrates approval using the dashboard's own "
    "Python process. Requests created by a separate MCP server process "
    "are not automatically shared with this in-memory approval manager."
)

with st.form("create_approval_request"):
    st.markdown("#### Create a test approval request")

    selected_report = st.selectbox(
        "Report to request",
        ["summary.txt", "public.txt"],
    )

    demo_session = st.text_input(
        "Session ID",
        value="dashboard-demo",
    )

    create_request = st.form_submit_button(
        "Submit for human approval"
    )

if create_request:
    if not demo_session.strip():
        st.error("Session ID cannot be empty.")
    else:
        request_arguments = {"filename": selected_report}

        try:
            response = execute_tool(
                "read_report",
                request_arguments,
                session_id=demo_session.strip(),
                require_approval=True,
            )

            st.session_state["approval_demo_response"] = response

            if response.get("decision") == "PENDING":
                st.session_state["approval_demo_request_id"] = (
                    response.get("approval_request_id")
                )
                st.session_state["approval_demo_arguments"] = (
                    request_arguments
                )
                st.session_state["approval_demo_session"] = (
                    demo_session.strip()
                )
                st.session_state["approval_demo_report"] = selected_report
                st.session_state["approval_demo_execution"] = None

            else:
                st.error(
                    "The gateway did not create a pending approval request."
                )
                st.json(response)

        except Exception as exc:
            st.error(f"Could not create approval request: {exc}")


# Show the most recent approval request.
request_id = st.session_state.get("approval_demo_request_id")

if request_id:
    st.markdown("#### Current approval request")

    st.code(request_id)

    st.write(
        "**Requested tool:** `read_report`  \n"
        f"**Requested report:** "
        f"`{st.session_state.get('approval_demo_report', 'unknown')}`  \n"
        f"**Session:** `{st.session_state.get('approval_demo_session', '')}`"
    )

    initial_response = st.session_state.get(
        "approval_demo_response", {}
    )

    st.write(
        "**Initial decision:** "
        f"`{initial_response.get('decision', 'UNKNOWN')}`"
    )

    st.write(
        "**Executed before approval:** "
        f"`{initial_response.get('executed', 'UNKNOWN')}`"
    )

    if initial_response.get("decision") == "PENDING":
        st.info(
            "The request is waiting for a human decision. "
            "No tool execution should occur at this stage."
        )

        pending_requests = APPROVAL_MANAGER.list_pending()

        matching_request = next(
            (
                item
                for item in pending_requests
                if item.get("request_id") == request_id
                or item.get("approval_request_id") == request_id
                or item.get("id") == request_id
            ),
            None,
        )

        if matching_request is not None:
            with st.expander("Review request details"):
                st.json(matching_request)

        reviewer = st.text_input(
            "Reviewer identifier",
            key="approval_reviewer",
            placeholder="Enter reviewer ID",
        )

        review_comment = st.text_input(
            "Review comment",
            key="approval_comment",
            placeholder="Reason for approval or rejection",
        )

        approve_col, reject_col = st.columns(2)

        with approve_col:
            approve_clicked = st.button(
                "✅ Approve and execute",
                use_container_width=True,
            )

        with reject_col:
            reject_clicked = st.button(
                "⛔ Reject request",
                use_container_width=True,
            )

        if approve_clicked:
            if not reviewer.strip():
                st.error("Enter a reviewer identifier first.")
            else:
                try:
                    review = APPROVAL_MANAGER.approve(
                        request_id,
                        reviewer.strip(),
                        review_comment.strip() or "Approved in dashboard",
                    )

                    st.session_state["approval_demo_review"] = review

                    if review.get("status") == "APPROVED":
                        final_response = execute_tool(
                            "read_report",
                            st.session_state["approval_demo_arguments"],
                            session_id=st.session_state[
                                "approval_demo_session"
                            ],
                            approval_request_id=request_id,
                        )

                        st.session_state["approval_demo_execution"] = (
                            final_response
                        )
                    else:
                        st.session_state["approval_demo_execution"] = None

                    st.rerun()

                except Exception as exc:
                    st.error(f"Approval failed: {exc}")

        if reject_clicked:
            if not reviewer.strip():
                st.error("Enter a reviewer identifier first.")
            else:
                try:
                    review = APPROVAL_MANAGER.reject(
                        request_id,
                        reviewer.strip(),
                        review_comment.strip() or "Rejected in dashboard",
                    )

                    st.session_state["approval_demo_review"] = review
                    st.session_state["approval_demo_execution"] = None
                    st.rerun()

                except Exception as exc:
                    st.error(f"Rejection failed: {exc}")

    review_result = st.session_state.get("approval_demo_review")

    if review_result:
        st.markdown("#### Human review result")
        st.json(review_result)

    final_result = st.session_state.get("approval_demo_execution")

    if final_result is not None:
        st.markdown("#### Gateway execution result")

        if final_result.get("decision") == "ALLOW":
            st.success("Approved request executed through the gateway.")
        else:
            st.warning(
                "The gateway did not allow execution. "
                "The approval does not override security policy."
            )

        st.write(
            f"**Final decision:** `{final_result.get('decision')}`"
        )
        st.write(
            f"**Tool executed:** `{final_result.get('executed')}`"
        )
        st.write(
            f"**Risk score:** "
            f"{final_result.get('risk_score', 'Not available')}/100"
        )

        if final_result.get("result") is not None:
            st.markdown("**Tool result**")
            st.json(final_result["result"])

    elif review_result and review_result.get("status") == "REJECTED":
        st.error("The request was rejected. The tool was not executed.")

    elif review_result and review_result.get("status") == "APPROVED":
        st.info(
            "The request was approved, but no successful execution "
            "result was recorded."
        )

else:
    st.info(
        "No approval demonstration has been started. "
        "Create a test request above to begin."
    )


# --------------------------------------------------
# SECURITY EVENTS
# --------------------------------------------------

st.divider()
st.header("📊 Security Overview")

events = load_events()

if not events:
    st.info(
        "No audit events found yet. Submit a gateway request "
        "to populate the security dashboard."
    )
    st.caption(f"Audit file: {AUDIT_FILE}")
    st.stop()

df = pd.DataFrame(events)

for column, default in [
    ("event_id", ""),
    ("timestamp", ""),
    ("tool_name", "unknown"),
    ("decision", "UNKNOWN"),
    ("reason", ""),
    ("execution_attempted", False),
]:
    if column not in df.columns:
        df[column] = default

df["decision"] = df["decision"].astype(str).str.upper()

# Derive display-only risk assessments for older audit events that do not
# store risk_score/risk_level. These values are estimates for the dashboard;
# they are not written back to the audit log and do not affect enforcement.
def dashboard_risk(event):
    stored_score = event.get("risk_score")
    stored_level = event.get("risk_level")
    if stored_score is not None and stored_level:
        try:
            return int(stored_score), str(stored_level).upper(), "Recorded"
        except (TypeError, ValueError):
            pass

    decision = str(event.get("decision", "BLOCK")).upper()
    if decision not in {"ALLOW", "BLOCK"}:
        decision = "BLOCK"
    tool_name = str(event.get("tool_name", "unknown"))
    estimate = calculate_risk(
        tool_name=tool_name,
        arguments={},
        decision=decision,
        suspicious_sequence=(tool_name == "send_external" and decision == "BLOCK"),
    )
    return int(estimate["risk_score"]), str(estimate["risk_level"]).upper(), "Estimated"

risk_details = [dashboard_risk(event) for event in events]
df["risk_score"] = [item[0] for item in risk_details]
df["risk_level"] = [item[1] for item in risk_details]
df["risk_source"] = [item[2] for item in risk_details]

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
        try:
            alert_risk = dashboard_risk(event)
        except (TypeError, ValueError, KeyError):
            alert_risk = (None, "UNKNOWN", "Unavailable")

        with st.container(border=True):
            st.markdown(f"### {decision}: `{tool_name}`")

            if decision == "BLOCK":
                st.warning("GUARDIAN MCP blocked this tool request.")
            else:
                st.error("A tool execution error was recorded.")

            st.write(f"**Why it was blocked:** {reason}")
            detail_left, detail_right = st.columns(2)
            with detail_left:
                st.write(f"**Risk score:** {alert_risk[0]}/100" if alert_risk[0] is not None else "**Risk score:** Unavailable")
                st.write(f"**Risk level:** {alert_risk[1]}")
            with detail_right:
                st.write(f"**Time (UTC):** {timestamp}")
                st.write(f"**Risk data:** {alert_risk[2]}")

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



total = len(df)
allowed = int((df["decision"] == "ALLOW").sum())
blocked = int((df["decision"] == "BLOCK").sum())
errors = int((df["decision"] == "ERROR").sum())

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Events", total)
c2.metric("Allowed", allowed)
c3.metric("Blocked", blocked)
c4.metric("Errors", errors)

st.subheader("Security Incident Summary")
st.caption("A quick read of the activity recorded in the audit log.")
high_risk = int((df["risk_level"] == "HIGH").sum())
external_send_blocks = int(
    ((df["tool_name"].astype(str).str.lower() == "send_external")
     & (df["decision"] == "BLOCK")).sum()
)
estimated_count = int((df["risk_source"] == "Estimated").sum())
s1, s2, s3 = st.columns(3)
s1.metric("High-Risk Events", high_risk, help="Includes risk levels recorded or estimated for display.")
s2.metric("Blocked External-Send Requests", external_send_blocks)
s3.metric("Risk Values Estimated", estimated_count)
st.caption(
    "Estimated risk values are calculated for display from existing event fields. "
    "They are not written back to the audit log and do not change gateway decisions."
)


# --------------------------------------------------
# AUDIT INTEGRITY
# --------------------------------------------------

st.divider()
st.subheader("🔐 Audit Log Integrity")

if verify_audit_log():
    st.success("Hash-chain verification passed.")
else:
    st.error(
        "Hash-chain verification failed. Investigate the audit records."
    )

st.caption(f"Audit file: `{AUDIT_FILE}`")


# --------------------------------------------------
# CHARTS
# --------------------------------------------------

st.divider()
chart1, chart2 = st.columns(2)

with chart1:
    st.markdown("#### Decision Breakdown")

    counts = (
        df["decision"]
        .value_counts()
        .rename_axis("Decision")
        .to_frame("Events")
    )

    st.bar_chart(counts, width="stretch")

with chart2:
    st.markdown("#### Tool Activity")

    counts = (
        df["tool_name"]
        .astype(str)
        .value_counts()
        .rename_axis("Tool")
        .to_frame("Events")
    )

    st.bar_chart(counts, width="stretch")


# --------------------------------------------------
# BLOCK REASONS
# --------------------------------------------------

st.subheader("Block Reasons")

blocked_df = df[df["decision"] == "BLOCK"]

if blocked_df.empty:
    st.info("No blocked events recorded.")
else:
    counts = (
        blocked_df["reason"]
        .fillna("No reason provided")
        .astype(str)
        .value_counts()
        .rename_axis("Reason")
        .to_frame("Events")
    )

    st.bar_chart(counts, width="stretch")


# --------------------------------------------------
# ATTACK INVESTIGATION TIMELINE
# --------------------------------------------------

st.divider()
st.header("🔎 Attack Investigation Timeline")

st.caption(
    "AttackTrace looks for a successful report read followed by "
    "a blocked external-send attempt within the configured event window."
)

try:
    traces = trace_attacks(events, window_size=10)
except (ValueError, TypeError) as exc:
    traces = []
    st.error(f"Could not analyze the audit events: {exc}")

if not traces:
    st.info(
        "No matching attack sequences were found in the current audit log. "
        "This does not guarantee that every possible attack is absent."
    )
else:
    st.warning(f"Detected {len(traces)} suspicious sequence(s).")

    for trace in traces:
        with st.expander(
            f"🚨 {trace['trace_id']} — {trace['summary']}",
            expanded=True,
        ):
            st.write(f"**Category:** {trace['category']}")
            st.write(f"**Severity:** {trace['severity'].upper()}")

            timeline_df = pd.DataFrame(trace["events"])

            if not timeline_df.empty:
                display_columns = [
                    column
                    for column in [
                        "step",
                        "timestamp",
                        "tool_name",
                        "decision",
                        "reason",
                        "execution_attempted",
                        "risk_score",
                        "risk_level",
                    ]
                    if column in timeline_df.columns
                ]

                st.dataframe(
                    timeline_df[display_columns],
                    width="stretch",
                    hide_index=True,
                )

                final_event = timeline_df.iloc[-1]
                risk_score = int(final_event.get("risk_score", 0))
                risk_level = str(
                    final_event.get("risk_level", "UNKNOWN")
                )

                st.metric("Final Event Risk Score", f"{risk_score}/100")
                st.write(f"**Risk level:** {risk_level}")

                st.info(
                    "A report was accessed successfully, then an "
                    "external-send request was blocked. Review the timeline "
                    "to investigate this sequence."
                )


# --------------------------------------------------
# RECENT SECURITY EVENTS
# --------------------------------------------------

st.divider()
st.header("Recent Security Events")

decisions = sorted(df["decision"].unique().tolist())

selected_decisions = st.multiselect(
    "Filter by decision",
    decisions,
    default=decisions,
)

tool_names = sorted(df["tool_name"].astype(str).unique().tolist())

selected_tools = st.multiselect(
    "Filter by tool",
    tool_names,
    default=tool_names,
)

filtered = df[
    df["decision"].isin(selected_decisions)
    & df["tool_name"].astype(str).isin(selected_tools)
].copy()

filtered["_sort_time"] = pd.to_datetime(
    filtered["timestamp"],
    errors="coerce",
    utc=True,
)

filtered = filtered.sort_values(
    "_sort_time",
    ascending=False,
    na_position="last",
)

columns = [
    name
    for name in [
        "timestamp",
        "event_id",
        "tool_name",
        "decision",
        "reason",
        "execution_attempted",
    ]
    if name in filtered.columns
]

st.dataframe(
    filtered[columns],
    width="stretch",
    hide_index=True,
)

if not filtered.empty:
    with st.expander("Inspect an audit event"):
        event_ids = filtered["event_id"].astype(str).tolist()
        chosen = st.selectbox("Event ID", event_ids)

        event = next(
            item
            for item in events
            if str(item.get("event_id", "")) == chosen
        )

        st.json(event)

st.caption(
    "GUARDIAN MCP — The dashboard displays audit records and "
    "investigation results. Authorization enforcement occurs in the "
    "protected gateway and MCP server."
)
