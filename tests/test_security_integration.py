
from pathlib import Path
import importlib.util

import pandas as pd
import streamlit as st


# --------------------------------------------------
# PATHS AND AUDIT LOGGER
# --------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]
AUDIT_FILE = ROOT / "data" / "audit" / "events.jsonl"

LOGGER_PATH = ROOT / "app" / "audit" / "logger.py"


@st.cache_resource
def load_verifier():
    """Load the existing audit hash-chain verifier."""
    spec = importlib.util.spec_from_file_location(
        "guardian_audit_logger",
        LOGGER_PATH,
    )

    if spec is None or spec.loader is None:
        raise ImportError("Could not load audit logger.")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module.verify_audit_log


verify_audit_log = load_verifier()


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="GUARDIAN MCP | Security Center",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ GUARDIAN MCP")
st.subheader("Runtime Security Center")
st.caption(
    "Monitor MCP authorization decisions, "
    "security alerts, and audit-log integrity."
)


# --------------------------------------------------
# LOAD AUDIT EVENTS
# --------------------------------------------------

@st.cache_data
def load_events():
    """Read audit events from the JSON Lines file."""
    events = []

    if not AUDIT_FILE.exists():
        return events

    with AUDIT_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = __import__("json").loads(line)

                if isinstance(event, dict):
                    events.append(event)

            except ValueError:
                st.warning(
                    f"Could not parse audit record "
                    f"on line {line_number}."
                )

    return events


if st.button("↻ Refresh security data"):
    load_events.clear()
    st.rerun()


events = load_events()

if not events:
    st.info(
        "No audit events found. Run an MCP tool request first."
    )
    st.caption(f"Audit file: {AUDIT_FILE}")
    st.stop()


df = pd.DataFrame(events)

# Ensure expected columns exist.
for column in [
    "timestamp",
    "event_id",
    "tool_name",
    "decision",
    "reason",
    "execution_attempted",
]:
    if column not in df.columns:
        df[column] = None

df["decision"] = (
    df["decision"]
    .fillna("UNKNOWN")
    .astype(str)
    .str.upper()
)

df["tool_name"] = (
    df["tool_name"]
    .fillna("Unknown tool")
    .astype(str)
)

df["reason"] = (
    df["reason"]
    .fillna("No reason provided")
    .astype(str)
)


# --------------------------------------------------
# SECURITY OVERVIEW
# --------------------------------------------------

st.markdown("## Security Overview")

total = len(df)
allowed = int((df["decision"] == "ALLOW").sum())
blocked = int((df["decision"] == "BLOCK").sum())
errors = int((df["decision"] == "ERROR").sum())

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Events", total)
c2.metric("Allowed", allowed)
c3.metric("Blocked", blocked)
c4.metric("Errors", errors)

st.divider()


# --------------------------------------------------
# AUDIT LOG INTEGRITY
# --------------------------------------------------

st.markdown("### Audit Log Integrity")

try:
    integrity_valid = verify_audit_log()
except Exception:
    integrity_valid = False

if integrity_valid:
    st.success("Hash-chain verification passed.")
else:
    st.error(
        "Hash-chain verification failed. "
        "Investigate the audit records."
    )

st.caption(f"Audit file: {AUDIT_FILE}")

st.divider()


# --------------------------------------------------
# SECURITY RISK ALERTS
# --------------------------------------------------

st.markdown("## 🚨 Security Risk Alerts")

blocked_events = df[df["decision"] == "BLOCK"].copy()

# Three or more blocks for the same tool trigger an alert.
BLOCK_THRESHOLD = 3

if blocked_events.empty:
    st.success("No blocked requests detected in the audit log.")

else:
    blocked_counts = blocked_events["tool_name"].value_counts()

    repeated_blocks = blocked_counts[
        blocked_counts >= BLOCK_THRESHOLD
    ]

    if not repeated_blocks.empty:
        for tool_name, count in repeated_blocks.items():
            st.error(
                f"High attention: tool '{tool_name}' "
                f"has been blocked {int(count)} times. "
                "Review the reasons and request history."
            )

    else:
        st.warning(
            f"{len(blocked_events)} blocked request(s) recorded. "
            f"No tool has reached the threshold of "
            f"{BLOCK_THRESHOLD} blocked requests."
        )

    with st.expander("View blocked-request details"):
        blocked_columns = [
            column
            for column in [
                "timestamp",
                "event_id",
                "tool_name",
                "reason",
                "decision",
                "execution_attempted",
            ]
            if column in blocked_events.columns
        ]

        st.dataframe(
            blocked_events[blocked_columns],
            width="stretch",
            hide_index=True,
        )

st.divider()


# --------------------------------------------------
# DECISION BREAKDOWN AND TOOL ACTIVITY
# --------------------------------------------------

st.markdown("## Security Analytics")

chart1, chart2 = st.columns(2)

with chart1:
    st.markdown("#### Decision Breakdown")

    decision_counts = (
        df["decision"]
        .value_counts()
        .rename_axis("Decision")
        .to_frame("Events")
    )

    st.bar_chart(decision_counts, width="stretch")

with chart2:
    st.markdown("#### Tool Activity")

    tool_counts = (
        df["tool_name"]
        .value_counts()
        .rename_axis("Tool")
        .to_frame("Events")
    )

    st.bar_chart(tool_counts, width="stretch")


# --------------------------------------------------
# BLOCK REASONS
# --------------------------------------------------

st.markdown("#### Block Reasons")

if blocked_events.empty:
    st.info("No blocked events recorded.")

else:
    reason_counts = (
        blocked_events["reason"]
        .value_counts()
        .rename_axis("Reason")
        .to_frame("Events")
    )

    st.bar_chart(reason_counts, width="stretch")


st.divider()


# --------------------------------------------------
# RECENT SECURITY EVENTS
# --------------------------------------------------

st.markdown("## Recent Security Events")

decisions = sorted(df["decision"].unique().tolist())

selected_decisions = st.multiselect(
    "Filter by decision",
    decisions,
    default=decisions,
)

tool_names = sorted(df["tool_name"].unique().tolist())

selected_tools = st.multiselect(
    "Filter by tool",
    tool_names,
    default=tool_names,
)

filtered = df[
    df["decision"].isin(selected_decisions)
    & df["tool_name"].isin(selected_tools)
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

display_columns = [
    column
    for column in [
        "timestamp",
        "event_id",
        "tool_name",
        "decision",
        "reason",
        "execution_attempted",
    ]
    if column in filtered.columns
]

st.dataframe(
    filtered[display_columns],
    width="stretch",
    hide_index=True,
)

# Detailed event inspection.
if not filtered.empty:
    with st.expander("Inspect an audit event"):
        event_ids = (
            filtered["event_id"]
            .fillna("")
            .astype(str)
            .tolist()
        )

        chosen = st.selectbox("Event ID", event_ids)

        chosen_event = next(
            (
                item
                for item in events
                if str(item.get("event_id", "")) == chosen
            ),
            None,
        )

        if chosen_event is not None:
            st.json(chosen_event)

st.caption(
    "GUARDIAN MCP — This dashboard displays audit records "
    "and rule-based alerts. Authorization enforcement occurs "
    "in the protected MCP server."
)
