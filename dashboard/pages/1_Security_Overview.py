import streamlit as st
import pandas as pd
from dashboard.components.theme import apply_cyber_theme, render_soc_header
from dashboard.components.charts import (
    create_decision_pie_chart,
    create_risk_distribution_chart,
    create_action_bar_chart
)
from dashboard.services.api_client import dashboard_service

st.set_page_config(page_title="Security Overview | AI Firewall", page_icon="🛡️", layout="wide")
apply_cyber_theme()

render_soc_header(
    title="AI Agent Firewall - Security Operations Center",
    subtitle="Continuous inspection, taint isolation, and policy enforcement metrics."
)

stats = dashboard_service.get_statistics()
recent_events = dashboard_service.get_recent_events(limit=50)

# Top KPIs
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric(label="Total Inspections", value=stats["total_inspections"])
with col2:
    st.metric(label="Allowed Actions", value=stats["allowed_actions"], delta="Safe")
with col3:
    st.metric(label="Blocked Threats", value=stats["blocked_threats"], delta=f"-{stats['blocked_threats']}", delta_color="inverse")
with col4:
    st.metric(label="Pending Approvals", value=stats["pending_approvals"])
with col5:
    st.metric(label="Threat Detection Rate", value=f"{stats['threat_detection_rate']}%")

st.markdown("<br>", unsafe_allow_html=True)

# Visualizations Row
row_col1, row_col2, row_col3 = st.columns(3)
with row_col1:
    st.plotly_chart(
        create_decision_pie_chart(
            allowed=stats["allowed_actions"],
            blocked=stats["blocked_threats"],
            pending=stats["pending_approvals"]
        ),
        use_container_width=True
    )

with row_col2:
    st.plotly_chart(create_risk_distribution_chart(recent_events), use_container_width=True)

with row_col3:
    st.plotly_chart(create_action_bar_chart(recent_events), use_container_width=True)

# Recent Security Events Table
st.markdown("### 📋 Recent Security Events")
if recent_events:
    df = pd.DataFrame(recent_events)[
        ["timestamp", "agent_id", "action_type", "target_resource", "threat_category", "calculated_risk", "decision", "decision_reason"]
    ]
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No security events recorded in SQLite yet. Run the Security Demo or Test Suite to generate telemetry.")
