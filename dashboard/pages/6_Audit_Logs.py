import streamlit as st
import pandas as pd
from dashboard.components.theme import apply_cyber_theme, render_soc_header
from dashboard.services.api_client import dashboard_service

st.set_page_config(page_title="Audit Logs | AI Firewall", page_icon="📑", layout="wide")
apply_cyber_theme()

render_soc_header(
    title="Tamper-Evident Security Audit Logs",
    subtitle="Full provenance trail of agent actions, decisions, risk evaluations, and human approvals."
)

col_s, col_limit = st.columns([4, 1])
with col_s:
    search_term = st.text_input("🔍 Search audit records by actor, event type, or keyword:", value="")
with col_limit:
    record_limit = st.selectbox("Max Records", [50, 100, 200, 500], index=1)

logs = dashboard_service.get_audit_logs(search=search_term if search_term else None, limit=record_limit)

st.markdown(f"**Found {len(logs)} audit record(s)**")

if logs:
    df = pd.DataFrame(logs)[["timestamp", "actor", "event_type", "agent_id", "decision", "risk_score", "action_summary", "details"]]
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No audit logs matching search parameters.")
