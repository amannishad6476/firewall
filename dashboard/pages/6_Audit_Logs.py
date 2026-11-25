import streamlit as st
import pandas as pd
from dashboard.components.theme import apply_cyber_theme, render_soc_header
from dashboard.services.api_client import dashboard_service

st.set_page_config(
    page_title="Audit Logs | AI Firewall",
    page_icon="📑",
    layout="wide",
    initial_sidebar_state="collapsed"
)
apply_cyber_theme(active_page="pages/6_Audit_Logs.py")

render_soc_header(
    title="Tamper-Evident Security Audit Logs",
    subtitle="Full provenance trail of agent actions, decisions, risk evaluations, and human approvals."
)

# Cryptographic chain verification widget
c_verify, c_status = st.columns([1, 3])
with c_verify:
    if st.button("🔐 Verify SHA-256 Hash Chain", use_container_width=True):
        chain_res = dashboard_service.verify_audit_chain()
        if chain_res.get("valid"):
            st.success(f"✅ Cryptographically Verified: {chain_res.get('details')}")
            if chain_res.get("head_hash"):
                st.caption(f"Head Block Hash: `{chain_res.get('head_hash')}`")
        else:
            st.error(f"❌ TAMPERING DETECTED: {chain_res.get('details')}")

col_s, col_limit = st.columns([4, 1])
with col_s:
    search_term = st.text_input("🔍 Search audit records by actor, event type, or keyword:", value="")
with col_limit:
    record_limit = st.selectbox("Max Records", [50, 100, 200, 500], index=1)

logs = dashboard_service.get_audit_logs(limit=record_limit, search=search_term if search_term else None)

if logs:
    df_logs = pd.DataFrame(logs)
    st.dataframe(
        df_logs[["timestamp", "event_type", "actor", "action", "risk_score", "prev_hash", "row_hash", "details"]],
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No audit logs matching query found.")
