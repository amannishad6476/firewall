import streamlit as st
import pandas as pd
from dashboard.components.theme import apply_cyber_theme, render_soc_header
from dashboard.services.api_client import dashboard_service
from backend.app.schemas.firewall_schemas import FirewallCheckRequest, ContextTaintInfo, OriginType
from backend.app.firewall.engine import firewall_engine

st.set_page_config(page_title="Live Security Monitor | AI Firewall", page_icon="📡", layout="wide")
apply_cyber_theme()

render_soc_header(
    title="Live Security Telemetry & Inspection Monitor",
    subtitle="Real-time stream of intercepted tool calls, risk assessments, and firewall decisions."
)

col_left, col_right = st.columns([2, 1])

with col_right:
    st.markdown("#### ⚡ Intercept Live Agent Tool Call")
    with st.form("simulate_call_form"):
        agent_id = st.selectbox("Agent ID", ["default_agent", "analyst_agent", "admin_agent"])
        action_type = st.selectbox("Tool Action", ["read_webpage", "read_file", "send_email", "delete_file", "execute_sql"])
        target_resource = st.text_input("Target Resource", value="confidential_financials.txt" if action_type == "read_file" else "attacker@example.com")
        origin = st.selectbox("Instruction Origin", ["USER", "WEBPAGE", "FILE", "EXTERNAL_API"])
        user_goal = st.text_input("Original User Goal", value="Summarize market trends")
        content_sample = st.text_area("Content Payload (optional)", value="", placeholder="Enter text or HTML snippet...")
        
        submitted = st.form_submit_button("Inspect through Firewall")
        if submitted:
            db = dashboard_service.get_db()
            try:
                check_req = FirewallCheckRequest(
                    agent_id=agent_id,
                    action_type=action_type,
                    target_resource=target_resource,
                    parameters={"payload": content_sample},
                    context_taint=ContextTaintInfo(
                        source=OriginType(origin),
                        is_tainted=(origin != "USER"),
                        original_user_goal=user_goal
                    ),
                    content_to_scan=content_sample if content_sample else None
                )
                res = firewall_engine.inspect_and_evaluate(check_req, db)
                if res.decision.value == "ALLOW":
                    st.success(f"Decision: {res.decision.value} (Risk: {res.risk_score:.2f}) - {res.reason}")
                elif res.decision.value == "ASK_HUMAN":
                    st.warning(f"Decision: {res.decision.value} (Risk: {res.risk_score:.2f}) - {res.reason}")
                else:
                    st.error(f"Decision: {res.decision.value} (Risk: {res.risk_score:.2f}) - {res.reason}")
            finally:
                db.close()

with col_left:
    st.markdown("#### 🔍 Real-Time Interception Feed")
    events = dashboard_service.get_recent_events(limit=40)
    if events:
        for ev in events[:15]:
            decision_color = "#10b981" if ev["decision"] == "ALLOW" else ("#ef4444" if ev["decision"] == "BLOCK" else "#f59e0b")
            st.markdown(f"""
            <div style="background: #111827; border-left: 4px solid {decision_color}; border-top: 1px solid #1f2937; border-right: 1px solid #1f2937; border-bottom: 1px solid #1f2937; padding: 12px 16px; border-radius: 6px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 700; color: #f1f5f9; font-size: 0.95rem;">{ev['action_type']} &rarr; <code>{ev['target_resource']}</code></span>
                    <span style="background: {decision_color}22; color: {decision_color}; font-weight: 700; font-size: 0.8rem; padding: 2px 8px; border-radius: 4px; border: 1px solid {decision_color};">{ev['decision']}</span>
                </div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 6px;">
                    Timestamp: {ev['timestamp']} | Agent: <code>{ev['agent_id']}</code> | Threat: <b style="color: {'#ef4444' if ev['threat_detected'] else '#64748b'};">{ev['threat_category']}</b> | Risk Score: <b>{ev['calculated_risk']:.2f}</b>
                </div>
                <div style="font-size: 0.85rem; color: #cbd5e1; margin-top: 6px; font-style: italic;">
                    {ev['decision_reason']}
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No incoming tool calls intercepted yet.")
