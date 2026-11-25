import streamlit as st
import pandas as pd
from dashboard.components.theme import apply_cyber_theme, render_soc_header
from dashboard.services.api_client import dashboard_service
from backend.app.schemas.firewall_schemas import FirewallCheckRequest, ContextTaintInfo, OriginType
from backend.app.firewall.engine import firewall_engine

st.set_page_config(
    page_title="Live Security Monitor | AI Firewall",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="collapsed"
)
apply_cyber_theme(active_page="pages/2_Live_Monitor.py")

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
                taint_origins = [OriginType(origin)] if origin != "USER" else []
                req = FirewallCheckRequest(
                    agent_id=agent_id,
                    action_type=action_type,
                    target_resource=target_resource,
                    parameters={"content": content_sample} if content_sample else {},
                    context_taint=ContextTaintInfo(
                        tainted_origins=taint_origins,
                        untrusted_content_sources=[target_resource] if taint_origins else [],
                        original_user_goal=user_goal
                    )
                )
                eval_res = firewall_engine.evaluate_request(req, db)
                if eval_res.decision.value == "ALLOW":
                    st.success(f"DECISION: {eval_res.decision.value} | Risk: {eval_res.risk_score:.2f}")
                elif eval_res.decision.value == "BLOCK":
                    st.error(f"DECISION: {eval_res.decision.value} | Risk: {eval_res.risk_score:.2f}\nReason: {eval_res.reason}")
                else:
                    st.warning(f"DECISION: {eval_res.decision.value} | Human Approval Required\nReason: {eval_res.reason}")
            finally:
                db.close()

with col_left:
    st.markdown("#### 🔄 Live Event Interception Stream")
    events = dashboard_service.get_recent_events(limit=15)
    if not events:
        st.info("No events intercepted yet. Use the simulation panel on the right to send a test request.")
    else:
        for ev in events:
            dec = ev.get("decision", "UNKNOWN")
            badge_class = "badge-allow" if dec == "ALLOW" else ("badge-block" if dec == "BLOCK" else "badge-human")
            st.markdown(f"""
            <div style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 12px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 600; color: #f3f4f6;">{ev.get('action_type')} &rarr; <code>{ev.get('target_resource')}</code></span>
                    <span class="{badge_class}">{dec} ({ev.get('risk_score', 0):.2f})</span>
                </div>
                <div style="font-size: 0.85rem; color: #9ca3af; margin-top: 4px;">
                    Agent: <code>{ev.get('agent_id')}</code> | Category: {ev.get('threat_category', 'NONE')} | {ev.get('timestamp')}
                </div>
                <div style="font-size: 0.82rem; color: #d1d5db; margin-top: 6px;">
                    {ev.get('reason')}
                </div>
            </div>
            """, unsafe_allow_html=True)
