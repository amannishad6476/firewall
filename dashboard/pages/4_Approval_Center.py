import streamlit as st
import pandas as pd
from dashboard.components.theme import apply_cyber_theme, render_soc_header
from dashboard.services.api_client import dashboard_service

st.set_page_config(
    page_title="Human Approval Center | AI Firewall",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="collapsed"
)
apply_cyber_theme(active_page="pages/4_Approval_Center.py")

render_soc_header(
    title="Human-In-The-Loop Approval Center",
    subtitle="Review and authorize medium-to-high risk operations intercepted by firewall policies."
)

pending = dashboard_service.get_pending_approvals()

st.markdown(f"### ⏳ Pending Approval Requests ({len(pending)})")

if not pending:
    st.success("No pending approval requests. All agent operations are either authorized or blocked.")
else:
    for req in pending:
        with st.container():
            st.markdown(f"""
            <div style="background: #111827; border: 1px solid #374151; border-radius: 8px; padding: 18px; margin-bottom: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 1.1rem; font-weight: 700; color: #f9fafb;">Operation: <code>{req['action_type']}</code> &rarr; <code>{req['target_resource']}</code></span>
                    <span style="background-color: #78350f; color: #fde68a; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 0.85rem;">RISK: {req['calculated_risk']:.2f}</span>
                </div>
                <div style="margin-top: 8px; font-size: 0.85rem; color: #94a3b8;">
                    Approval ID: <code>{req['id']}</code> | Agent: <code>{req['agent_id']}</code> | Time: {req['created_at']} | Category: <b>{req['threat_category']}</b>
                </div>
                <div style="margin-top: 10px; font-size: 0.9rem; color: #e5e7eb;">
                    <b>Trigger Reason</b>: {req['reason']}
                </div>
            </div>
            """, unsafe_allow_html=True)

            c_act1, c_act2, c_spacer = st.columns([1, 1, 4])
            with c_act1:
                if st.button("✅ Approve Action", key=f"app_{req['id']}", use_container_width=True):
                    res = dashboard_service.approve_request(req['id'])
                    if res["success"]:
                        st.success(f"Operation {req['id'][:8]} APPROVED.")
                        st.rerun()
                    else:
                        st.error(f"Approval failed: {res.get('error')}")

            with c_act2:
                if st.button("❌ Reject Action", key=f"rej_{req['id']}", use_container_width=True):
                    res = dashboard_service.reject_request(req['id'])
                    if res["success"]:
                        st.warning(f"Operation {req['id'][:8]} REJECTED.")
                        st.rerun()
                    else:
                        st.error(f"Rejection failed: {res.get('error')}")
