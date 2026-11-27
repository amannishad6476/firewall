import streamlit as st
import pandas as pd
from dashboard.components.theme import apply_cyber_theme, render_soc_header, get_current_theme
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
    subtitle="Review and authorize medium-to-high risk operations intercepted by firewall policies (60-second window)."
)

col_top1, col_top2 = st.columns([4, 1])
with col_top2:
    if st.button("🔄 Refresh / Sweep", use_container_width=True):
        st.rerun()

pending = dashboard_service.get_pending_approvals()

st.markdown(f"### ⏳ Pending Approval Requests ({len(pending)})")
st.caption("Active operations requiring operator clearance. If unreviewed after 60s, the firewall fail-safe auto-rejects and blocks the tool call.")

if not pending:
    st.success("No pending approval requests. All agent operations are either authorized or blocked.")
else:
    for req in pending:
        with st.container():
            rem_sec = req.get("seconds_remaining", 0)
            mins = rem_sec // 60
            secs = rem_sec % 60
            timer_badge = f"⏱️ Window: {mins:02d}:{secs:02d}" if rem_sec > 0 else "⚠️ Expiring Imminently"

            st.markdown(f"""
            <div class="approval-card">
                <div class="approval-card-header">
                    <span class="approval-op-title">Operation: <code>{req['action_type']}</code> &rarr; <code>{req['target_resource']}</code></span>
                    <div>
                        <span style="background: rgba(234, 179, 8, 0.15); color: #eab308; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; margin-right: 6px;">{timer_badge}</span>
                        <span class="badge-human">RISK: {req['calculated_risk']:.2f}</span>
                    </div>
                </div>
                <div class="approval-meta">
                    Approval ID: <code>{req['id']}</code> | Agent: <code>{req['agent_id']}</code> | Created: {req['created_at']} | Expires: {req.get('expires_at', 'N/A')} | Category: <b>{req['threat_category']}</b>
                </div>
                <div class="approval-reason">
                    <b>Trigger Reason</b>: {req['reason']}
                </div>
            </div>
            """, unsafe_allow_html=True)

            c_act1, c_act2, c_spacer = st.columns([1.2, 1.2, 3.6])
            with c_act1:
                if st.button("✅ Approve Action", key=f"app_{req['id']}", use_container_width=True, type="primary"):
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
