import streamlit as st
import pandas as pd
from dashboard.components.theme import apply_cyber_theme, render_soc_header
from dashboard.services.api_client import dashboard_service

st.set_page_config(page_title="Human Approval Center | AI Firewall", page_icon="⚖️", layout="wide")
apply_cyber_theme()

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
            <div class="approval-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="approval-title">Operation: <code>{req['action_type']}</code> &rarr; <code>{req['target_resource']}</code></span>
                    <span style="background-color: #78350f; color: #fde68a; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 0.85rem;">RISK: {req['calculated_risk']:.2f}</span>
                </div>
                <div class="approval-meta">
                    Approval ID: <code>{req['id']}</code> | Agent: <code>{req['agent_id']}</code> | Time: {req['created_at']} | Category: <b>{req['threat_category']}</b>
                </div>
                <div class="approval-reason-box">
                    <b>Reason for Review:</b> {req['reason']}
                </div>
                <div class="approval-params">
                    <b>Parameters:</b> <code>{req['parameters']}</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

            col_btn1, col_btn2, col_reviewer, col_notes = st.columns([1, 1, 2, 3])
            with col_reviewer:
                reviewer_name = st.text_input("Reviewer Identity", value="security_lead", key=f"rev_{req['id']}")
            with col_notes:
                notes = st.text_input("Review Notes", value="Authorized after verifying operational context", key=f"notes_{req['id']}")
            
            with col_btn1:
                if st.button("✅ APPROVE", key=f"app_{req['id']}", use_container_width=True):
                    res = dashboard_service.approve_action(req["id"], reviewer=reviewer_name, notes=notes)
                    if res["success"]:
                        st.success(f"Action approved! ID: {req['id']}")
                        st.rerun()
                    else:
                        st.error(res["message"])

            with col_btn2:
                if st.button("❌ REJECT", key=f"rej_{req['id']}", use_container_width=True):
                    res = dashboard_service.reject_action(req["id"], reviewer=reviewer_name, notes=notes)
                    if res["success"]:
                        st.warning(f"Action rejected! ID: {req['id']}")
                        st.rerun()
                    else:
                        st.error(res["message"])

st.markdown("---")
st.markdown("### 📜 Recent Approval Resolutions")
db = dashboard_service.get_db()
try:
    from backend.app.models.db_models import ApprovalRequest
    resolved = db.query(ApprovalRequest).filter(ApprovalRequest.status != "PENDING").order_by(ApprovalRequest.resolved_at.desc()).limit(20).all()
    if resolved:
        res_data = []
        for r in resolved:
            res_data.append({
                "Resolved At": r.resolved_at.strftime("%Y-%m-%d %H:%M:%S") if r.resolved_at else "N/A",
                "Action": r.action_type,
                "Target": r.target_resource,
                "Agent": r.agent_id,
                "Risk": f"{r.calculated_risk:.2f}",
                "Status": r.status,
                "Reviewer": r.resolved_by or "N/A",
                "Notes": r.resolution_notes or ""
            })
        st.dataframe(pd.DataFrame(res_data), use_container_width=True, hide_index=True)
    else:
        st.info("No resolved approvals recorded yet.")
finally:
    db.close()
