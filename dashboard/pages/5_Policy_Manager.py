import streamlit as st
import yaml
from dashboard.components.theme import apply_cyber_theme, render_soc_header
from dashboard.services.api_client import dashboard_service
from backend.app.policies.policy_engine import policy_engine

st.set_page_config(page_title="Security Policy Manager | AI Firewall", page_icon="📜", layout="wide")
apply_cyber_theme()

render_soc_header(
    title="Declarative Security Policy Governance",
    subtitle="Manage risk thresholds, domain boundaries, prohibited actions, and agent roles."
)

current_yaml = dashboard_service.get_policy_yaml()

tab_edit, tab_view = st.tabs(["✏️ Edit YAML Policy", "🔍 Structured View"])

with tab_edit:
    st.markdown("Modify security rules in declarative YAML format. All updates undergo structural schema validation before persisting.")
    edited_yaml = st.text_area("Policy Configuration (YAML)", value=current_yaml, height=450)
    
    col_save, col_reset = st.columns([1, 4])
    with col_save:
        if st.button("💾 Save Policy Update", use_container_width=True):
            res = dashboard_service.update_policy_yaml(edited_yaml)
            if res["success"]:
                st.success("Security policy validated and updated successfully!")
                st.rerun()
            else:
                st.error(f"Failed to update policy: {res['error']}")

with tab_view:
    policy = policy_engine.policy
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### 🌐 Domain Governance")
        st.write("**Allowed Domains:**", policy.get("domains", {}).get("allowed", []))
        st.write("**Blocked Domains:**", policy.get("domains", {}).get("blocked", []))
        
        st.markdown("#### ⚖️ Normalized Risk Thresholds")
        st.json(policy.get("thresholds", {}))

    with c2:
        st.markdown("#### 🔒 Sensitive Protected Actions")
        st.write(policy.get("sensitive_operations", []))

        st.markdown("#### 🤖 Agent Role Permissions")
        st.json(policy.get("agent_permissions", {}))
