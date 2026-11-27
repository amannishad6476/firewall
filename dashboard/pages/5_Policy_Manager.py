import streamlit as st
import yaml
import pandas as pd
from dashboard.components.theme import apply_cyber_theme, render_soc_header, get_current_theme
from dashboard.services.api_client import dashboard_service
from backend.app.policies.policy_engine import policy_engine

st.set_page_config(
    page_title="Security Policy Manager | AI Firewall",
    page_icon="📜",
    layout="wide",
    initial_sidebar_state="collapsed"
)
apply_cyber_theme(active_page="pages/5_Policy_Manager.py")

render_soc_header(
    title="Declarative Security Policy Governance",
    subtitle="Manage risk thresholds, domain boundaries, prohibited actions, and agent roles."
)

# Robust JS injection to ensure spellcheck attribute is disabled on textarea DOM elements
st.markdown("""
<script>
    function disableSpellcheck() {
        const textareas = document.querySelectorAll('textarea');
        textareas.forEach(el => {
            el.setAttribute('spellcheck', 'false');
            el.setAttribute('autocomplete', 'off');
            el.setAttribute('autocorrect', 'off');
            el.setAttribute('autocapitalize', 'off');
        });
    }
    disableSpellcheck();
    window.addEventListener('DOMContentLoaded', disableSpellcheck);
    const observer = new MutationObserver(disableSpellcheck);
    observer.observe(document.body, { childList: true, subtree: true });
</script>
""", unsafe_allow_html=True)

current_yaml = dashboard_service.get_policy_yaml()

tab_edit, tab_view, tab_inventory = st.tabs(["✏️ Edit YAML Policy", "🔍 Structured View", "🤖 Agent Inventory & Tiers"])

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
                st.error(f"Policy Validation Error: {res.get('error')}")

with tab_view:
    try:
        parsed = yaml.safe_load(current_yaml)
        st.json(parsed)
    except Exception as e:
        st.error(f"Failed to parse policy structure: {e}")

with tab_inventory:
    st.markdown("### 🤖 Registered AI Agents & Sandboxing Governance")
    st.markdown("Inspect registered autonomous agents, their security tiers, model providers, and runtime execution boundaries.")
    agents_list = dashboard_service.get_registered_agents()
    if agents_list:
        df_agents = pd.DataFrame(agents_list)
        display_cols = [
            "id", "name", "role", "security_tier", "model_provider", 
            "model_name", "sandbox_mode", "trust_level", "is_active"
        ]
        st.dataframe(
            df_agents[[c for c in display_cols if c in df_agents.columns]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No registered agents found in database.")
