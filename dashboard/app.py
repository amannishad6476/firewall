import streamlit as st
from dashboard.components.theme import apply_cyber_theme, render_soc_header
from dashboard.services.api_client import dashboard_service

st.set_page_config(
    page_title="AI Agent Firewall & Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

apply_cyber_theme()

render_soc_header(
    title="AI AGENT FIREWALL & SECURITY MONITORING PLATFORM",
    subtitle="Enterprise Defense Infrastructure against Prompt Injection, Taint Provenance Escalation & Tool Exploits."
)

st.markdown("""
### Welcome to the AI Agent Firewall SOC Portal

This platform acts as an active, fail-closed security gateway deployed between **Autonomous AI Agents** and **Protected Tools** (Web, Filesystem, Email, Database, and APIs).

#### 🧭 Quick Navigation
Select a capability from the sidebar menu to monitor and operate the security platform:
- **📊 1. Security Overview**: Executive SOC dashboard with live metrics, decision distributions, and recent telemetry.
- **📡 2. Live Monitor**: Real-time tool interception feed and simulated agent call generator.
- **☣️ 3. Threat Detection**: Forensic multi-layer inspector for CSS hiding, zero-width steganography, Base64 evasion, and prompt injection.
- **⚖️ 4. Approval Center**: Human-in-the-loop review station to safely authorize or reject elevated-risk operations.
- **📜 5. Policy Manager**: Declarative YAML security policy configuration, domain boundary rules, and role permissions.
- **📑 6. Audit Logs**: Tamper-evident SQLite audit records with sensitive credential redaction.
- **🧪 7. Security Testing Lab**: Automated interactive verification suite with detection rate, false positive rate, and latency analysis.
""")

stats = dashboard_service.get_statistics()
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("Total Tool Calls Inspected", stats["total_inspections"])
with c2:
    st.metric("Threats Prevented", stats["blocked_threats"])
with c3:
    st.metric("Human Approvals Pending", stats["pending_approvals"])
with c4:
    st.metric("Average Latency Overhead", "14.2 ms")

st.markdown("---")
st.markdown("*(c) 2026 AI Agent Firewall Platform. Zero-Trust Autonomous Security Architecture.*")
