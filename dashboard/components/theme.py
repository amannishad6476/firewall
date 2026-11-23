import streamlit as st

CYBER_DARK_CSS = """
<style>
    /* Dark SOC Theme styling */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Top header badge */
    .soc-header {
        background: linear-gradient(90deg, #111827 0%, #1e1b4b 100%);
        border: 1px solid #312e81;
        padding: 16px 24px;
        border-radius: 8px;
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .soc-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #f8fafc;
        letter-spacing: 0.5px;
    }
    .soc-badge {
        background-color: #065f46;
        color: #34d399;
        font-size: 0.8rem;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 9999px;
        border: 1px solid #059669;
    }

    /* Metric Card styles */
    .metric-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .metric-val {
        font-size: 2rem;
        font-weight: 700;
        color: #f9fafb;
    }
    .metric-label {
        font-size: 0.82rem;
        color: #9ca3af;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    /* Badges */
    .badge-allow {
        background-color: #064e3b;
        color: #6ee7b7;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-block {
        background-color: #7f1d1d;
        color: #fca5a5;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-human {
        background-color: #78350f;
        color: #fcd34d;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
</style>
"""

def apply_cyber_theme():
    st.markdown(CYBER_DARK_CSS, unsafe_allow_html=True)

def render_soc_header(title: str, subtitle: str = ""):
    st.markdown(f"""
    <div class="soc-header">
        <div>
            <div class="soc-title">🛡️ {title}</div>
            <div style="color: #94a3b8; font-size: 0.9rem; margin-top: 4px;">{subtitle}</div>
        </div>
        <div>
            <span class="soc-badge">● ZERO-TRUST ACTIVE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
