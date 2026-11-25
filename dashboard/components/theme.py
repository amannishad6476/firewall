import streamlit as st

CYBER_DARK_CSS = """
<style>
    /* Dark Theme (Default) */
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

    /* Suppress spellcheck squiggles on YAML/code editors */
    textarea {
        spellcheck: false;
        -webkit-spell-check: false;
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
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

CYBER_LIGHT_CSS = """
<style>
    /* Light Theme */
    .stApp {
        background-color: #f8fafc;
        color: #0f172a;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Top header badge */
    .soc-header {
        background: linear-gradient(90deg, #f1f5f9 0%, #e2e8f0 100%);
        border: 1px solid #cbd5e1;
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
        color: #0f172a;
        letter-spacing: 0.5px;
    }
    .soc-badge {
        background-color: #d1fae5;
        color: #065f46;
        font-size: 0.8rem;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 9999px;
        border: 1px solid #10b981;
    }

    /* Metric Card styles */
    .metric-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .metric-val {
        font-size: 2rem;
        font-weight: 700;
        color: #0f172a;
    }
    .metric-label {
        font-size: 0.82rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    /* Card surface adjustment for light mode */
    div[style*="background: #111827"] {
        background: #ffffff !important;
        border-color: #cbd5e1 !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
    div[style*="background: #0f172a"] {
        background: #f1f5f9 !important;
    }
    div[style*="background: #111827"] span, 
    div[style*="background: #111827"] div {
        color: #1e293b !important;
    }
    div[style*="background: #111827"] code {
        color: #0f172a !important;
        background-color: #f1f5f9 !important;
    }

    /* Suppress spellcheck squiggles on YAML/code editors */
    textarea {
        spellcheck: false;
        -webkit-spell-check: false;
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
    }

    /* Badges */
    .badge-allow {
        background-color: #d1fae5;
        color: #065f46;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-block {
        background-color: #fee2e2;
        color: #991b1b;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-human {
        background-color: #fef3c7;
        color: #92400e;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
</style>
"""

def get_current_theme() -> str:
    """Returns the active theme mode safely."""
    try:
        if "dashboard_theme" not in st.session_state:
            st.session_state["dashboard_theme"] = "Dark"
        return st.session_state["dashboard_theme"]
    except Exception:
        return "Dark"

def apply_cyber_theme():
    """Applies theme CSS and renders a simple non-destructive sidebar toggle."""
    if "dashboard_theme" not in st.session_state:
        st.session_state["dashboard_theme"] = "Dark"

    # Non-destructive sidebar toggle
    try:
        with st.sidebar:
            st.markdown("---")
            choice = st.radio(
                "Theme",
                options=["Dark", "Light"],
                index=0 if st.session_state["dashboard_theme"] == "Dark" else 1,
                horizontal=True,
                key="_theme_toggle_key"
            )
            if choice != st.session_state["dashboard_theme"]:
                st.session_state["dashboard_theme"] = choice
                st.rerun()
    except Exception:
        pass

    # Apply minimal, targeted theme CSS
    theme = get_current_theme()
    if theme == "Light":
        st.markdown(CYBER_LIGHT_CSS, unsafe_allow_html=True)
    else:
        st.markdown(CYBER_DARK_CSS, unsafe_allow_html=True)

def render_soc_header(title: str, subtitle: str = ""):
    theme = get_current_theme()
    subtitle_color = "#475569" if theme == "Light" else "#94a3b8"

    st.markdown(f"""
    <div class="soc-header">
        <div>
            <div class="soc-title">🛡️ {title}</div>
            <div style="color: {subtitle_color}; font-size: 0.9rem; margin-top: 4px;">{subtitle}</div>
        </div>
        <div>
            <span class="soc-badge">● ZERO-TRUST ACTIVE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
