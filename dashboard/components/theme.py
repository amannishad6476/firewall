import streamlit as st

CYBER_DARK_CSS = """
<style>
    /* =========================================================================
       DARK SOC THEME (Default)
       ========================================================================= */
    .stApp {
        background-color: #0b0f19 !important;
        color: #f8fafc !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    [data-testid="stHeader"] {
        background-color: #0b0f19 !important;
    }

    /* Headings and text */
    .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
        color: #f8fafc !important;
        font-weight: 700 !important;
    }
    .stApp p, .stApp label, .stApp li {
        color: #cbd5e1;
    }

    /* Streamlit KPI Metric Cards */
    [data-testid="stMetric"] {
        background: #111827 !important;
        border: 1px solid #1f2937 !important;
        border-radius: 8px !important;
        padding: 14px 18px !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3) !important;
    }
    [data-testid="stMetricValue"] {
        color: #f8fafc !important;
        font-size: 2rem !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
    }
    [data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
        font-size: 0.8rem !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
    }
    [data-testid="stMetricDelta"] svg {
        fill: currentColor !important;
    }

    /* High-Contrast Interactive Buttons */
    .stButton > button {
        background-color: #1e293b !important;
        color: #f8fafc !important;
        border: 1px solid #475569 !important;
        font-weight: 600 !important;
        border-radius: 6px !important;
        padding: 8px 16px !important;
        transition: all 0.15s ease-in-out !important;
    }
    .stButton > button:hover {
        background-color: #334155 !important;
        border-color: #818cf8 !important;
        color: #ffffff !important;
        box-shadow: 0 0 8px rgba(99, 102, 241, 0.3) !important;
    }
    .stButton > button:active {
        background-color: #4f46e5 !important;
        border-color: #6366f1 !important;
        color: #ffffff !important;
    }

    /* Form Inputs, TextAreas, and Selectboxes */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div {
        background-color: #111827 !important;
        color: #f8fafc !important;
        border: 1px solid #374151 !important;
        border-radius: 6px !important;
    }
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 1px #6366f1 !important;
    }

    /* Code & YAML Textareas: Clean Monospace & Suppress Spellcheck Squiggles */
    textarea {
        font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', monospace !important;
        font-size: 0.9rem !important;
        line-height: 1.5 !important;
        spellcheck: false !important;
        -webkit-spell-check: false !important;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
        border-bottom: 1px solid #1f2937;
    }
    .stTabs [data-baseweb="tab"] {
        color: #94a3b8 !important;
        border-radius: 6px 6px 0 0;
        padding: 10px 18px;
        font-weight: 600;
        background-color: transparent;
    }
    .stTabs [aria-selected="true"] {
        color: #f8fafc !important;
        background-color: #1e293b !important;
        border-bottom: 2px solid #6366f1 !important;
    }

    /* Dataframe Table Container */
    [data-testid="stDataFrame"] {
        background-color: #111827 !important;
        border-radius: 8px !important;
        border: 1px solid #1f2937 !important;
    }

    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #0d131f !important;
        border-right: 1px solid #1e293b !important;
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

    /* Cards */
    .feed-card {
        background: #111827;
        border-top: 1px solid #1f2937;
        border-right: 1px solid #1f2937;
        border-bottom: 1px solid #1f2937;
        padding: 12px 16px;
        border-radius: 6px;
        margin-bottom: 10px;
    }
    .feed-title {
        font-weight: 700;
        color: #f1f5f9;
        font-size: 0.95rem;
    }
    .feed-meta {
        font-size: 0.8rem;
        color: #94a3b8;
        margin-top: 6px;
    }
    .feed-reason {
        font-size: 0.85rem;
        color: #cbd5e1;
        margin-top: 6px;
        font-style: italic;
    }

    .approval-card {
        background: #111827;
        border: 1px solid #374151;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 16px;
    }
    .approval-title {
        font-size: 1.1rem;
        font-weight: 700;
        color: #f9fafb;
    }
    .approval-meta {
        margin-top: 8px;
        font-size: 0.85rem;
        color: #94a3b8;
    }
    .approval-reason-box {
        margin-top: 10px;
        padding: 10px;
        background: #0f172a;
        border-radius: 4px;
        border-left: 3px solid #f59e0b;
        color: #e2e8f0;
        font-size: 0.9rem;
    }
    .approval-params {
        margin-top: 8px;
        font-size: 0.85rem;
        color: #cbd5e1;
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
    /* =========================================================================
       LIGHT SOC THEME
       ========================================================================= */
    .stApp {
        background-color: #f8fafc !important;
        color: #0f172a !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    [data-testid="stHeader"] {
        background-color: #f8fafc !important;
    }

    /* Headings and text */
    .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
        color: #0f172a !important;
        font-weight: 700 !important;
    }
    .stApp p, .stApp label, .stApp li {
        color: #334155 !important;
    }

    /* Streamlit KPI Metric Cards */
    [data-testid="stMetric"] {
        background: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        border-radius: 8px !important;
        padding: 14px 18px !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05) !important;
    }
    [data-testid="stMetricValue"] {
        color: #0f172a !important;
        font-size: 2rem !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
    }
    [data-testid="stMetricLabel"] {
        color: #64748b !important;
        font-size: 0.8rem !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
    }
    [data-testid="stMetricDelta"] svg {
        fill: currentColor !important;
    }

    /* High-Contrast Interactive Buttons */
    .stButton > button {
        background-color: #ffffff !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
        font-weight: 600 !important;
        border-radius: 6px !important;
        padding: 8px 16px !important;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05) !important;
        transition: all 0.15s ease-in-out !important;
    }
    .stButton > button:hover {
        background-color: #f1f5f9 !important;
        border-color: #6366f1 !important;
        color: #4338ca !important;
        box-shadow: 0 0 8px rgba(99, 102, 241, 0.25) !important;
    }
    .stButton > button:active {
        background-color: #6366f1 !important;
        border-color: #4f46e5 !important;
        color: #ffffff !important;
    }

    /* Form Inputs, TextAreas, and Selectboxes */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div {
        background-color: #ffffff !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
        border-radius: 6px !important;
    }
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 1px #6366f1 !important;
    }

    /* Code & YAML Textareas */
    textarea {
        font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', monospace !important;
        font-size: 0.9rem !important;
        line-height: 1.5 !important;
        spellcheck: false !important;
        -webkit-spell-check: false !important;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
        border-bottom: 1px solid #e2e8f0;
    }
    .stTabs [data-baseweb="tab"] {
        color: #64748b !important;
        border-radius: 6px 6px 0 0;
        padding: 10px 18px;
        font-weight: 600;
        background-color: transparent;
    }
    .stTabs [aria-selected="true"] {
        color: #0f172a !important;
        background-color: #ffffff !important;
        border-bottom: 2px solid #6366f1 !important;
    }

    /* Dataframe Table Container */
    [data-testid="stDataFrame"] {
        background-color: #ffffff !important;
        border-radius: 8px !important;
        border: 1px solid #e2e8f0 !important;
    }

    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #f1f5f9 !important;
        border-right: 1px solid #e2e8f0 !important;
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] span {
        color: #1e293b !important;
    }

    /* Top header badge */
    .soc-header {
        background: linear-gradient(90deg, #f8fafc 0%, #eef2ff 100%);
        border: 1px solid #c7d2fe;
        padding: 16px 24px;
        border-radius: 8px;
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
    }
    .soc-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #1e1b4b;
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

    /* Cards */
    .feed-card {
        background: #ffffff;
        border-top: 1px solid #e2e8f0;
        border-right: 1px solid #e2e8f0;
        border-bottom: 1px solid #e2e8f0;
        padding: 12px 16px;
        border-radius: 6px;
        margin-bottom: 10px;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }
    .feed-title {
        font-weight: 700;
        color: #0f172a;
        font-size: 0.95rem;
    }
    .feed-meta {
        font-size: 0.8rem;
        color: #64748b;
        margin-top: 6px;
    }
    .feed-reason {
        font-size: 0.85rem;
        color: #334155;
        margin-top: 6px;
        font-style: italic;
    }

    .approval-card {
        background: #ffffff;
        border: 1px solid #cbd5e1;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    }
    .approval-title {
        font-size: 1.1rem;
        font-weight: 700;
        color: #0f172a;
    }
    .approval-meta {
        margin-top: 8px;
        font-size: 0.85rem;
        color: #64748b;
    }
    .approval-reason-box {
        margin-top: 10px;
        padding: 10px;
        background: #f8fafc;
        border-radius: 4px;
        border-left: 3px solid #f59e0b;
        color: #1e293b;
        font-size: 0.9rem;
    }
    .approval-params {
        margin-top: 8px;
        font-size: 0.85rem;
        color: #475569;
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
    """Returns the current theme mode safely in any execution context."""
    try:
        if "dashboard_theme" not in st.session_state:
            st.session_state["dashboard_theme"] = "Dark Mode"
        return st.session_state["dashboard_theme"]
    except Exception:
        return "Dark Mode"

def apply_cyber_theme():
    """Applies active theme CSS and renders persistent sidebar theme toggle."""
    current = get_current_theme()

    # Render Theme Toggle in Sidebar
    try:
        with st.sidebar:
            st.markdown("---")
            st.caption("🎨 **DISPLAY THEME**")
            theme_choice = st.radio(
                "Interface Theme",
                options=["🌙 Dark Mode", "☀️ Light Mode"],
                index=0 if current == "Dark Mode" else 1,
                key="_soc_theme_selector",
                horizontal=True,
                label_visibility="collapsed"
            )
            mode = "Dark Mode" if "Dark" in theme_choice else "Light Mode"
            if mode != st.session_state.get("dashboard_theme"):
                st.session_state["dashboard_theme"] = mode
                st.rerun()
    except Exception:
        pass

    # Inject theme-appropriate CSS
    if current == "Light Mode":
        st.markdown(CYBER_LIGHT_CSS, unsafe_allow_html=True)
    else:
        st.markdown(CYBER_DARK_CSS, unsafe_allow_html=True)

def render_soc_header(title: str, subtitle: str = ""):
    """Renders the top SOC banner with theme-adaptive colors."""
    current = get_current_theme()
    subtitle_color = "#94a3b8" if current == "Dark Mode" else "#475569"
    badge_style = (
        "background-color: #065f46; color: #34d399; border: 1px solid #059669;"
        if current == "Dark Mode"
        else "background-color: #d1fae5; color: #065f46; border: 1px solid #10b981;"
    )

    st.markdown(f"""
    <div class="soc-header">
        <div>
            <div class="soc-title">🛡️ {title}</div>
            <div class="soc-subtitle" style="color: {subtitle_color}; font-size: 0.9rem; margin-top: 4px;">{subtitle}</div>
        </div>
        <div>
            <span class="soc-badge" style="{badge_style}">● ZERO-TRUST ACTIVE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
