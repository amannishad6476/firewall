import streamlit as st

HIDE_SIDEBAR_CSS = """
<style>
    /* Hide Streamlit default sidebar and sidebar navigation elements */
    [data-testid="stSidebar"],
    [data-testid="stSidebarNav"],
    [data-testid="collapsedControl"],
    section[data-testid="stSidebar"] {
        display: none !important;
        visibility: hidden !important;
        width: 0px !important;
        margin-left: -500px !important;
    }

    /* Expand main content area to utilize full width without sidebar padding */
    .stMainBlockContainer,
    .block-container,
    [data-testid="stMainBlockContainer"],
    [data-testid="stAppViewBlockContainer"] {
        padding-top: 1rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        max-width: 100% !important;
    }

    /* Styling for top navbar container */
    .top-navbar-wrapper {
        margin-bottom: 1.25rem;
        padding: 0.6rem 0.85rem;
        border-radius: 10px;
        backdrop-filter: blur(8px);
    }
</style>
"""

CYBER_DARK_CSS = """
<style>
    /* Dark Theme (Default) */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Top navbar container styling - Dark */
    .top-navbar-wrapper {
        background: #111827 !important;
        border: 1px solid #1f2937 !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -2px rgba(0, 0, 0, 0.3) !important;
    }

    /* Top navbar page links/buttons styling - Dark */
    .top-navbar-wrapper [data-testid="stPageLink"],
    .top-navbar-wrapper [data-testid="stPageLink"] a,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"] {
        background-color: #1f2937 !important;
        border: 1px solid #374151 !important;
        border-radius: 6px !important;
        font-size: 0.82rem !important;
        font-weight: 500 !important;
        text-decoration: none !important;
        transition: all 0.15s ease-in-out !important;
    }
    .top-navbar-wrapper [data-testid="stPageLink"] *,
    .top-navbar-wrapper [data-testid="stPageLink"] a *,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"] * {
        color: #cbd5e1 !important;
    }
    .top-navbar-wrapper [data-testid="stPageLink"]:hover,
    .top-navbar-wrapper [data-testid="stPageLink"] a:hover,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"]:hover {
        background-color: #312e81 !important;
        border-color: #4f46e5 !important;
    }
    .top-navbar-wrapper [data-testid="stPageLink"]:hover *,
    .top-navbar-wrapper [data-testid="stPageLink"] a:hover *,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"]:hover * {
        color: #ffffff !important;
    }
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"][aria-current="page"],
    .top-navbar-wrapper [data-testid="stPageLink"] a[aria-current="page"] {
        background-color: #4338ca !important;
        border-color: #6366f1 !important;
        box-shadow: 0 0 10px rgba(99, 102, 241, 0.4) !important;
    }
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"][aria-current="page"] *,
    .top-navbar-wrapper [data-testid="stPageLink"] a[aria-current="page"] * {
        color: #ffffff !important;
        font-weight: 700 !important;
    }

    /* Top navbar fallback buttons & theme toggle button - Dark */
    .top-navbar-wrapper .stButton > button {
        background-color: #1f2937 !important;
        color: #f8fafc !important;
        border: 1px solid #374151 !important;
        font-weight: 600 !important;
        border-radius: 6px !important;
        font-size: 0.82rem !important;
    }
    .top-navbar-wrapper .stButton > button * {
        color: #f8fafc !important;
    }
    .top-navbar-wrapper .stButton > button:hover {
        background-color: #312e81 !important;
        border-color: #6366f1 !important;
        color: #ffffff !important;
    }
    .top-navbar-wrapper .stButton > button:hover * {
        color: #ffffff !important;
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

    /* Dark Mode Textarea / Editor High Contrast */
    textarea,
    .stTextArea textarea,
    [data-baseweb="textarea"] textarea {
        background-color: #0f172a !important;
        color: #f8fafc !important;
        border: 1px solid #334155 !important;
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace !important;
        font-size: 0.88rem !important;
        line-height: 1.5 !important;
        border-radius: 6px !important;
        spellcheck: false;
        -webkit-spell-check: false;
    }
    textarea:focus,
    .stTextArea textarea:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 1px #6366f1 !important;
    }

    /* Tabs Styling - Dark Mode */
    [data-baseweb="tab-list"] {
        border-bottom: 1px solid #1f2937 !important;
    }
    [data-baseweb="tab"] {
        color: #94a3b8 !important;
        font-weight: 500 !important;
    }
    [data-baseweb="tab"][aria-selected="true"] {
        color: #818cf8 !important;
        border-bottom-color: #6366f1 !important;
        font-weight: 700 !important;
    }

    /* Approval Card styles - Dark Mode */
    .approval-card {
        background: #111827;
        border: 1px solid #374151;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 16px;
    }
    .approval-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .approval-op-title {
        font-size: 1.1rem;
        font-weight: 700;
        color: #f9fafb;
    }
    .approval-op-title code {
        background-color: #1f2937;
        color: #a5b4fc;
        padding: 2px 6px;
        border-radius: 4px;
    }
    .approval-meta {
        margin-top: 8px;
        font-size: 0.85rem;
        color: #94a3b8;
    }
    .approval-meta code {
        background-color: #1f2937;
        color: #e2e8f0;
        padding: 2px 6px;
        border-radius: 4px;
    }
    .approval-reason {
        margin-top: 10px;
        font-size: 0.9rem;
        color: #e5e7eb;
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
    
    /* Top navbar container styling - Light */
    .top-navbar-wrapper {
        background: #ffffff !important;
        border: 1px solid #cbd5e1 !important;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.06) !important;
    }

    /* Top navbar page links styling - Light Mode */
    .top-navbar-wrapper [data-testid="stPageLink"],
    .top-navbar-wrapper [data-testid="stPageLink"] a,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"] {
        background-color: #f1f5f9 !important;
        border: 1px solid #cbd5e1 !important;
        border-radius: 6px !important;
        font-size: 0.82rem !important;
        font-weight: 600 !important;
        text-decoration: none !important;
        transition: all 0.15s ease-in-out !important;
    }
    
    /* Ensure all text, paragraphs, labels and spans inside navbar links are crisp dark #0f172a */
    .top-navbar-wrapper [data-testid="stPageLink"] *,
    .top-navbar-wrapper [data-testid="stPageLink"] a *,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"] *,
    .top-navbar-wrapper [data-testid="stPageLink"] p,
    .top-navbar-wrapper [data-testid="stPageLink"] span,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"] p,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"] span {
        color: #0f172a !important;
        font-weight: 600 !important;
    }

    /* Top navbar link hover - Light Mode */
    .top-navbar-wrapper [data-testid="stPageLink"]:hover,
    .top-navbar-wrapper [data-testid="stPageLink"] a:hover,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"]:hover {
        background-color: #e2e8f0 !important;
        border-color: #4f46e5 !important;
    }
    .top-navbar-wrapper [data-testid="stPageLink"]:hover *,
    .top-navbar-wrapper [data-testid="stPageLink"] a:hover *,
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"]:hover * {
        color: #4338ca !important;
    }

    /* Active Page in Top Navbar - Light Mode */
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"][aria-current="page"],
    .top-navbar-wrapper [data-testid="stPageLink"] a[aria-current="page"] {
        background-color: #4338ca !important;
        border-color: #3730a3 !important;
        box-shadow: 0 0 8px rgba(67, 56, 202, 0.35) !important;
    }
    .top-navbar-wrapper div[data-testid="stPageLink-NavLink"][aria-current="page"] *,
    .top-navbar-wrapper [data-testid="stPageLink"] a[aria-current="page"] * {
        color: #ffffff !important;
        font-weight: 700 !important;
    }

    /* Top navbar fallback buttons & Theme Toggle Button in Light Mode */
    .top-navbar-wrapper .stButton > button {
        background-color: #ffffff !important;
        color: #0f172a !important;
        border: 1px solid #94a3b8 !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-size: 0.82rem !important;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05) !important;
    }
    .top-navbar-wrapper .stButton > button * {
        color: #0f172a !important;
        font-weight: 600 !important;
    }
    .top-navbar-wrapper .stButton > button:hover {
        background-color: #f1f5f9 !important;
        border-color: #4f46e5 !important;
        color: #4338ca !important;
    }
    .top-navbar-wrapper .stButton > button:hover * {
        color: #4338ca !important;
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

    /* Approval Card styles - Light Mode */
    .approval-card {
        background: #ffffff !important;
        border: 1px solid #cbd5e1 !important;
        border-radius: 8px !important;
        padding: 18px !important;
        margin-bottom: 16px !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06) !important;
    }
    .approval-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .approval-op-title {
        font-size: 1.1rem !important;
        font-weight: 700 !important;
        color: #0f172a !important;
    }
    .approval-op-title code {
        background-color: #f1f5f9 !important;
        color: #3730a3 !important;
        border: 1px solid #e2e8f0 !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
    }
    .approval-meta {
        margin-top: 8px !important;
        font-size: 0.85rem !important;
        color: #475569 !important;
    }
    .approval-meta code {
        background-color: #f1f5f9 !important;
        color: #1e293b !important;
        border: 1px solid #e2e8f0 !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
    }
    .approval-reason {
        margin-top: 10px !important;
        font-size: 0.9rem !important;
        color: #1e293b !important;
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

    /* Light Mode Textarea / YAML Editor - Crisp Light Surface with Dark High-Contrast Text */
    textarea,
    .stTextArea textarea,
    [data-baseweb="textarea"] textarea {
        background-color: #ffffff !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace !important;
        font-size: 0.88rem !important;
        line-height: 1.5 !important;
        border-radius: 6px !important;
        spellcheck: false;
        -webkit-spell-check: false;
        box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.04);
    }
    textarea:focus,
    .stTextArea textarea:focus {
        border-color: #4f46e5 !important;
        box-shadow: 0 0 0 1px #4f46e5 !important;
    }

    /* Tabs Styling - Light Mode */
    [data-baseweb="tab-list"] {
        border-bottom: 1px solid #cbd5e1 !important;
    }
    [data-baseweb="tab"] {
        color: #475569 !important;
        font-weight: 500 !important;
    }
    [data-baseweb="tab"]:hover {
        color: #0f172a !important;
    }
    [data-baseweb="tab"][aria-selected="true"] {
        color: #4338ca !important;
        border-bottom-color: #4f46e5 !important;
        font-weight: 700 !important;
    }

    /* General Buttons in Light Mode */
    .stButton > button {
        border: 1px solid #cbd5e1 !important;
        color: #0f172a !important;
        background-color: #ffffff !important;
        font-weight: 600 !important;
    }
    .stButton > button * {
        color: #0f172a !important;
    }
    .stButton > button:hover {
        border-color: #4f46e5 !important;
        color: #4338ca !important;
        background-color: #f1f5f9 !important;
    }
    .stButton > button:hover * {
        color: #4338ca !important;
    }
    
    /* Primary buttons (e.g. Approve Action) in Light Mode */
    .stButton > button[kind="primary"],
    .stButton > button[data-testid="baseButton-primary"] {
        background-color: #059669 !important;
        border-color: #047857 !important;
        color: #ffffff !important;
        font-weight: 700 !important;
    }
    .stButton > button[kind="primary"] *,
    .stButton > button[data-testid="baseButton-primary"] * {
        color: #ffffff !important;
    }
    .stButton > button[kind="primary"]:hover,
    .stButton > button[data-testid="baseButton-primary"]:hover {
        background-color: #047857 !important;
        border-color: #065f46 !important;
        color: #ffffff !important;
    }
    .stButton > button[kind="primary"]:hover *,
    .stButton > button[data-testid="baseButton-primary"]:hover * {
        color: #ffffff !important;
    }
    
    .stButton > button:active {
        background-color: #4f46e5 !important;
        color: #ffffff !important;
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

NAV_ITEMS = [
    {"label": "Home", "icon": "🛡️", "page": "app.py"},
    {"label": "Overview", "icon": "📊", "page": "pages/1_Security_Overview.py"},
    {"label": "Live Monitor", "icon": "📡", "page": "pages/2_Live_Monitor.py"},
    {"label": "Threats", "icon": "☣️", "page": "pages/3_Threat_Detection.py"},
    {"label": "Approvals", "icon": "⚖️", "page": "pages/4_Approval_Center.py"},
    {"label": "Policies", "icon": "📜", "page": "pages/5_Policy_Manager.py"},
    {"label": "Audit Logs", "icon": "📑", "page": "pages/6_Audit_Logs.py"},
    {"label": "Testing Lab", "icon": "🧪", "page": "pages/7_Security_Testing_Lab.py"},
]

def get_current_theme() -> str:
    """Returns the active theme mode safely."""
    try:
        if "dashboard_theme" not in st.session_state:
            st.session_state["dashboard_theme"] = "Dark"
        return st.session_state["dashboard_theme"]
    except Exception:
        return "Dark"

def render_top_navbar(active_page: str = "app.py"):
    """
    Renders a sleek top horizontal navigation bar across all pages
    with navigation links and the Dark/Light theme switcher.
    """
    st.markdown(HIDE_SIDEBAR_CSS, unsafe_allow_html=True)

    theme = get_current_theme()
    if theme == "Light":
        st.markdown(CYBER_LIGHT_CSS, unsafe_allow_html=True)
    else:
        st.markdown(CYBER_DARK_CSS, unsafe_allow_html=True)

    # Render top navbar layout: 8 nav columns + 1 theme toggle column
    with st.container():
        st.markdown('<div class="top-navbar-wrapper">', unsafe_allow_html=True)
        cols = st.columns([1.1, 1.2, 1.3, 1.1, 1.2, 1.1, 1.2, 1.3, 1.4])
        
        for idx, item in enumerate(NAV_ITEMS):
            with cols[idx]:
                try:
                    st.page_link(
                        page=item["page"],
                        label=item["label"],
                        icon=item["icon"],
                        use_container_width=True
                    )
                except Exception:
                    # Fallback for environments where page_link paths differ
                    if st.button(f"{item['icon']} {item['label']}", key=f"nav_btn_{idx}", use_container_width=True):
                        try:
                            st.switch_page(item["page"])
                        except Exception:
                            pass
        
        with cols[-1]:
            current_theme = get_current_theme()
            is_dark = (current_theme == "Dark")
            toggle_label = "🌙 Dark" if is_dark else "☀️ Light"
            if st.button(toggle_label, key="_top_navbar_theme_toggle", use_container_width=True, help="Toggle Dark/Light Mode"):
                st.session_state["dashboard_theme"] = "Light" if is_dark else "Dark"
                st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)

def apply_cyber_theme(active_page: str = "app.py"):
    """Applies theme and top horizontal navigation bar."""
    if "dashboard_theme" not in st.session_state:
        st.session_state["dashboard_theme"] = "Dark"
    render_top_navbar(active_page=active_page)

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
