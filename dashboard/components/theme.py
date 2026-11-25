import streamlit as st

CYBER_DARK_CSS = """
<style>
    /* Dark SOC Theme styling */
    .stApp {
        background-color: #0b0f19;
        color: #f8fafc;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Streamlit KPI Metric Cards */
    [data-testid="stMetric"] {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 14px 18px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    }
    [data-testid="stMetricValue"] {
        color: #f8fafc !important;
        font-size: 2rem !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em;
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
