import plotly.graph_objects as go
import plotly.express as px
from typing import List, Dict, Any
from .theme import get_current_theme

def _chart_theme_colors():
    is_light = (get_current_theme() == "Light")
    if is_light:
        return {
            "bg": "#ffffff",
            "title": "#0f172a",
            "text": "#334155",
            "grid": "#e2e8f0",
            "donut_border": "#ffffff",
            "hist_marker": "#6366f1",
            "hist_line": "#4338ca",
            "bar_marker": "#0284c7",
            "bar_line": "#0369a1"
        }
    return {
        "bg": "#111827",
        "title": "#f8fafc",
        "text": "#cbd5e1",
        "grid": "#1f2937",
        "donut_border": "#0b0f19",
        "hist_marker": "#6366f1",
        "hist_line": "#312e81",
        "bar_marker": "#38bdf8",
        "bar_line": "#0284c7"
    }

def create_decision_pie_chart(allowed: int, blocked: int, pending: int) -> go.Figure:
    c = _chart_theme_colors()
    labels = ["ALLOW", "BLOCK", "ASK_HUMAN"]
    values = [allowed, blocked, pending]
    colors = ["#10b981", "#ef4444", "#f59e0b"]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color=c["donut_border"], width=2)),
        textinfo='percent',
        insidetextorientation='horizontal',
        textfont=dict(color='#ffffff', size=13),
        hovertemplate="<b>%{label}</b>: %{value} actions (%{percent})<extra></extra>"
    )])

    fig.update_layout(
        title="Firewall Enforcement Distribution",
        title_font=dict(color=c["title"], size=15),
        paper_bgcolor=c["bg"],
        plot_bgcolor=c["bg"],
        font=dict(color=c["text"]),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.22,
            xanchor="center",
            x=0.5,
            font=dict(size=12, color=c["text"])
        ),
        margin=dict(t=40, b=50, l=20, r=20),
        height=280
    )
    return fig

def create_risk_distribution_chart(events: List[Dict[str, Any]]) -> go.Figure:
    c = _chart_theme_colors()
    if not events:
        scores = [0.1, 0.4, 0.85]
    else:
        scores = [e.get("calculated_risk", 0.0) for e in events]

    fig = go.Figure(data=[go.Histogram(
        x=scores,
        nbinsx=10,
        marker_color=c["hist_marker"],
        marker_line=dict(width=1, color=c["hist_line"])
    )])

    fig.update_layout(
        title="Risk Score Distribution [0.0 - 1.0]",
        title_font=dict(color=c["title"], size=15),
        paper_bgcolor=c["bg"],
        plot_bgcolor=c["bg"],
        font=dict(color=c["text"]),
        xaxis=dict(title="Normalized Risk Score", gridcolor=c["grid"], range=[0, 1]),
        yaxis=dict(title="Frequency", gridcolor=c["grid"]),
        margin=dict(t=40, b=40, l=40, r=20),
        height=280
    )
    return fig

def create_action_bar_chart(events: List[Dict[str, Any]]) -> go.Figure:
    c = _chart_theme_colors()
    actions_count: Dict[str, int] = {}
    for e in events:
        act = e.get("action_type", "unknown")
        actions_count[act] = actions_count.get(act, 0) + 1

    x = list(actions_count.keys()) or ["read_webpage", "read_file", "send_email", "delete_file"]
    y = list(actions_count.values()) or [1, 1, 1, 0]

    fig = go.Figure(data=[go.Bar(
        x=x,
        y=y,
        marker_color=c["bar_marker"],
        marker_line=dict(color=c["bar_line"], width=1.5)
    )])

    fig.update_layout(
        title="Protected Tool Executions by Type",
        title_font=dict(color=c["title"], size=15),
        paper_bgcolor=c["bg"],
        plot_bgcolor=c["bg"],
        font=dict(color=c["text"]),
        xaxis=dict(gridcolor=c["grid"]),
        yaxis=dict(title="Invocations", gridcolor=c["grid"]),
        margin=dict(t=40, b=40, l=40, r=20),
        height=280
    )
    return fig
