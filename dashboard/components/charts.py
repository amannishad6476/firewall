import plotly.graph_objects as go
import plotly.express as px
from typing import List, Dict, Any

def create_decision_pie_chart(allowed: int, blocked: int, pending: int) -> go.Figure:
    labels = ["ALLOW", "BLOCK", "ASK_HUMAN"]
    values = [allowed, blocked, pending]
    colors = ["#10b981", "#ef4444", "#f59e0b"]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.58,
        marker=dict(colors=colors, line=dict(color='#0b0f19', width=2)),
        textinfo='percent',
        textposition='inside',
        insidetextorientation='horizontal',
        textfont=dict(color='#ffffff', size=13, family='sans-serif'),
        hovertemplate="<b>%{label}</b>: %{value} actions (%{percent})<extra></extra>"
    )])

    fig.update_layout(
        title="Firewall Enforcement Distribution",
        title_font=dict(color="#f8fafc", size=15),
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        font=dict(color="#cbd5e1"),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.22,
            xanchor="center",
            x=0.5,
            font=dict(size=12, color="#cbd5e1")
        ),
        margin=dict(t=40, b=50, l=20, r=20),
        height=290
    )
    return fig

def create_risk_distribution_chart(events: List[Dict[str, Any]]) -> go.Figure:
    if not events:
        scores = [0.1, 0.4, 0.85]
    else:
        scores = [e.get("calculated_risk", 0.0) for e in events]

    fig = go.Figure(data=[go.Histogram(
        x=scores,
        nbinsx=10,
        marker_color="#6366f1",
        marker_line=dict(width=1, color="#312e81")
    )])

    fig.update_layout(
        title="Risk Score Distribution [0.0 - 1.0]",
        title_font=dict(color="#f8fafc", size=15),
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        font=dict(color="#cbd5e1"),
        xaxis=dict(title="Normalized Risk Score", gridcolor="#1f2937", range=[0, 1], title_font=dict(color="#94a3b8")),
        yaxis=dict(title="Frequency", gridcolor="#1f2937", title_font=dict(color="#94a3b8")),
        margin=dict(t=40, b=50, l=40, r=20),
        height=290
    )
    return fig

def create_action_bar_chart(events: List[Dict[str, Any]]) -> go.Figure:
    actions_count: Dict[str, int] = {}
    for e in events:
        act = e.get("action_type", "unknown")
        actions_count[act] = actions_count.get(act, 0) + 1

    x = list(actions_count.keys()) or ["read_webpage", "read_file", "send_email", "delete_file"]
    y = list(actions_count.values()) or [1, 1, 1, 0]

    fig = go.Figure(data=[go.Bar(
        x=x,
        y=y,
        marker_color="#38bdf8",
        marker_line=dict(color="#0284c7", width=1.5)
    )])

    fig.update_layout(
        title="Protected Tool Executions by Type",
        title_font=dict(color="#f8fafc", size=15),
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        font=dict(color="#cbd5e1"),
        xaxis=dict(gridcolor="#1f2937"),
        yaxis=dict(title="Invocations", gridcolor="#1f2937", title_font=dict(color="#94a3b8")),
        margin=dict(t=40, b=50, l=40, r=20),
        height=290
    )
    return fig
