from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

DATA_PATH = Path(os.getenv("OT_PUBLIC_DATA_PATH", ROOT / "data" / "demo_events.jsonl"))

st.set_page_config(
    page_title="OT Sentinel | ICS Threat Observatory",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Manrope', sans-serif; }
.stApp { background: radial-gradient(circle at 70% 0%, #16212c 0, #0b1118 36%, #080c11 100%); }
[data-testid="stSidebar"] { background: rgba(13,20,28,.97); border-right: 1px solid #263746; }
[data-testid="stMetric"] { background: linear-gradient(145deg, rgba(21,31,42,.94), rgba(13,21,29,.94)); border: 1px solid #2a3d4a; border-radius: 12px; padding: 16px 18px; }
[data-testid="stMetricValue"] { font-family: 'DM Mono', monospace; color: #edf3f8; }
.eyebrow { color:#6f9fc4; font-family:'DM Mono',monospace; letter-spacing:.14em; text-transform:uppercase; font-size:.72rem; }
.hero { padding: 1.1rem 0 1.2rem; border-bottom:1px solid #263746; margin-bottom:1.3rem; }
.hero h1 { font-size:2.35rem; letter-spacing:-.045em; margin:.3rem 0 .25rem; color:#f3f6f9; }
.hero p { color:#9caebb; max-width:780px; margin:0; font-size:.98rem; }
.author-line { color:#728696; font-size:.78rem; margin-top:.6rem; }
.author-line a, .footer-note a { color:#8eb2cf; text-decoration:none; }
.author-line a:hover, .footer-note a:hover { text-decoration:underline; }
.demo-banner { border:1px solid #806a2d; background:rgba(89,67,14,.22); color:#f1d98a; padding:.72rem 1rem; border-radius:9px; font-size:.88rem; margin:.4rem 0 1.2rem; }
.live-banner { border:1px solid #436b80; background:rgba(37,70,89,.22); color:#a9c6d8; padding:.72rem 1rem; border-radius:9px; font-size:.88rem; margin:.4rem 0 1.2rem; }
.section-title { font-size:1.05rem; font-weight:650; color:#e8edf2; margin-top:.55rem; }
.technique { border-left:3px solid #6f9fc4; background:rgba(19,28,38,.78); padding:.75rem .9rem; margin:.5rem 0; border-radius:0 8px 8px 0; }
.technique .id { color:#6f9fc4; font-family:'DM Mono',monospace; font-size:.76rem; }
.technique .name { color:#eef3f7; font-weight:650; margin-top:.16rem; }
.technique .meta { color:#8599a8; font-size:.78rem; margin-top:.16rem; }
.footer-note { color:#728696; font-size:.74rem; border-top:1px solid #22303d; margin-top:2rem; padding-top:1rem; }
div[data-testid="stDataFrame"] { border:1px solid #2a3a46; border-radius:10px; overflow:hidden; }
.stTabs [data-baseweb="tab-list"] { gap:1.25rem; border-bottom:1px solid #253443; }
.stTabs [data-baseweb="tab"] { font-family:'DM Mono',monospace; font-size:.78rem; }
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner=False)
def load_events(path: str, mtime: float) -> pd.DataFrame:
    del mtime
    records: list[dict] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    frame = pd.json_normalize(records)
    frame["observed_at"] = pd.to_datetime(frame["observed_at"], utc=True, errors="coerce")
    frame["technique_ids"] = frame.get("techniques", pd.Series([[]] * len(frame))).apply(
        lambda items: [item.get("technique_id", "") for item in items or []]
    )
    frame["technique_names"] = frame.get("techniques", pd.Series([[]] * len(frame))).apply(
        lambda items: [item.get("name", "") for item in items or []]
    )
    return frame


def flatten_techniques(frame: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict] = []
    for _, event in frame.iterrows():
        for technique in event.get("techniques", []) or []:
            rows.append(
                {
                    "technique_id": technique.get("technique_id"),
                    "name": technique.get("name"),
                    "tactic": technique.get("tactic"),
                    "confidence": technique.get("confidence"),
                    "observed_at": event["observed_at"],
                    "protocol": event.get("protocol"),
                }
            )
    return pd.DataFrame(rows)


def technique_cards(techniques: pd.DataFrame) -> None:
    if techniques.empty:
        st.info("No technique hypotheses match the current filters.")
        return
    summary = (
        techniques.groupby(["technique_id", "name", "tactic"], dropna=False)
        .size()
        .reset_index(name="events")
        .sort_values("events", ascending=False)
    )
    for row in summary.head(6).itertuples():
        st.markdown(
            f"<div class='technique'><div class='id'>{row.technique_id} · {row.events} OBSERVATIONS</div>"
            f"<div class='name'>{row.name}</div><div class='meta'>{row.tactic} · evidence-qualified hypothesis</div></div>",
            unsafe_allow_html=True,
        )


if not DATA_PATH.exists():
    st.error(f"Dataset not found: {DATA_PATH}")
    st.stop()

df = load_events(str(DATA_PATH), DATA_PATH.stat().st_mtime)
is_demo = bool(df.get("is_demo", pd.Series([False])).fillna(False).all())

st.markdown(
    """
<div class="hero">
  <div class="eyebrow">ICS THREAT RESEARCH / UAE SENSOR PROGRAM</div>
  <h1>OT Sentinel</h1>
  <p>A low-interaction observatory for Modbus, S7 and IEC-104 activity, with evidence-aware MITRE ATT&amp;CK for ICS mapping.</p>
  <div class="author-line">Project by <a href="https://github.com/Afnan16312" target="_blank">Mir Afnan Ali · @Afnan16312</a></div>
</div>
""",
    unsafe_allow_html=True,
)

if is_demo:
    st.markdown(
        "<div class='demo-banner'><b>DEMONSTRATION DATA</b> — Every event in this public build is synthetic. It validates the full analysis pipeline but is not presented as observed attacker activity.</div>",
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        "<div class='live-banner'><b>SANITIZED OBSERVATIONS</b> — Source identifiers are pseudonymized and payload content is excluded from this public view.</div>",
        unsafe_allow_html=True,
    )

with st.sidebar:
    st.markdown("<div class='eyebrow'>VIEW CONTROLS</div>", unsafe_allow_html=True)
    protocols = sorted(df["protocol"].dropna().unique().tolist())
    selected_protocols = st.multiselect("Protocols", protocols, default=protocols)
    severities = [item for item in ["high", "medium", "low", "info"] if item in df["severity"].unique()]
    selected_severity = st.multiselect("Severity", severities, default=severities)
    countries = sorted(df["source_country"].dropna().unique().tolist())
    selected_countries = st.multiselect("Source country", countries, default=countries)
    st.divider()
    st.markdown("<div class='eyebrow'>SENSOR POSTURE</div>", unsafe_allow_html=True)
    st.caption("Low interaction · no command execution · bounded payload capture · outbound denied")
    st.markdown("`MODBUS` 502/TCP")
    st.markdown("`S7COMM` 102/TCP")
    st.markdown("`IEC-104` 2404/TCP")

filtered = df[
    df["protocol"].isin(selected_protocols)
    & df["severity"].isin(selected_severity)
    & df["source_country"].isin(selected_countries)
].copy()
techniques = flatten_techniques(filtered)

events_count = len(filtered)
sessions = filtered["session_id"].nunique()
sources = filtered.get("source_id", filtered.get("source_ip", pd.Series(dtype=str))).nunique()
commands = filtered["decoded.operation"].isin(
    ["write_single", "write_multiple", "single_command", "setpoint_command", "program_download"]
).sum()

m1, m2, m3, m4 = st.columns(4)
m1.metric("Protocol events", f"{events_count:,}")
m2.metric("Distinct sessions", f"{sessions:,}")
m3.metric("Pseudonymous sources", f"{sources:,}")
m4.metric("Control attempts", f"{commands:,}", help="Requests containing a write, command, or program-transfer operation")

overview, attack_tab, sessions_tab, methodology = st.tabs(
    ["OBSERVATORY", "ATT&CK LAYER", "SESSION EXPLORER", "METHODOLOGY"]
)

with overview:
    left, right = st.columns([1.55, 1], gap="large")
    with left:
        st.markdown("<div class='section-title'>Global source distribution</div>", unsafe_allow_html=True)
        geo = (
            filtered.dropna(subset=["source_latitude", "source_longitude"])
            .groupby(["source_country", "source_latitude", "source_longitude", "protocol"])
            .size()
            .reset_index(name="events")
        )
        fig = px.scatter_geo(
            geo,
            lat="source_latitude",
            lon="source_longitude",
            size="events",
            color="protocol",
            hover_name="source_country",
            projection="natural earth",
            color_discrete_map={"modbus": "#6F9FC4", "s7": "#C59A5B", "iec104": "#8D82B8"},
        )
        fig.update_geos(
            showland=True,
            landcolor="#151f2a",
            showocean=True,
            oceancolor="#0b1118",
            showcountries=True,
            countrycolor="#354758",
            showframe=False,
            bgcolor="rgba(0,0,0,0)",
        )
        fig.update_layout(
            margin={"l": 0, "r": 0, "t": 10, "b": 0},
            height=390,
            paper_bgcolor="rgba(0,0,0,0)",
            legend_title_text="",
        )
        st.plotly_chart(fig, use_container_width=True)
    with right:
        st.markdown("<div class='section-title'>Top ATT&CK hypotheses</div>", unsafe_allow_html=True)
        technique_cards(techniques)

    st.markdown("<div class='section-title'>Activity cadence</div>", unsafe_allow_html=True)
    timeline = (
        filtered.set_index("observed_at")
        .groupby("protocol")
        .resample("6h")
        .size()
        .reset_index(name="events")
    )
    line = px.area(
        timeline,
        x="observed_at",
        y="events",
        color="protocol",
        color_discrete_map={"modbus": "#6F9FC4", "s7": "#C59A5B", "iec104": "#8D82B8"},
    )
    line.update_traces(line_width=1.4)
    line.update_layout(
        height=260,
        margin={"l": 0, "r": 0, "t": 10, "b": 0},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend_title_text="",
        xaxis_title="",
        yaxis_title="Events / 6h",
    )
    line.update_xaxes(gridcolor="#22384a")
    line.update_yaxes(gridcolor="#22384a")
    st.plotly_chart(line, use_container_width=True)

with attack_tab:
    st.markdown("<div class='section-title'>Technique intensity by protocol</div>", unsafe_allow_html=True)
    if techniques.empty:
        st.info("No mapped behaviors match the current filters.")
    else:
        matrix = techniques.groupby(["technique_id", "name", "protocol"]).size().reset_index(name="events")
        matrix["label"] = matrix["technique_id"] + " · " + matrix["name"]
        pivot = matrix.pivot_table(index="label", columns="protocol", values="events", fill_value=0)
        heat = go.Figure(
            data=go.Heatmap(
                z=pivot.values,
                x=pivot.columns,
                y=pivot.index,
                colorscale=[[0, "#111820"], [0.35, "#324e67"], [1, "#6f9fc4"]],
                hovertemplate="%{y}<br>%{x}: %{z} observations<extra></extra>",
            )
        )
        heat.update_layout(
            height=max(330, len(pivot) * 58),
            margin={"l": 0, "r": 0, "t": 20, "b": 0},
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            xaxis_title="Protocol",
            yaxis_title="",
        )
        st.plotly_chart(heat, use_container_width=True)
        st.caption(
            "Counts represent telemetry matches, not unique intrusions. Confidence and rationale remain attached to each event."
        )

with sessions_tab:
    st.markdown("<div class='section-title'>Sanitized event ledger</div>", unsafe_allow_html=True)
    display = filtered.copy()
    display["techniques"] = display["technique_ids"].apply(lambda value: ", ".join(value) or "—")
    display["operation"] = display.get("decoded.operation", "unknown")
    display["source"] = display.get("source_id", display.get("source_ip", "redacted"))
    columns = ["observed_at", "source", "source_country", "source_asn", "protocol", "operation", "severity", "techniques", "session_id"]
    st.dataframe(
        display[columns].sort_values("observed_at", ascending=False),
        use_container_width=True,
        hide_index=True,
        column_config={"observed_at": st.column_config.DatetimeColumn("Observed (UTC)", format="YYYY-MM-DD HH:mm:ss")},
    )

with methodology:
    c1, c2 = st.columns(2, gap="large")
    with c1:
        st.markdown("### What the sensor does")
        st.markdown(
            """
- Emulates bounded fragments of Modbus/TCP, ISO-on-TCP/S7 and IEC-60870-5-104.
- Records connection metadata and at most 512 payload bytes.
- Parses protocol functions without executing instructions or changing a real process.
- Assigns ATT&CK hypotheses only when protocol evidence supports them.
- Keeps raw telemetry private and publishes pseudonymized, payload-free events.
"""
        )
    with c2:
        st.markdown("### What the data cannot prove")
        st.markdown(
            """
- IP geolocation does not establish an operator's physical location or identity.
- An open-port probe does not prove exploitation or compromise.
- Honeypot traffic is not representative of every UAE organization or ICS environment.
- Technique mappings are analyst hypotheses with explicit confidence, not attribution.
- This research does not demonstrate regulatory compliance.
"""
        )

st.markdown(
    "<div class='footer-note'>Project by <a href='https://github.com/Afnan16312' target='_blank'>Mir Afnan Ali (@Afnan16312)</a> · OT Sentinel research build 0.1.0 · Times shown in UTC · MITRE ATT&CK® is a registered trademark of The MITRE Corporation.</div>",
    unsafe_allow_html=True,
)
