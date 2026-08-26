from __future__ import annotations

import json
import os
import sys
from datetime import timedelta
from html import escape
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from ot_sentinel.dashboard_map import (
    MAP_MODES,
    build_threat_map,
    filter_time_window,
    map_points_csv,
    map_quality,
    prepare_map_points,
    selection_from_plotly_state,
)
from ot_sentinel.detection_preview import preview_detections
from ot_sentinel.evaluation import evaluate_mapper, load_labeled_jsonl
from ot_sentinel.publication import (
    PublicationValidationError,
    load_public_jsonl,
    validate_public_stix_bundle,
)
from ot_sentinel.stix_export import export_events
from ot_sentinel.triage import assess_event, factor_summary

DATA_PATH = Path(os.getenv("OT_PUBLIC_DATA_PATH", ROOT / "data" / "demo_events.jsonl"))
EVALUATION_FIXTURE = ROOT / "tests" / "fixtures" / "evaluation" / "mapper_cases.jsonl"

st.set_page_config(
    page_title="OT Sentinel | ICS Threat Observatory",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="auto",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Manrope', sans-serif; }
.stApp { background:#090e13; }
[data-testid="stSidebar"] { background:#0d141b; border-right:1px solid #26343e; }
[data-testid="stMetric"] { background:#101820; border:1px solid #2a3944; border-radius:8px; padding:15px 17px; }
[data-testid="stMetricValue"] { font-family: 'DM Mono', monospace; color: #edf3f8; }
.eyebrow { color:#6f9fc4; font-family:'DM Mono',monospace; letter-spacing:.14em; text-transform:uppercase; font-size:.72rem; }
.hero { padding:.45rem 0 .65rem; border-bottom:1px solid #263746; margin-bottom:.75rem; }
.hero h1 { font-size:1.95rem; letter-spacing:-.04em; margin:.2rem 0 .18rem; color:#f3f6f9; }
.hero p { color:#9caebb; max-width:780px; margin:0; font-size:.9rem; }
.author-line { color:#728696; font-size:.75rem; margin-top:.38rem; }
.author-line a, .footer-note a { color:#8eb2cf; text-decoration:none; }
.author-line a:hover, .footer-note a:hover { text-decoration:underline; }
.demo-banner { border:1px solid #806a2d; background:rgba(89,67,14,.22); color:#f1d98a; padding:.55rem .85rem; border-radius:8px; font-size:.82rem; margin:.3rem 0 .75rem; }
.live-banner { border:1px solid #436b80; background:rgba(37,70,89,.22); color:#a9c6d8; padding:.55rem .85rem; border-radius:8px; font-size:.82rem; margin:.3rem 0 .75rem; }
.telemetry-strip { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:1px; background:#2a3944; border:1px solid #2a3944; border-radius:9px; overflow:hidden; margin:.1rem 0 .85rem; }
.telemetry-cell { background:#101820; padding:.72rem .85rem; min-width:0; }
.telemetry-label { color:#7f919e; font-size:.68rem; text-transform:uppercase; letter-spacing:.075em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.telemetry-value { color:#edf3f8; font-family:'DM Mono',monospace; font-size:1.15rem; line-height:1.25; margin-top:.16rem; }
.section-title { font-size:1.05rem; font-weight:650; color:#e8edf2; margin-top:.55rem; }
.technique { border-left:3px solid #6f9fc4; background:rgba(19,28,38,.78); padding:.75rem .9rem; margin:.5rem 0; border-radius:0 8px 8px 0; }
.technique .id { color:#6f9fc4; font-family:'DM Mono',monospace; font-size:.76rem; }
.technique .name { color:#eef3f7; font-weight:650; margin-top:.16rem; }
.technique .meta { color:#8599a8; font-size:.78rem; margin-top:.16rem; }
.footer-note { color:#728696; font-size:.74rem; border-top:1px solid #22303d; margin-top:2rem; padding-top:1rem; }
div[data-testid="stDataFrame"] { border:1px solid #2a3a46; border-radius:10px; overflow:hidden; }
.stTabs [data-baseweb="tab-list"] { gap:1.25rem; border-bottom:1px solid #253443; }
.stTabs [data-baseweb="tab"] { font-family:'DM Mono',monospace; font-size:.78rem; }
.map-shell { background:#0b1117; border:1px solid #2a3944; border-radius:10px; padding:.8rem .9rem .35rem; }
.map-kicker { color:#7898ad; font-family:'DM Mono',monospace; letter-spacing:.09em; text-transform:uppercase; font-size:.68rem; }
.map-title { color:#eef3f6; font-size:1.18rem; font-weight:650; margin:.18rem 0 .15rem; }
.map-copy { color:#8ea0ad; font-size:.82rem; margin:0 0 .75rem; max-width:850px; }
.map-stat-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:1px; background:#26343e; border:1px solid #26343e; border-radius:8px; overflow:hidden; margin:.2rem 0 .8rem; }
.map-stat { background:#0f171e; padding:.65rem .75rem; }
.map-stat .label { color:#758896; font-size:.68rem; text-transform:uppercase; letter-spacing:.08em; }
.map-stat .value { color:#edf2f5; font-family:'DM Mono',monospace; font-size:.94rem; margin-top:.12rem; }
.detail-panel { background:#0f171e; border:1px solid #2a3944; border-radius:9px; padding:.9rem 1rem; min-height:210px; }
.detail-label { color:#758896; font-family:'DM Mono',monospace; font-size:.67rem; letter-spacing:.08em; text-transform:uppercase; }
.detail-value { color:#edf3f6; font-size:.9rem; margin:.18rem 0 .7rem; word-break:break-word; }
.privacy-note { color:#93a4b0; border-left:2px solid #586d7b; padding:.45rem .65rem; font-size:.76rem; margin-top:.65rem; }
@media (max-width:900px) {
  .telemetry-strip, .map-stat-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .telemetry-cell { padding:.62rem .7rem; }
  .telemetry-value { font-size:1rem; }
  .hero h1 { font-size:1.65rem; }
}
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner=False)
def load_events(path: str, mtime: float) -> tuple[list[dict], pd.DataFrame]:
    del mtime
    records = load_public_jsonl(path)
    frame = pd.json_normalize(records)
    frame["observed_at"] = pd.to_datetime(frame["observed_at"], utc=True, errors="coerce")
    frame["technique_ids"] = frame.get("techniques", pd.Series([[]] * len(frame))).apply(
        lambda items: [item.get("technique_id", "") for item in items or []]
    )
    frame["technique_names"] = frame.get("techniques", pd.Series([[]] * len(frame))).apply(
        lambda items: [item.get("name", "") for item in items or []]
    )
    return records, frame


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


def build_triage_queue(frame: pd.DataFrame) -> pd.DataFrame:
    """Create an explainable review queue from normalized dashboard rows."""
    rows: list[dict] = []
    decoded_columns = [column for column in frame.columns if column.startswith("decoded.")]
    for _, event in frame.iterrows():
        decoded = {
            column.removeprefix("decoded."): event[column]
            for column in decoded_columns
            if pd.notna(event[column])
        }
        assessment = assess_event(
            {
                "event_type": event.get("event_type"),
                "decoded": decoded,
                "techniques": event.get("techniques", []),
            }
        )
        rows.append(
            {
                "observed_at": event.get("observed_at"),
                "source": event.get("source_id", event.get("source_ip", "redacted")),
                "protocol": event.get("protocol"),
                "operation": decoded.get("operation", "unknown"),
                "score": assessment.score,
                "priority": assessment.priority,
                "evidence factors": factor_summary(assessment),
                "analyst note": assessment.analyst_note,
                "session_id": event.get("session_id"),
            }
        )
    return pd.DataFrame(rows)


@st.cache_data(show_spinner=False)
def load_evaluation(path: str, mtime: float) -> dict:
    del mtime
    return evaluate_mapper(load_labeled_jsonl(path)).to_dict()


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

try:
    public_records, df = load_events(str(DATA_PATH), DATA_PATH.stat().st_mtime)
except (OSError, PublicationValidationError):
    st.error("The public dataset failed the safety gate and will not be displayed.")
    st.stop()
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

pending_country = st.session_state.pop("_pending_country_filter", None)
if pending_country is not None:
    st.session_state["filter_countries"] = pending_country

with st.sidebar:
    st.markdown("<div class='eyebrow'>VIEW CONTROLS</div>", unsafe_allow_html=True)
    protocols = sorted(df["protocol"].dropna().unique().tolist())
    selected_protocols = st.multiselect(
        "Protocols", protocols, default=protocols, key="filter_protocols"
    )
    severities = [item for item in ["high", "medium", "low", "info"] if item in df["severity"].unique()]
    selected_severity = st.multiselect(
        "Severity", severities, default=severities, key="filter_severity"
    )
    countries = sorted(df["source_country"].dropna().unique().tolist())
    country_default = {"default": countries} if "filter_countries" not in st.session_state else {}
    selected_countries = st.multiselect(
        "Source country", countries, key="filter_countries", **country_default
    )
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

st.markdown(
    f"""
<div class="telemetry-strip" aria-label="Current filtered telemetry summary">
  <div class="telemetry-cell"><div class="telemetry-label">Protocol events</div><div class="telemetry-value">{events_count:,}</div></div>
  <div class="telemetry-cell"><div class="telemetry-label">Distinct sessions</div><div class="telemetry-value">{sessions:,}</div></div>
  <div class="telemetry-cell"><div class="telemetry-label">Pseudonymous sources</div><div class="telemetry-value">{sources:,}</div></div>
  <div class="telemetry-cell" title="Requests containing a write, command, or program-transfer operation"><div class="telemetry-label">Control attempts</div><div class="telemetry-value">{commands:,}</div></div>
</div>
""",
    unsafe_allow_html=True,
)

overview, attack_tab, detection_tab, triage_tab, sessions_tab, methodology = st.tabs(
    [
        "OBSERVATORY",
        "ATT&CK LAYER",
        "DETECTION PREVIEW",
        "TRIAGE & VALIDATION",
        "SESSION EXPLORER",
        "METHODOLOGY",
    ]
)

with overview:
    st.markdown(
        """
<div class="map-shell">
  <div class="map-kicker">Geographic investigation workspace</div>
  <div class="map-title">Global observation map</div>
  <p class="map-copy">Explore coarse public geolocation, compare protocol activity and select a source for a privacy-safe investigation summary.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    control1, control2, control3, control4, control5 = st.columns([1.25, 1.1, 1, 1.1, 0.8])
    map_mode = control1.selectbox("Map mode", MAP_MODES, key="map_mode")
    time_preset = control2.selectbox(
        "Observation window",
        ["All observations", "Last 24 hours", "Last 7 days", "Last 14 days"],
        key="map_window",
    )
    show_labels = control3.toggle("Place labels", value=False, key="map_labels")
    show_flows = control4.toggle(
        "Observation paths",
        value=True,
        disabled=map_mode != "Flow view",
        key="map_flows",
        help="Paths indicate network observations, not a proven physical attacker route.",
    )
    if control5.button("Reset camera", width="stretch"):
        st.session_state["_map_revision"] = st.session_state.get("_map_revision", 0) + 1

    map_frame = filtered.copy()
    latest_observation = map_frame["observed_at"].max() if not map_frame.empty else pd.NaT
    if pd.notna(latest_observation):
        window_durations = {
            "Last 24 hours": timedelta(hours=24),
            "Last 7 days": timedelta(days=7),
            "Last 14 days": timedelta(days=14),
        }
        duration = window_durations.get(time_preset)
        if duration is not None:
            map_frame = filter_time_window(map_frame, latest_observation - duration, latest_observation)

    map_points = prepare_map_points(map_frame)
    quality = map_quality(map_frame)
    source_count = int(map_points["source"].nunique()) if not map_points.empty else 0
    protocol_count = int(map_points["protocol"].nunique()) if not map_points.empty else 0
    st.markdown(
        f"""
<div class="map-stat-grid">
  <div class="map-stat"><div class="label">Visible events</div><div class="value">{quality['events']:,}</div></div>
  <div class="map-stat"><div class="label">Mapped sources</div><div class="value">{source_count:,}</div></div>
  <div class="map-stat"><div class="label">Countries</div><div class="value">{quality['countries']:,}</div></div>
  <div class="map-stat"><div class="label">Protocols active</div><div class="value">{protocol_count:,}</div></div>
</div>
""",
        unsafe_allow_html=True,
    )

    map_column, detail_column = st.columns([2.5, 0.9], gap="large")
    with map_column:
        if map_points.empty:
            st.info("No safely mappable observations match the current filters and time window.")
            map_selection = None
        else:
            map_style = "carto-darkmatter" if show_labels else "carto-darkmatter-nolabels"
            revision = f"ot-map-{st.session_state.get('_map_revision', 0)}"
            threat_map = build_threat_map(
                map_points,
                mode=map_mode,
                event_frame=map_frame,
                show_flows=show_flows,
                show_region=True,
                map_style=map_style,
                revision=revision,
            )
            map_state = st.plotly_chart(
                threat_map,
                width="stretch",
                key=f"interactive_threat_map_{map_mode}",
                on_select="rerun",
                selection_mode="points",
                config={
                    "displaylogo": False,
                    "scrollZoom": True,
                    "responsive": True,
                    "modeBarButtonsToRemove": ["lasso2d", "select2d"],
                },
            )
            map_selection = selection_from_plotly_state(map_state)
            if map_selection is not None:
                st.session_state["_selected_map_source"] = map_selection

        selected = map_selection or st.session_state.get("_selected_map_source")
        if selected:
            selection_visible = (
                not map_points.empty
                and (
                    (map_points["source"] == selected["source"])
                    & (map_points["protocol"] == selected["protocol"])
                ).any()
            )
            if not selection_visible:
                st.session_state.pop("_selected_map_source", None)
                selected = None
        st.caption(
            "White endpoint: approximate UAE sensor region. Map locations are deliberately coarse. "
            "Paths show observed network relationships; "
            "they do not prove attribution, travel, infrastructure ownership or operator location."
        )

    with detail_column:
        st.markdown("<div class='map-kicker'>Investigation summary</div>", unsafe_allow_html=True)
        if selected:
            safe = {key: escape(str(value)) for key, value in selected.items()}
            st.markdown(
                f"""
<div class="detail-panel">
  <div class="detail-label">Pseudonymous source</div><div class="detail-value"><code>{safe['source']}</code></div>
  <div class="detail-label">Country / protocol</div><div class="detail-value">{safe['country']} · {safe['protocol'].upper()}</div>
  <div class="detail-label">Observed activity</div><div class="detail-value">{safe['events']} events · {safe['sessions']} sessions · {safe['control_attempts']} control attempts</div>
  <div class="detail-label">Highest severity</div><div class="detail-value">{safe['max_severity'].upper()}</div>
  <div class="detail-label">Latest observation</div><div class="detail-value">{safe['last_seen']}</div>
  <div class="detail-label">ATT&amp;CK hypotheses</div><div class="detail-value">{safe['techniques']}</div>
  <div class="privacy-note">This panel contains reviewed public fields only. Raw IP addresses and payloads are never exposed.</div>
</div>
""",
                unsafe_allow_html=True,
            )
            if selected["country"] in countries and st.button(
                f"Filter dashboard to {selected['country']}", width="stretch"
            ):
                st.session_state["_pending_country_filter"] = [selected["country"]]
                st.rerun()
        elif not map_points.empty:
            top_point = map_points.iloc[0]
            st.markdown(
                f"""
<div class="detail-panel">
  <div class="detail-label">How to investigate</div><div class="detail-value">Select a source bubble to inspect its public evidence summary.</div>
  <div class="detail-label">Most active visible source</div><div class="detail-value"><code>{escape(str(top_point['source']))}</code></div>
  <div class="detail-label">Current concentration</div><div class="detail-value">{escape(str(top_point['country']))} · {int(top_point['events'])} events</div>
  <div class="privacy-note">Zoom, pan, switch layers or play the time sequence. Map interaction never changes the underlying evidence.</div>
</div>
""",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                "<div class='detail-panel'><div class='detail-label'>No mapped evidence</div>"
                "<div class='detail-value'>Change the filters or observation window.</div></div>",
                unsafe_allow_html=True,
            )

        st.download_button(
            "Export visible map summary",
            data=map_points_csv(map_points),
            file_name="ot-sentinel-map-summary.csv",
            mime="text/csv",
            width="stretch",
            disabled=map_points.empty,
            help="Exports coarse, aggregate and privacy-reviewed map fields only.",
        )
        if st.button("Show all countries", width="stretch", disabled=len(selected_countries) == len(countries)):
            st.session_state["_pending_country_filter"] = countries
            st.rerun()

    with st.expander("Map coverage and privacy audit"):
        st.write(
            f"{quality['plotted_events']:,} of {quality['events']:,} filtered events have valid "
            f"public coordinates; {quality['unmapped_events']:,} are excluded from the map."
        )
        st.write(
            "Coordinates are rounded before aggregation. The UAE marker represents a broad public "
            "region and is not the location of a cloud instance or sensor."
        )

    insight_left, insight_right = st.columns([1.15, 1], gap="large")
    with insight_left:
        st.markdown("<div class='section-title'>Top ATT&CK hypotheses</div>", unsafe_allow_html=True)
        technique_cards(flatten_techniques(map_frame))
    with insight_right:
        st.markdown("<div class='section-title'>Geographic concentration</div>", unsafe_allow_html=True)
        if map_frame.empty:
            st.info("No geographic summary is available for the current window.")
        else:
            concentration = (
                map_frame.groupby("source_country", dropna=False)
                .agg(events=("event_id", "count"), sessions=("session_id", "nunique"))
                .sort_values("events", ascending=False)
                .head(8)
                .reset_index()
                .rename(columns={"source_country": "country"})
            )
            st.dataframe(concentration, width="stretch", hide_index=True)

    st.markdown("<div class='section-title'>Activity cadence</div>", unsafe_allow_html=True)
    if map_frame.empty:
        st.info("No activity matches the current map window.")
    else:
        timeline = (
            map_frame.set_index("observed_at")
            .groupby("protocol")
            .resample("6h", include_groups=False)
            .size()
            .reset_index(name="events")
        )
        line = px.area(
            timeline,
            x="observed_at",
            y="events",
            color="protocol",
            color_discrete_map={"modbus": "#4E8FB8", "s7": "#C08A4E", "iec104": "#8175A8"},
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
        st.plotly_chart(line, width="stretch")

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
        st.plotly_chart(heat, width="stretch")
        st.caption(
            "Counts represent telemetry matches, not unique intrusions. Confidence and rationale remain attached to each event."
        )

    st.divider()
    st.markdown("<div class='section-title'>Public STIX 2.1 export</div>", unsafe_allow_html=True)
    try:
        public_stix = export_events(public_records, profile="public")
        validate_public_stix_bundle(public_stix)
    except (PublicationValidationError, ValueError):
        st.error("The STIX export failed the independent publication safety gate.")
    else:
        st.download_button(
            "Download validated public STIX bundle",
            data=json.dumps(public_stix, indent=2) + "\n",
            file_name="ot-sentinel-public-demo.stix.json",
            mime="application/json",
            help="Contains sanitized synthetic evidence only; raw addresses and payloads are excluded.",
        )

with detection_tab:
    st.markdown("<div class='section-title'>Detection Preview</div>", unsafe_allow_html=True)
    st.warning(
        "Offline prediction only. These matches use local rule logic and are not proof that a native Sigma, Wazuh or Suricata engine fired."
    )
    visible_event_ids = set(filtered["event_id"].astype(str))
    preview_records = [
        record for record in public_records if str(record.get("event_id", "")) in visible_event_ids
    ]
    predictions = [item.to_dict() for item in preview_detections(preview_records, root=ROOT)]
    if not predictions:
        st.info("No offline detection rule matches the current sanitized event filters.")
    else:
        preview_frame = pd.DataFrame(predictions)
        engines = sorted(preview_frame["engine"].unique())
        protocols_for_preview = sorted(preview_frame["protocol"].unique())
        rules_for_preview = sorted(preview_frame["rule_id"].unique())
        p1, p2, p3 = st.columns(3)
        selected_engines = p1.multiselect("Detection engine", engines, default=engines)
        selected_preview_protocols = p2.multiselect(
            "Detection protocol", protocols_for_preview, default=protocols_for_preview
        )
        selected_rules = p3.multiselect("Detection rule", rules_for_preview, default=rules_for_preview)
        preview_frame = preview_frame[
            preview_frame["engine"].isin(selected_engines)
            & preview_frame["protocol"].isin(selected_preview_protocols)
            & preview_frame["rule_id"].isin(selected_rules)
        ]
        st.dataframe(
            preview_frame[
                [
                    "engine",
                    "protocol",
                    "rule_id",
                    "title",
                    "severity",
                    "technique",
                    "evidence_reason",
                ]
            ],
            width="stretch",
            hide_index=True,
        )

with triage_tab:
    st.markdown("<div class='section-title'>Evidence-based analyst review queue</div>", unsafe_allow_html=True)
    st.caption(
        "Scores prioritize recorded decoy interactions for review. They do not establish attacker intent, identity, attribution, or compromise."
    )
    triage = build_triage_queue(filtered)
    if triage.empty:
        st.info("No events match the current filters.")
    else:
        scored = int((triage["score"] > 0).sum())
        high_review = int((triage["score"] >= 50).sum())
        top_score = int(triage["score"].max())
        q1, q2, q3 = st.columns(3)
        q1.metric("Scored interactions", f"{scored:,}")
        q2.metric("High / urgent review", f"{high_review:,}")
        q3.metric("Highest review score", f"{top_score}/100")

        queue_col, chart_col = st.columns([1.65, 1], gap="large")
        with queue_col:
            st.dataframe(
                triage.sort_values(["score", "observed_at"], ascending=[False, False]),
                width="stretch",
                hide_index=True,
                column_config={
                    "observed_at": st.column_config.DatetimeColumn("Observed (UTC)", format="YYYY-MM-DD HH:mm:ss"),
                    "score": st.column_config.ProgressColumn("Review score", min_value=0, max_value=100),
                },
            )
        with chart_col:
            score_counts = triage.groupby("priority", dropna=False).size().reset_index(name="events")
            priority_order = [
                "urgent review",
                "high review",
                "elevated review",
                "routine review",
                "informational",
            ]
            score_counts["priority"] = pd.Categorical(
                score_counts["priority"], categories=priority_order, ordered=True
            )
            score_counts = score_counts.sort_values("priority")
            bars = px.bar(
                score_counts,
                x="events",
                y="priority",
                orientation="h",
                color="priority",
                color_discrete_map={
                    "urgent review": "#B86A6A",
                    "high review": "#C58F5B",
                    "elevated review": "#B7A265",
                    "routine review": "#6F9FC4",
                    "informational": "#526778",
                },
            )
            bars.update_layout(
                height=330,
                margin={"l": 0, "r": 0, "t": 10, "b": 0},
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                xaxis_title="Events",
                yaxis_title="",
            )
            st.plotly_chart(bars, width="stretch")

    st.divider()
    st.markdown("<div class='section-title'>ATT&CK mapper regression benchmark</div>", unsafe_allow_html=True)
    st.caption(
        "The fixed, human-labeled fixture checks expected mapper behavior. These metrics are not a claim of accuracy on live traffic."
    )
    if not EVALUATION_FIXTURE.exists():
        st.warning("Evaluation fixture is not available in this build.")
    else:
        evaluation = load_evaluation(
            str(EVALUATION_FIXTURE), EVALUATION_FIXTURE.stat().st_mtime
        )
        e1, e2, e3, e4 = st.columns(4)
        e1.metric("Labeled cases", evaluation["cases"])
        e2.metric("Exact match", f"{evaluation['exact_match_ratio']:.0%}")
        e3.metric("Micro F1", f"{evaluation['micro_f1']:.2f}")
        e4.metric("Macro F1", f"{evaluation['macro_f1']:.2f}")
        metrics_frame = pd.DataFrame(evaluation["techniques"]).rename(
            columns={
                "technique_id": "technique",
                "true_positive": "TP",
                "false_positive": "FP",
                "false_negative": "FN",
                "true_negative": "TN",
            }
        )
        st.dataframe(
            metrics_frame[["technique", "support", "TP", "FP", "FN", "TN", "precision", "recall", "f1"]],
            width="stretch",
            hide_index=True,
            column_config={
                "precision": st.column_config.NumberColumn(format="%.2f"),
                "recall": st.column_config.NumberColumn(format="%.2f"),
                "f1": st.column_config.NumberColumn(format="%.2f"),
            },
        )
        st.caption(
            "A perfect fixture result means the mapper has not regressed against these cases; broader validation requires independently reviewed, authorized observations."
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
        width="stretch",
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
    "<div class='footer-note'>Project by <a href='https://github.com/Afnan16312' target='_blank'>Mir Afnan Ali (@Afnan16312)</a> · OT Sentinel research build 0.2.0 · Times shown in UTC · MITRE ATT&CK® is a registered trademark of The MITRE Corporation.</div>",
    unsafe_allow_html=True,
)
