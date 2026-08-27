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
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
CONTROL_OPERATIONS = {
    "write_single",
    "write_multiple",
    "single_command",
    "setpoint_command",
    "program_download",
}

st.set_page_config(
    page_title="OT Sentinel | ICS Threat Observatory",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="auto",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root { --canvas:#f9f9f9; --surface:#ffffff; --recessed:#f5f7fa; --border:#d1d5db; --text:#1a1c1e; --muted:#414751; --blue:#0060ab; --purple:#6a4da0; --red:#d32f2f; --amber:#b47c00; --green:#1b804b; }
html, body, [class*="css"] { font-family:'Inter',sans-serif; color:var(--text); }
.stApp { background:var(--canvas); }
[data-testid="stHeader"] { background:transparent; }
[data-testid="stSidebar"] { display:none; }
.block-container { max-width:1800px; padding:0 24px 32px 244px; }
.stitch-header { min-height:52px; display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid var(--border); margin:0 -24px 16px -244px; padding:0 24px; background:rgba(255,255,255,.97); }
.stitch-brand { color:#004883; font-size:18px; font-weight:600; letter-spacing:-.02em; }
.stTabs [role="tablist"]::before { content:'OT Sentinel'; position:absolute; top:-52px; left:20px; height:52px; display:flex; align-items:center; color:#004883; font-size:18px; font-weight:600; letter-spacing:-.02em; }
.stitch-brand { display:none; }
.stitch-status { display:flex; align-items:center; gap:10px; color:var(--muted); font-size:10px; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
.stitch-status .dot { width:8px; height:8px; border-radius:50%; background:var(--green); display:inline-block; }
.stitch-status .divider { color:#c1c7d3; margin:0 4px; }
.stitch-actions { display:flex; align-items:center; justify-content:flex-end; gap:8px; }
.header-info { width:32px; height:32px; border:1px solid var(--border); border-radius:4px; background:white; color:var(--muted); }
.stitch-header + div { margin-top:0; }
.hero { padding:4px 0 8px; margin-bottom:12px; }
.hero .eyebrow { color:var(--muted); }
.hero h1 { display:none; }
.hero p { color:var(--muted); max-width:900px; margin:0; font-size:.85rem; }
.author-line { color:#667085; font-size:.72rem; margin-top:4px; }
.author-line a, .footer-note a { color:var(--blue); text-decoration:none; }
.author-line a:hover, .footer-note a:hover { text-decoration:underline; }
.eyebrow, .map-kicker, .detail-label { color:var(--muted); font-family:'JetBrains Mono',monospace; letter-spacing:.12em; text-transform:uppercase; font-size:10px; font-weight:600; }
.demo-banner, .live-banner { border:1px solid #9ac4dc; background:#eef8ff; color:#185577; padding:8px 12px; border-radius:4px; font-size:.78rem; margin:4px 0 12px; }
.live-banner { border-color:#9ac4dc; background:#eef8ff; color:#185577; }
.filter-bar { display:flex; align-items:center; gap:14px; min-height:58px; padding:12px 16px; background:var(--surface); border:1px solid var(--border); border-radius:4px; margin:10px 0 12px; }
.filter-group { display:flex; align-items:center; gap:8px; white-space:nowrap; }
.filter-label { color:var(--muted); font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; }
.filter-chip { display:inline-flex; align-items:center; padding:5px 9px; border-radius:4px; border:1px solid var(--border); background:#fff; color:var(--text); font-family:'JetBrains Mono',monospace; font-size:11px; }
.filter-chip.blue { color:var(--blue); border-color:#a9c7ff; background:#eef4ff; }
.filter-chip.purple { color:var(--purple); border-color:#d8b8ff; background:#f8efff; }
.filter-chip.green { color:var(--green); border-color:#abd9be; background:#eefaf2; }
.filter-chip.red { color:var(--red); border-color:#f2b0b0; background:#fff0f0; }
.filter-divider { height:24px; width:1px; background:var(--border); }
.filter-help { margin-left:auto; color:var(--muted); font-size:11px; }
.telemetry-strip { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:16px; background:transparent; border:0; margin:8px 0 16px; }
.telemetry-cell { background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:14px 16px; min-width:0; }
.telemetry-label { color:var(--muted); font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.08em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.telemetry-value { color:var(--text); font-family:'JetBrains Mono',monospace; font-size:1.55rem; line-height:1.2; margin-top:8px; font-variant-numeric:tabular-nums; }
.telemetry-cell:first-child .telemetry-value { color:#2d67d8; }
.telemetry-cell:last-child .telemetry-value { color:var(--red); }
.section-title { font-size:1rem; font-weight:600; color:var(--text); margin-top:8px; }
.technique { border-left:3px solid var(--blue); background:var(--surface); border-top:1px solid var(--border); border-right:1px solid var(--border); border-bottom:1px solid var(--border); padding:10px 12px; margin:8px 0; border-radius:0 4px 4px 0; }
.technique .id { color:var(--blue); font-family:'JetBrains Mono',monospace; font-size:.7rem; }
.technique .name { color:var(--text); font-weight:600; margin-top:3px; }
.technique .meta { color:var(--muted); font-size:.74rem; margin-top:3px; }
.footer-note { color:#667085; font-size:.7rem; border-top:1px solid var(--border); margin-top:24px; padding-top:12px; }
div[data-testid="stDataFrame"] { border:1px solid var(--border); border-radius:4px; overflow:hidden; }
.stTabs { padding-top:0; }
.stTabs [role="tablist"] { position:fixed; z-index:20; left:0; top:52px; bottom:0; width:220px; padding:14px 10px; display:flex; flex-direction:column; align-items:stretch; gap:4px; background:var(--recessed); border-right:1px solid var(--border); }
.stTabs [role="tab"] { width:100%; min-height:40px; justify-content:flex-start; padding:8px 12px; border-left:3px solid transparent; border-radius:4px; color:var(--muted); font-size:13px; font-weight:500; letter-spacing:0; }
.stTabs [role="tab"] p { font-family:'Inter',sans-serif; font-size:13px; }
.stTabs [role="tab"] p::before { display:inline-block; width:24px; margin-right:7px; color:currentColor; font-size:17px; line-height:1; vertical-align:-2px; }
.stTabs [role="tab"]:nth-child(1) p::before { content:'▦'; }
.stTabs [role="tab"]:nth-child(2) p::before { content:'⬟'; }
.stTabs [role="tab"]:nth-child(3) p::before { content:'▣'; }
.stTabs [role="tab"]:nth-child(4) p::before { content:'▢'; }
.stTabs [role="tab"]:nth-child(5) p::before { content:'⇄'; }
.stTabs [role="tab"]:nth-child(6) p::before { content:'▤'; }
.stTabs [role="tab"]:hover { background:#ebf2fa; color:var(--blue); }
.stTabs [role="tab"][aria-selected="true"] { background:#dbe3f5; color:#004883; border-left-color:#004883; font-weight:600; }
.stTabs [role="tablist"] + div { margin-left:0; }
.stTabs [role="tabpanel"] { padding-top:0; }
.map-shell { background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:12px 14px 4px; }
.map-title { color:var(--text); font-size:1.15rem; font-weight:600; margin:4px 0 3px; }
.map-copy { color:var(--muted); font-size:.8rem; margin:0 0 10px; max-width:850px; }
.map-stat-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:0; background:var(--surface); border:1px solid var(--border); border-radius:4px; overflow:hidden; margin:8px 0 12px; }
.map-stat { background:var(--surface); padding:9px 11px; border-right:1px solid var(--border); }
.map-stat:last-child { border-right:0; }
.map-stat .label { color:var(--muted); font-size:.65rem; text-transform:uppercase; letter-spacing:.08em; }
.map-stat .value { color:var(--text); font-family:'JetBrains Mono',monospace; font-size:.9rem; margin-top:3px; }
.metric-info { position:relative; display:inline-flex; align-items:center; justify-content:center; width:14px; height:14px; margin-left:4px; border:1px solid #aab4c0; border-radius:50%; color:#5d6b7a; font-size:9px; font-weight:700; line-height:1; letter-spacing:0; text-transform:none; cursor:help; vertical-align:1px; }
.metric-info:focus-visible { outline:2px solid #4e8fb8; outline-offset:2px; }
.metric-tooltip { position:absolute; z-index:30; top:calc(100% + 8px); left:0; width:210px; padding:8px 9px; border:1px solid #aab4c0; border-radius:4px; background:#1f2933; color:#fff; box-shadow:0 4px 12px rgba(20,30,40,.18); font-size:11px; font-weight:400; line-height:1.35; letter-spacing:0; text-transform:none; text-align:left; visibility:hidden; opacity:0; pointer-events:none; transition:opacity .15s ease; }
.metric-info:hover .metric-tooltip, .metric-info:focus .metric-tooltip { visibility:visible; opacity:1; }
.detail-panel { background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:12px; min-height:210px; }
.detail-value { color:var(--text); font-size:.85rem; margin:3px 0 10px; word-break:break-word; }
.privacy-note { color:var(--muted); border-left:2px solid #9da3ad; padding:6px 8px; font-size:.72rem; margin-top:8px; }
.map-legend { display:flex; flex-wrap:wrap; gap:8px 14px; align-items:center; padding:8px 10px; margin:8px 0 10px; background:#f5f7fa; border:1px solid var(--border); border-radius:4px; color:var(--muted); font-size:.7rem; }
.map-legend span { display:inline-flex; align-items:center; gap:5px; }
.legend-dot { width:9px; height:9px; border-radius:50%; display:inline-block; border:1px solid rgba(0,0,0,.18); }
.legend-line { width:18px; height:0; border-top:2px solid #6a4da0; display:inline-block; }
.context-strip { display:flex; flex-wrap:wrap; gap:6px 12px; align-items:center; padding:8px 10px; margin:8px 0 10px; border-left:3px solid var(--blue); background:#eef4ff; color:#185577; font-size:.72rem; }
.context-strip b { color:#004883; }
.evidence-badge { display:inline-block; padding:3px 6px; border-radius:3px; margin:2px 3px 2px 0; border:1px solid #b9d2ee; background:#eef4ff; color:#185577; font-family:'JetBrains Mono',monospace; font-size:.68rem; }
.rail-card { background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:12px; margin-bottom:10px; }
.rail-card.critical { border-left:4px solid var(--red); }
.rail-label { color:var(--muted); font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; }
.rail-value { color:var(--text); font-family:'JetBrains Mono',monospace; font-size:1.4rem; margin:4px 0 7px; }
.rail-value.red { color:var(--red); }
.rail-trend { color:var(--green); font-family:'JetBrains Mono',monospace; font-size:.78rem; }
.protocol-row { margin:8px 0 10px; }
.protocol-meta { display:flex; justify-content:space-between; color:var(--muted); font-family:'JetBrains Mono',monospace; font-size:.7rem; }
.protocol-track { height:6px; background:#eef1f5; margin-top:4px; }
.protocol-fill { height:100%; }
[data-baseweb="select"] > div { background:#ffffff !important; border-color:var(--border) !important; color:var(--text) !important; }
[data-baseweb="select"] span { color:var(--text) !important; }
[data-baseweb="select"] svg { fill:var(--muted) !important; }
[data-testid="stSelectbox"] div:has(> input[role="combobox"]) { background:#ffffff !important; border-color:var(--border) !important; color:var(--text) !important; }
[data-testid="stSelectbox"] input[role="combobox"] { color:var(--text) !important; }
.stExpander { border:1px solid var(--border); border-radius:4px; background:var(--surface); }
.stExpander [data-testid="stExpanderToggleIcon"] { color:var(--muted); }
.stExpander summary p { color:var(--muted); font-size:11px; font-weight:600; letter-spacing:.08em; text-transform:uppercase; }
@media (max-width:1024px) { .block-container { padding-left:84px; } .stitch-header { margin-left:-84px; } .stTabs [role="tablist"] { width:64px; } .stTabs [role="tab"] { font-size:0; justify-content:center; padding:8px 6px; } .stTabs [role="tab"] p { font-size:0; } .stTabs [role="tab"] p:before { content:'•'; font-size:20px; } }
@media (max-width:700px) { .block-container { padding:0 12px 24px 66px; } .stitch-header { margin:0 -12px 12px -66px; padding:0 12px 0 66px; } .stitch-status { gap:5px; font-size:8px; } .stitch-status .divider, .stitch-status span:nth-of-type(n+3) { display:none; } .stTabs [role="tablist"] { top:52px; width:54px; } .telemetry-strip { grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; } .telemetry-value { font-size:1.15rem; } .filter-bar { flex-wrap:wrap; gap:8px; } .filter-help { width:100%; margin-left:0; } .map-stat-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration:.01ms !important; animation-iteration-count:1 !important; transition-duration:.01ms !important; scroll-behavior:auto !important; } }
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


def highest_confidence(value: object) -> str:
    """Return the strongest recorded mapping confidence without guessing."""
    if not isinstance(value, list):
        return "none"
    values = [str(item.get("confidence", "")).lower() for item in value if isinstance(item, dict)]
    return max(values, key=lambda item: CONFIDENCE_ORDER.get(item, -1), default="none")


def map_selection_from_row(row: pd.Series) -> dict[str, object]:
    """Convert one public aggregate row to the reviewed map selection contract."""
    return {
        "source": str(row["source"]),
        "country": str(row["country"]),
        "protocol": str(row["protocol"]),
        "events": int(row["events"]),
        "sessions": int(row["sessions"]),
        "max_severity": str(row["max_severity"]),
        "first_seen": str(row["first_seen"]),
        "last_seen": str(row["last_seen"]),
        "control_attempts": int(row["control_attempts"]),
        "techniques": str(row["techniques"]),
    }


def build_view_manifest(
    *,
    is_demo: bool,
    time_preset: str,
    filtered: pd.DataFrame,
    map_points: pd.DataFrame,
    quality: dict[str, int],
    selected_protocols: list[str],
    selected_severity: list[str],
    selected_countries: list[str],
    selected_confidence: list[str],
    selected_priorities: list[str],
    control_only: bool,
) -> dict[str, object]:
    """Build an aggregate-only manifest that makes a view reproducible."""
    return {
        "dataset_status": "synthetic" if is_demo else "sanitized",
        "time_window": time_preset,
        "filters": {
            "protocols": sorted(selected_protocols),
            "severity": sorted(selected_severity),
            "source_countries": sorted(selected_countries),
            "mapping_confidence": sorted(selected_confidence),
            "triage_priorities": sorted(selected_priorities),
            "control_actions_only": control_only,
        },
        "aggregate_counts": {
            "filtered_events": len(filtered),
            "mapped_events": int(quality["plotted_events"]),
            "mapped_sources": int(map_points["source"].nunique()) if not map_points.empty else 0,
            "mapped_countries": int(map_points["country"].nunique()) if not map_points.empty else 0,
        },
        "privacy": {
            "coordinates": "rounded aggregate only",
            "source_identity": "pseudonymous source groups only",
            "raw_payloads": "excluded",
            "raw_addresses": "excluded",
        },
    }


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
                "event_id": event.get("event_id"),
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
df = df.copy()
df["mapping_confidence"] = df.get("techniques", pd.Series([[]] * len(df))).apply(highest_confidence)
triage_all = build_triage_queue(df)
triage_lookup = triage_all.set_index("event_id") if not triage_all.empty else pd.DataFrame()
df["triage_score"] = df["event_id"].map(triage_lookup["score"] if not triage_all.empty else {}).fillna(0).astype(int)
df["triage_priority"] = df["event_id"].map(triage_lookup["priority"] if not triage_all.empty else {}).fillna("informational")

pending_country = st.session_state.pop("_pending_country_filter", None)
if pending_country is not None:
    st.session_state["filter_countries"] = pending_country
if st.session_state.pop("_reset_analysis_filters", False):
    for key in ("filter_protocols", "filter_severity", "filter_countries", "filter_confidence", "filter_priorities", "filter_control_only"):
        st.session_state.pop(key, None)

protocols = sorted(df["protocol"].dropna().unique().tolist())
severities = [item for item in ["high", "medium", "low", "info"] if item in df["severity"].unique()]
countries = sorted(df["source_country"].dropna().unique().tolist())
confidence_levels = [item for item in ["high", "medium", "low", "none"] if item in df["mapping_confidence"].unique()]
priority_levels = [
    item
    for item in ["urgent review", "high review", "elevated review", "routine review", "informational"]
    if item in df["triage_priority"].unique()
]
country_default = {"default": countries} if "filter_countries" not in st.session_state else {}
confidence_default = (
    {"default": confidence_levels} if "filter_confidence" not in st.session_state else {}
)
priority_default = {"default": priority_levels} if "filter_priorities" not in st.session_state else {}

with st.expander("Filters", expanded=False):
    filter_left, filter_mid, filter_right = st.columns(3)
    selected_protocols = filter_left.multiselect(
        "Protocols", protocols, default=protocols, key="filter_protocols"
    )
    selected_severity = filter_mid.multiselect(
        "Severity", severities, default=severities, key="filter_severity"
    )
    selected_countries = filter_right.multiselect(
        "Source countries", countries, key="filter_countries", **country_default
    )
    filter_confidence, filter_priority, filter_control = st.columns([1, 1, 1.1])
    selected_confidence = filter_confidence.multiselect(
        "Mapping confidence", confidence_levels, key="filter_confidence", **confidence_default
    )
    selected_priorities = filter_priority.multiselect(
        "Triage priority", priority_levels, key="filter_priorities", **priority_default
    )
    control_only = filter_control.toggle(
        "Control actions only", value=False, key="filter_control_only",
        help="Keep events whose decoded operation can change the fictional decoy state.",
    )
    st.caption("All filters use reviewed public fields. Raw addresses and payloads are never used by the dashboard.")
    if st.button("Reset analysis filters", key="reset_analysis_filters", width="stretch"):
        st.session_state["_reset_analysis_filters"] = True
        st.rerun()

filtered = df[
    df["protocol"].isin(selected_protocols)
    & df["severity"].isin(selected_severity)
    & df["source_country"].isin(selected_countries)
    & df["mapping_confidence"].isin(selected_confidence)
    & df["triage_priority"].isin(selected_priorities)
    & (
        (not control_only)
        | df["decoded.operation"].isin(CONTROL_OPERATIONS)
    )
].copy()
techniques = flatten_techniques(filtered)

events_count = len(filtered)
sessions = filtered["session_id"].nunique()
sources = filtered.get("source_id", filtered.get("source_ip", pd.Series(dtype=str))).nunique()
commands = filtered["decoded.operation"].isin(
    CONTROL_OPERATIONS
).sum()

status_label = "SYNTHETIC" if is_demo else "SANITIZED"
latest_public = df["observed_at"].max()
latest_label = latest_public.strftime("%d %b %Y %H:%M UTC") if pd.notna(latest_public) else "No observations"
header_export = map_points_csv(prepare_map_points(filtered))
header_left, header_status, header_export_col, header_info_col = st.columns([2.2, 4.2, 1, .45], gap="small")
with header_left:
    st.markdown("<div class='stitch-brand'>OT Sentinel</div>", unsafe_allow_html=True)
with header_status:
    st.markdown(
        f"<div class='stitch-status'><span class='dot'></span><span>DATASET: {status_label}</span>"
        f"<span class='divider'>|</span><span>UTC {pd.Timestamp.now(tz='UTC').strftime('%H:%M')}</span>"
        f"<span class='divider'>|</span><span>DATASET DATE: {latest_label}</span></div>",
        unsafe_allow_html=True,
    )
with header_export_col:
    st.download_button(
        "Export",
        data=header_export,
        file_name="ot-sentinel-filtered-summary.csv",
        mime="text/csv",
        key="header_export",
        width="stretch",
        help="Download the reviewed, aggregate summary for the current filters.",
    )
with header_info_col:
    if st.button("ⓘ", key="header_info", help="About this build"):
        st.info("OT Sentinel is a low-interaction ICS research dashboard. Public views contain synthetic or sanitized fields only.")

st.markdown(
    f"""
<div class="filter-bar" aria-label="Current dashboard filters">
  <div class="filter-group"><span class="filter-label">Protocols</span>
    <span class="filter-chip blue">{', '.join(item.upper() for item in selected_protocols) or 'NONE'}</span></div>
  <span class="filter-divider"></span>
  <div class="filter-group"><span class="filter-label">Severity</span>
    <span class="filter-chip red">{', '.join(item.upper() for item in selected_severity) or 'NONE'}</span></div>
  <span class="filter-divider"></span>
  <div class="filter-group"><span class="filter-label">Source countries</span>
    <span class="filter-chip purple">{len(selected_countries)} selected</span></div>
  <span class="filter-divider"></span>
  <div class="filter-group"><span class="filter-label">Evidence</span>
    <span class="filter-chip green">{', '.join(item.upper() for item in selected_confidence) or 'NONE'}</span></div>
  <span class="filter-divider"></span>
  <div class="filter-group"><span class="filter-label">Priority</span>
    <span class="filter-chip">{len(selected_priorities)} selected</span></div>
  {'<span class="filter-chip red">CONTROL ONLY</span>' if control_only else ''}
  <span class="filter-help">Use Filters to refine the dashboard.</span>
</div>
""",
    unsafe_allow_html=True,
)
st.markdown(
    f"<div class='context-strip'><b>View context</b><span>{'Synthetic dataset' if is_demo else 'Sanitized observations'}</span>"
    f"<span>{len(filtered):,} events in scope</span>"
    f"<span>{len(selected_countries):,} source countries selected</span></div>",
    unsafe_allow_html=True,
)

if is_demo:
    st.markdown(
        "<div class='demo-banner'><b>SYNTHETIC DATA</b> — This public build contains synthetic events for safe pipeline testing. It is not presented as observed attacker activity.</div>",
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        "<div class='live-banner'><b>SANITIZED OBSERVATIONS</b> — Source identifiers are pseudonymized and payload content is excluded from this public view.</div>",
        unsafe_allow_html=True,
    )

st.markdown(
    f"""
<div class="telemetry-strip" aria-label="Current filtered telemetry summary">
  <div class="telemetry-cell"><div class="telemetry-label">Observed events</div><div class="telemetry-value">{events_count:,}</div></div>
  <div class="telemetry-cell"><div class="telemetry-label">Sessions</div><div class="telemetry-value">{sessions:,}</div></div>
  <div class="telemetry-cell"><div class="telemetry-label">Source groups</div><div class="telemetry-value">{sources:,}</div></div>
  <div class="telemetry-cell" title="Requests containing a write, command, or program-transfer operation"><div class="telemetry-label">Control actions</div><div class="telemetry-value">{commands:,}</div></div>
</div>
""",
    unsafe_allow_html=True,
)

overview, attack_tab, detection_tab, triage_tab, sessions_tab, methodology = st.tabs(
    [
        "Observatory",
        "ATT&CK Analysis",
        "Detection Preview",
        "Triage",
        "Session Explorer",
        "Methodology",
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
    with st.expander("How to use this workspace", expanded=False):
        st.markdown(
            "**1. Observe** — choose a map mode and time window. **2. Investigate** — select a source bubble or use the accessible source table. **3. Validate** — follow the evidence into ATT&CK, Detection Preview, Triage or Session Explorer."
        )
        st.caption(
            "A source group is a privacy-safe identifier, a session is one bounded connection, and a technique is an evidence-qualified hypothesis—not proof of intent or compromise."
        )

    control1, control2, control3, control4, control5 = st.columns([1.25, 1.1, 1, 1.1, 0.8])
    map_mode = control1.selectbox("Map mode", MAP_MODES, key="map_mode")
    time_preset = control2.selectbox(
        "Observation window",
        ["All observations", "Last 24 hours", "Last 7 days", "Last 14 days", "Custom UTC range"],
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
    offline_map = st.checkbox(
        "Offline map fallback",
        value=False,
        key="map_offline",
        help="Use a tile-free geographic view when external CARTO/OpenStreetMap tiles are blocked.",
    )

    map_frame = filtered.copy()
    duration = None
    custom_dates = None
    if time_preset == "Custom UTC range" and not filtered.empty:
        latest_for_custom = filtered["observed_at"].max()
        earliest_for_custom = filtered["observed_at"].min()
        custom_dates = st.date_input(
            "Custom UTC dates",
            value=(earliest_for_custom.date(), latest_for_custom.date()),
            min_value=earliest_for_custom.date(),
            max_value=latest_for_custom.date(),
            key="map_custom_dates",
            help="Both dates are inclusive and interpreted as UTC.",
        )
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
        elif time_preset == "Custom UTC range" and isinstance(custom_dates, (tuple, list)) and len(custom_dates) == 2:
            start = pd.Timestamp(custom_dates[0], tz="UTC")
            end = pd.Timestamp(custom_dates[1], tz="UTC") + timedelta(days=1) - timedelta(microseconds=1)
            map_frame = filter_time_window(map_frame, start, end)

    map_points = prepare_map_points(map_frame)
    if not map_points.empty:
        map_points = map_points.assign(
            repeat_observations=(map_points["events"] - map_points["sessions"]).clip(lower=0)
        )
    quality = map_quality(map_frame)
    source_count = int(map_points["source"].nunique()) if not map_points.empty else 0
    protocol_count = int(map_points["protocol"].nunique()) if not map_points.empty else 0
    st.markdown(
        f"""
<div class="map-stat-grid">
  <div class="map-stat"><div class="label">Visible events <span class="metric-info" tabindex="0" title="Number of events matching the selected filters and observation window." aria-label="Number of events matching the selected filters and observation window.">i<span class="metric-tooltip">Number of events matching the selected filters and observation window.</span></span></div><div class="value">{quality['events']:,}</div></div>
  <div class="map-stat"><div class="label">Mapped sources <span class="metric-info" tabindex="0" title="Unique pseudonymous source groups with valid public map coordinates." aria-label="Unique pseudonymous source groups with valid public map coordinates.">i<span class="metric-tooltip">Unique pseudonymous source groups with valid public map coordinates.</span></span></div><div class="value">{source_count:,}</div></div>
  <div class="map-stat"><div class="label">Countries <span class="metric-info" tabindex="0" title="Countries represented by the filtered, sanitized observations." aria-label="Countries represented by the filtered, sanitized observations.">i<span class="metric-tooltip">Countries represented by the filtered, sanitized observations.</span></span></div><div class="value">{quality['countries']:,}</div></div>
  <div class="map-stat"><div class="label">Protocols active <span class="metric-info" tabindex="0" title="Different OT protocols present in the filtered map data." aria-label="Different OT protocols present in the filtered map data.">i<span class="metric-tooltip">Different OT protocols present in the filtered map data.</span></span></div><div class="value">{protocol_count:,}</div></div>
</div>
""",
        unsafe_allow_html=True,
    )
    st.markdown(
        f"<div class='context-strip'><b>Map window</b><span>{escape(time_preset)}</span>"
        f"<span>{quality['plotted_events']:,} mapped events</span><span>{quality['unmapped_events']:,} excluded for coordinate quality</span></div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<div class='map-legend' aria-label='Map legend'>"
        "<span><i class='legend-dot' style='background:#4E8FB8'></i>Modbus</span>"
        "<span><i class='legend-dot' style='background:#6A4DA0'></i>S7</span>"
        "<span><i class='legend-dot' style='background:#8175A8'></i>IEC-104</span>"
        "<span><i class='legend-line'></i>Observation relationship</span>"
        "<span>White endpoint = approximate UAE region</span>"
        "</div>",
        unsafe_allow_html=True,
    )
    if duration is not None and pd.notna(latest_observation):
        with st.expander("Compare with the previous equal window", expanded=False):
            previous_frame = filter_time_window(
                filtered,
                latest_observation - (duration * 2),
                latest_observation - duration,
            )
            compare = pd.DataFrame(
                {
                    "metric": ["Events", "Sessions", "Control actions", "Mapped sources"],
                    "Current window": [
                        len(map_frame),
                        map_frame["session_id"].nunique(),
                        int(map_frame["decoded.operation"].isin(CONTROL_OPERATIONS).sum()),
                        int(prepare_map_points(map_frame)["source"].nunique()),
                    ],
                    "Previous window": [
                        len(previous_frame),
                        previous_frame["session_id"].nunique(),
                        int(previous_frame["decoded.operation"].isin(CONTROL_OPERATIONS).sum()),
                        int(prepare_map_points(previous_frame)["source"].nunique()),
                    ],
                }
            )
            compare["Change"] = compare["Current window"] - compare["Previous window"]
            st.dataframe(compare, width="stretch", hide_index=True)
            st.caption("This compares recorded windows only; it is not a live-rate or attribution signal.")

    map_column, detail_column = st.columns([2.5, 0.9], gap="large")
    with map_column:
        if map_points.empty:
            st.info("No safely mappable observations match the current filters and time window.")
            map_selection = None
        else:
            map_style = "carto-positron" if show_labels else "carto-positron-nolabels"
            revision = f"ot-map-{st.session_state.get('_map_revision', 0)}"
            threat_map = build_threat_map(
                map_points,
                mode=map_mode,
                event_frame=map_frame,
                show_flows=show_flows,
                show_region=True,
                map_style=map_style,
                revision=revision,
                offline_map=offline_map,
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
            if offline_map and map_mode == "Time playback":
                st.caption("Offline fallback is available for Flow, Source bubbles and Density; playback uses the tile map.")

        with st.expander("Accessible source table", expanded=False):
            accessible_selection = None
            if map_points.empty:
                st.info("No source groups are available for the current filters and time window.")
                accessible_choice = "No source selected"
            else:
                accessible_table = map_points[
                    [
                        "source",
                        "country",
                        "protocol",
                        "events",
                        "sessions",
                        "repeat_observations",
                        "control_attempts",
                        "max_severity",
                        "first_seen",
                        "last_seen",
                    ]
                ].sort_values(["events", "source"], ascending=[False, True])
                st.dataframe(accessible_table, width="stretch", hide_index=True)
                accessible_choice = st.selectbox(
                    "Inspect source group",
                    ["No source selected"] + accessible_table["source"].astype(str).tolist(),
                    key="map_accessible_source",
                )
                if accessible_choice != "No source selected":
                    accessible_selection = map_selection_from_row(
                        accessible_table[accessible_table["source"].astype(str) == accessible_choice].iloc[0]
                    )

        selected = map_selection or accessible_selection or st.session_state.get("_selected_map_source")
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
        critical_count = int((filtered["severity"] == "high").sum()) if not filtered.empty else 0
        protocol_counts = filtered["protocol"].value_counts() if not filtered.empty else pd.Series(dtype="int64")
        protocol_total = max(int(protocol_counts.sum()), 1)
        protocol_rows = []
        protocol_colors = {"modbus": "#0060ab", "s7": "#6a4da0", "iec104": "#575f6e"}
        for protocol, count in protocol_counts.items():
            percent = round((int(count) / protocol_total) * 100)
            protocol_rows.append(
                f"<div class='protocol-row'><div class='protocol-meta'><span>{escape(str(protocol).upper())}</span><span>{percent}%</span></div>"
                f"<div class='protocol-track'><div class='protocol-fill' style='width:{percent}%;background:{protocol_colors.get(protocol, '#717782')}'></div></div></div>"
            )
        st.markdown(
            f"<div class='rail-card'><div class='rail-label'>Total monitored events</div><div class='rail-value'>{events_count:,}</div>"
            f"<div class='rail-trend'>↗ {len(protocol_counts)} protocols in view</div></div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<div class='rail-card critical'><div class='rail-label'>Critical anomalies</div><div class='rail-value red'>{critical_count:,}</div>"
            "<div class='rail-trend' style='color:#d32f2f'>High-severity control evidence only</div></div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<div class='rail-card'><div class='rail-label'>Protocol distribution</div>"
            + ("".join(protocol_rows) or "<div class='detail-value'>No protocols match the current filters.</div>")
            + "</div>",
            unsafe_allow_html=True,
        )
        recent_rows = []
        if not filtered.empty:
            for _, item in filtered.sort_values("observed_at", ascending=False).head(4).iterrows():
                operation = item.get("decoded.operation", "unknown")
                severity = str(item.get("severity", "info")).lower()
                dot_color = {"high": "#d32f2f", "medium": "#b47c00", "low": "#0060ab"}.get(severity, "#717782")
                recent_rows.append(
                    f"<div style='display:flex;justify-content:space-between;gap:8px;border-top:1px solid #d1d5db;padding:8px 0;font-family:JetBrains Mono,monospace;font-size:10px'>"
                    f"<span><span style='color:{dot_color}'>●</span> {escape(str(item.get('protocol', 'unknown')).upper())}</span>"
                    f"<span style='color:#414751;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>{escape(str(operation))}</span></div>"
                )
        st.markdown(
            "<div class='rail-card'><div class='rail-label'>Recent observations</div>"
            + ("".join(recent_rows) or "<div class='detail-value'>No observations match the current filters.</div>")
            + "</div>",
            unsafe_allow_html=True,
        )
        st.markdown("<div class='map-kicker'>Investigation summary</div>", unsafe_allow_html=True)
        if selected:
            safe = {key: escape(str(value)) for key, value in selected.items()}
            source_values = (
                map_frame["source_id"]
                if "source_id" in map_frame
                else map_frame.get("source_ip", pd.Series(index=map_frame.index, dtype=str))
            )
            selected_events = map_frame[
                source_values.astype(str).eq(str(selected["source"]))
                & map_frame["protocol"].astype(str).eq(str(selected["protocol"]))
            ].copy()
            selected_techniques = flatten_techniques(selected_events)
            confidence_values = (
                selected_techniques["confidence"].dropna().astype(str).str.lower().unique().tolist()
                if not selected_techniques.empty and "confidence" in selected_techniques
                else []
            )
            confidence_badges = "".join(
                f"<span class='evidence-badge'>{escape(value.upper())} confidence</span>"
                for value in sorted(confidence_values, key=lambda item: CONFIDENCE_ORDER.get(item, -1), reverse=True)
            ) or "<span class='evidence-badge'>No mapped confidence</span>"
            st.markdown(
                f"""
<div class="detail-panel">
  <div class="detail-label">Pseudonymous source</div><div class="detail-value"><code>{safe['source']}</code></div>
  <div class="detail-label">Country / protocol</div><div class="detail-value">{safe['country']} · {safe['protocol'].upper()}</div>
  <div class="detail-label">Observed activity</div><div class="detail-value">{safe['events']} events · {safe['sessions']} sessions · {safe['control_attempts']} control attempts</div>
  <div class="detail-label">Repeat observations</div><div class="detail-value">{max(int(selected['events']) - int(selected['sessions']), 0)} after the first session</div>
  <div class="detail-label">Highest severity</div><div class="detail-value">{safe['max_severity'].upper()}</div>
  <div class="detail-label">Latest observation</div><div class="detail-value">{safe['last_seen']}</div>
  <div class="detail-label">ATT&amp;CK hypotheses</div><div class="detail-value">{safe['techniques']}</div>
  <div class="detail-label">Evidence confidence</div><div class="detail-value">{confidence_badges}</div>
  <div class="privacy-note">This panel contains reviewed public fields only. Raw IP addresses and payloads are never exposed.</div>
</div>
""",
                unsafe_allow_html=True,
            )
            action_left, action_right = st.columns(2)
            if action_left.button("Prepare Session Explorer", key="prepare_session_view", width="stretch"):
                st.session_state["session_focus_source"] = selected["source"]
                st.info("Session Explorer is ready for this source group. Open that tab to review its events.")
            if action_right.button("Prepare ATT&CK review", key="prepare_attack_view", width="stretch"):
                if not selected_techniques.empty:
                    st.session_state["attack_focus_technique"] = str(selected_techniques.iloc[0]["technique_id"])
                st.info("ATT&CK Analysis is ready for this source context. Open that tab to review the evidence.")
            with st.expander("Private local review note", expanded=False):
                st.selectbox(
                    "Review state",
                    ["Unreviewed", "Reviewed", "Needs more context", "False positive"],
                    key="local_review_state",
                )
                st.text_area(
                    "Analyst note (local session only)",
                    key="local_review_note",
                    height=80,
                    placeholder="Record why this evidence needs attention. This note is not exported.",
                )
            if not selected_events.empty:
                timeline = selected_events.copy()
                timeline["techniques"] = timeline.get("technique_ids", pd.Series([[]] * len(timeline))).apply(
                    lambda value: ", ".join(value) or "—"
                )
                timeline["operation"] = timeline.get("decoded.operation", "unknown")
                timeline["source"] = timeline.get("source_id", "redacted")
                timeline = timeline[
                    ["observed_at", "protocol", "operation", "severity", "techniques", "session_id"]
                ].sort_values("observed_at", ascending=False).head(20)
                st.caption("Recent public evidence for the selected source group (maximum 20 rows).")
                st.dataframe(
                    timeline,
                    width="stretch",
                    hide_index=True,
                    column_config={
                        "observed_at": st.column_config.DatetimeColumn("Observed (UTC)", format="YYYY-MM-DD HH:mm:ss"),
                    },
                )
            if selected["country"] in countries and st.button(
                f"Filter dashboard to {selected['country']}", width="stretch"
            ):
                st.session_state["previous_countries"] = list(selected_countries)
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
        view_manifest = build_view_manifest(
            is_demo=is_demo,
            time_preset=time_preset,
            filtered=filtered,
            map_points=map_points,
            quality=quality,
            selected_protocols=selected_protocols,
            selected_severity=selected_severity,
            selected_countries=selected_countries,
            selected_confidence=selected_confidence,
            selected_priorities=selected_priorities,
            control_only=control_only,
        )
        st.download_button(
            "Export view manifest",
            data=json.dumps(view_manifest, indent=2) + "\n",
            file_name="ot-sentinel-view-manifest.json",
            mime="application/json",
            width="stretch",
            help="Exports aggregate view context and privacy guarantees; no individual event rows are included.",
        )
        if st.button("Show all countries", width="stretch", disabled=len(selected_countries) == len(countries)):
            st.session_state["_pending_country_filter"] = countries
            st.rerun()
        previous_countries = st.session_state.get("previous_countries")
        if previous_countries and previous_countries != selected_countries and st.button(
            "Restore previous country view", width="stretch"
        ):
            st.session_state["_pending_country_filter"] = previous_countries
            st.session_state.pop("previous_countries", None)
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
            color_discrete_map={"modbus": "#4E8FB8", "s7": "#6A4DA0", "iec104": "#8175A8"},
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
        line.update_xaxes(gridcolor="#D1D5DB")
        line.update_yaxes(gridcolor="#D1D5DB")
        st.plotly_chart(line, width="stretch")

with attack_tab:
    st.markdown("<div class='section-title'>Technique intensity by protocol</div>", unsafe_allow_html=True)
    attack_technique_options = ["All techniques"] + (
        sorted(techniques["technique_id"].dropna().astype(str).unique().tolist())
        if not techniques.empty
        else []
    )
    attack_default = st.session_state.get("attack_focus_technique", "All techniques")
    if attack_default not in attack_technique_options:
        attack_default = "All techniques"
    attack_focus = st.selectbox(
        "Technique focus",
        attack_technique_options,
        index=attack_technique_options.index(attack_default),
        key="attack_technique_filter",
    )
    if attack_focus != "All techniques":
        techniques = techniques[techniques["technique_id"].astype(str) == attack_focus]
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
                colorscale=[[0, "#F5F7FA"], [0.35, "#B9D2EE"], [1, "#0060AB"]],
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
    st.info(
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
        coverage = (
            preview_frame.groupby("protocol", dropna=False)
            .agg(
                predicted_matches=("rule_id", "size"),
                rules=("rule_id", "nunique"),
                techniques=("technique", "nunique"),
            )
            .reset_index()
            .sort_values("predicted_matches", ascending=False)
        )
        st.caption("Detection coverage summary — predictions are offline rule matches, not native engine alerts.")
        st.dataframe(coverage, width="stretch", hide_index=True)
        mapped_ids = set(techniques.get("technique_id", pd.Series(dtype=str)).dropna().astype(str))
        covered_ids = set(preview_frame.get("technique", pd.Series(dtype=str)).dropna().astype(str))
        uncovered_ids = sorted(mapped_ids - covered_ids)
        if uncovered_ids:
            st.info(
                "Mapped behaviors without an offline rule match in this view: "
                + ", ".join(uncovered_ids)
                + ". Review the evidence before treating this as a detection gap."
            )
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
                    "high review": "#C84C6B",
                    "elevated review": "#7A66C2",
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
        st.info("Evaluation fixture is not available in this build.")
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
    session_sources = sorted(display.get("source_id", pd.Series(dtype=str)).dropna().astype(str).unique().tolist())
    session_focus_options = ["All source groups"] + session_sources
    session_focus_default = st.session_state.get("session_focus_source", "All source groups")
    if session_focus_default not in session_focus_options:
        session_focus_default = "All source groups"
    session_focus = st.selectbox(
        "Source group focus",
        session_focus_options,
        index=session_focus_options.index(session_focus_default),
        key="session_source_filter",
    )
    if session_focus != "All source groups" and "source_id" in display:
        display = display[display["source_id"].astype(str) == session_focus]
    st.caption("The ledger contains reviewed public fields only. Select a source on the map to prepare a focused view.")
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
