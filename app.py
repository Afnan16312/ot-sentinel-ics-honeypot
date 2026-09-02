from __future__ import annotations

import json
import os
import sys
from collections.abc import MutableMapping
from datetime import timedelta
from hashlib import sha256
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
    build_source_comparison,
    build_threat_map,
    build_window_comparison,
    filter_time_window,
    map_points_csv,
    map_quality,
    map_viewpoint,
    prepare_map_points,
    selection_from_plotly_state,
    summarize_window_change,
)
from ot_sentinel.detection_preview import (
    detection_coverage_backlog,
    load_native_validation_evidence,
    preview_detections,
)
from ot_sentinel.evaluation import evaluate_mapper, load_labeled_jsonl
from ot_sentinel.investigation_state import InvestigationState
from ot_sentinel.operator_assurance import load_operator_assurance
from ot_sentinel.publication import (
    PublicationValidationError,
    load_public_jsonl,
    validate_public_stix_bundle,
)
from ot_sentinel.stix_export import export_events
from ot_sentinel.triage import (
    assess_event,
    assess_evidence_completeness,
    factor_summary,
    next_step_for_priority,
)

DATA_PATH = Path(os.getenv("OT_PUBLIC_DATA_PATH", ROOT / "data" / "demo_events.jsonl"))
EVALUATION_FIXTURE = ROOT / "tests" / "fixtures" / "evaluation" / "mapper_cases.jsonl"
NATIVE_VALIDATION_RECORD = ROOT / "tests" / "soc" / "NATIVE_VALIDATION.md"
ASSURANCE_HEALTH_PATH = Path(os.getenv("OT_ASSURANCE_HEALTH_PATH", "")).expanduser() if os.getenv("OT_ASSURANCE_HEALTH_PATH") else None
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
CONTROL_OPERATIONS = {
    "write_single",
    "write_multiple",
    "single_command",
    "setpoint_command",
    "program_download",
}
WORKSPACE_STATE_KEYS = {
    "filter_protocols",
    "filter_severity",
    "filter_countries",
    "filter_confidence",
    "filter_priorities",
    "filter_control_only",
    "map_mode",
    "map_window",
    "map_labels",
    "map_theme",
    "map_flows",
    "map_offline",
    "map_custom_dates",
    "map_accessible_source",
    "map_compare_sources",
    "attack_focus_technique",
    "attack_technique_filter",
    "session_focus_source",
    "session_source_filter",
    "triage_group_sessions",
    "detection_engines",
    "detection_protocols",
    "detection_rules",
    "reset_workspace_clear_notes",
    "previous_countries",
    "_pending_country_filter",
    "_selected_map_source",
    "_investigation_state",
    "_active_view",
    "_next_view",
    "_map_focus",
    "_map_camera",
    "_walkthrough_step",
    "_selected_event_id",
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
.filter-bar { display:flex; flex-wrap:wrap; align-items:center; gap:14px; min-height:58px; padding:12px 16px; background:var(--surface); border:1px solid var(--border); border-radius:4px; margin:10px 0 12px; }
.filter-bar > p { flex:0 1 200px; min-width:180px; margin:0 0 0 auto; }
.filter-group { display:flex; align-items:center; gap:8px; white-space:nowrap; }
.filter-label { color:var(--muted); font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; }
.filter-chip { display:inline-flex; align-items:center; padding:5px 9px; border-radius:4px; border:1px solid var(--border); background:#fff; color:var(--text); font-family:'JetBrains Mono',monospace; font-size:11px; }
.filter-chip.blue { color:var(--blue); border-color:#a9c7ff; background:#eef4ff; }
.filter-chip.purple { color:var(--purple); border-color:#d8b8ff; background:#f8efff; }
.filter-chip.green { color:var(--green); border-color:#abd9be; background:#eefaf2; }
.filter-chip.red { color:var(--red); border-color:#f2b0b0; background:#fff0f0; }
.filter-divider { height:24px; width:1px; background:var(--border); }
.filter-help { display:block; margin-left:0; color:var(--muted); font-size:11px; line-height:1.35; white-space:nowrap; }
.telemetry-strip { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:16px; background:transparent; border:0; margin:8px 0 16px; }
.telemetry-cell { background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:14px 16px; min-width:0; }
.telemetry-label { color:var(--muted); font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.08em; white-space:nowrap; overflow:visible; text-overflow:clip; }
.telemetry-value { color:var(--text); font-family:'JetBrains Mono',monospace; font-size:1.55rem; line-height:1.2; margin-top:8px; font-variant-numeric:tabular-nums; }
.telemetry-cell:first-child .telemetry-value { color:#2d67d8; }
.telemetry-cell:last-child .telemetry-value { color:var(--red); }
.guided-path { border:1px solid #b9cee5; border-left:3px solid var(--blue); background:#f7fbff; border-radius:4px; padding:14px 16px; margin:8px 0 10px; }
.guided-kicker { color:#004883; font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; }
.guided-title { color:var(--text); font-size:16px; font-weight:600; margin-top:4px; }
.guided-copy { color:var(--muted); font-size:13px; margin:6px 0 0; }
.guided-step { border-top:1px solid #d6e3f0; padding-top:8px; margin-top:8px; color:#25334a; font-size:13px; }
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
.metric-info { position:relative; display:inline-flex; align-items:center; justify-content:center; width:16px; min-height:16px; margin-left:4px; border:1px solid #aab4c0; border-radius:50%; color:#5d6b7a; font-size:9px; font-weight:700; line-height:1; letter-spacing:0; text-transform:none; vertical-align:1px; cursor:help; }
.metric-info:focus { outline:2px solid #4e8fb8; outline-offset:2px; }
.metric-tooltip { position:absolute; z-index:30; top:calc(100% + 8px); left:0; width:230px; max-width:calc(100vw - 32px); padding:8px 9px; border:1px solid #aab4c0; border-radius:4px; background:#1f2933; color:#fff; box-shadow:0 4px 12px rgba(20,30,40,.18); font-size:11px; font-weight:400; line-height:1.35; letter-spacing:0; text-transform:none; text-align:left; white-space:normal; overflow-wrap:anywhere; visibility:hidden; opacity:0; pointer-events:none; transition:opacity .15s ease; }
.metric-info:hover .metric-tooltip, .metric-info:focus .metric-tooltip, .metric-info:active .metric-tooltip { visibility:visible; opacity:1; }
.detail-panel { background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:12px; min-height:210px; }
.detail-value { color:var(--text); font-size:.85rem; margin:3px 0 10px; word-break:break-word; }
.privacy-note { color:var(--muted); border-left:2px solid #9da3ad; padding:6px 8px; font-size:.72rem; margin-top:8px; }
.map-legend { display:flex; flex-wrap:wrap; gap:8px 14px; align-items:center; padding:8px 10px; margin:8px 0 10px; background:#f5f7fa; border:1px solid var(--border); border-radius:4px; color:var(--muted); font-size:.7rem; }
.map-legend span { display:inline-flex; align-items:center; gap:5px; }
.legend-dot { width:9px; height:9px; border-radius:50%; display:inline-block; border:1px solid rgba(0,0,0,.18); }
.legend-line { width:18px; height:0; border-top:2px solid #3B82F6; display:inline-block; }
.map-story { display:grid; grid-template-columns:1.3fr 1fr 1fr; gap:8px; margin:8px 0 10px; }
.map-story-card { padding:9px 10px; background:#f8fafc; border:1px solid var(--border); border-radius:4px; color:var(--muted); font-size:.72rem; line-height:1.4; }
.map-story-card.primary { border-left:3px solid var(--blue); background:#f2f7ff; }
.map-story-label { display:block; color:#004883; font-family:'JetBrains Mono',monospace; font-size:.62rem; font-weight:600; letter-spacing:.08em; text-transform:uppercase; margin-bottom:3px; }
.map-story-card b { color:var(--text); }
.context-strip { display:flex; flex-wrap:wrap; gap:6px 12px; align-items:center; padding:8px 10px; margin:8px 0 10px; border-left:3px solid var(--blue); background:#eef4ff; color:#185577; font-size:.72rem; }
.context-strip b { color:#004883; }
.state-chip-row { display:flex; flex-wrap:wrap; gap:6px; align-items:center; padding:7px 0; margin:0 0 10px; }
.state-chip { display:inline-flex; align-items:center; min-height:24px; padding:4px 8px; border:1px solid #b9cee5; border-radius:999px; background:#fff; color:#334155; font-family:'JetBrains Mono',monospace; font-size:10px; }
.state-chip strong { color:#004883; margin-right:4px; }
.state-chip.warning { border-color:#e5c56a; background:#fff9e8; color:#775400; }
.investigation-drawer { background:#fff; border:1px solid #9bb7d2; border-left:4px solid var(--blue); border-radius:4px; padding:12px; min-height:210px; box-shadow:0 2px 10px rgba(50,80,110,.06); }
.drawer-kicker { color:#004883; font-family:'JetBrains Mono',monospace; font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; }
.drawer-title { color:var(--text); font-size:1rem; font-weight:600; margin:3px 0 8px; }
.route-banner { display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:8px; padding:8px 10px; margin:8px 0 10px; border:1px solid #b9cee5; background:#f7fbff; color:#185577; border-radius:4px; font-size:.75rem; }
.scope-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.scope-card { border:1px solid var(--border); border-radius:4px; background:#fff; padding:10px 12px; color:var(--muted); font-size:.78rem; }
.scope-card strong { display:block; color:var(--text); margin-bottom:5px; }
.scope-card ul { margin:0; padding-left:18px; }
.scope-card li { margin:3px 0; }
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
@media (max-width:1024px) { .block-container { padding-left:204px; } .stitch-header { margin-left:-204px; } .stTabs [role="tablist"] { width:184px; } .stTabs [role="tab"] { font-size:12px; justify-content:flex-start; padding:8px 8px; } .stTabs [role="tab"] p { font-size:12px; } }
@media (max-width:700px) { .block-container { padding:0 12px 24px; } .stitch-header { margin:0 -12px 12px; padding:0 12px; } .stitch-status { gap:5px; font-size:8px; } .stitch-status .divider, .stitch-status span:nth-of-type(n+3) { display:none; } .stTabs [role="tablist"] { position:static; width:auto; flex-direction:row; overflow-x:auto; padding:4px; margin:0 0 10px; border:1px solid var(--border); border-radius:4px; } .stTabs [role="tab"] { flex:0 0 auto; width:auto; min-width:max-content; font-size:11px; justify-content:flex-start; padding:7px 8px; border-left:0; border-bottom:3px solid transparent; } .stTabs [role="tab"] p, .stTabs [role="tab"] p:before { font-size:11px; } .stTabs [role="tab"] p:before { width:16px; margin-right:3px; font-size:13px; } .stTabs [role="tab"][aria-selected="true"] { border-left:0; border-bottom-color:#004883; } .telemetry-strip { grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; } .telemetry-value { font-size:1.15rem; } .filter-bar { gap:8px; } .filter-bar > p { flex-basis:100%; min-width:0; } .filter-help { white-space:normal; } .map-stat-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .map-story { grid-template-columns:1fr; } .scope-grid { grid-template-columns:1fr; } }
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


def reset_workspace_state(
    state: MutableMapping[str, object], *, clear_notes: bool = False
) -> None:
    """Clear transient investigation state while preserving local notes by default."""

    keys = list(state)
    for key in keys:
        is_workspace_key = key in WORKSPACE_STATE_KEYS or key.startswith(
            "interactive_threat_map_"
        )
        is_note_key = key.startswith(("local_review_note_", "local_review_state_"))
        if is_workspace_key or (clear_notes and is_note_key):
            state.pop(key, None)


def render_scope_panel(title: str, can_prove: list[str], cannot_prove: list[str]) -> None:
    """Render view-specific interpretation boundaries."""

    with st.expander(f"What {title} can and cannot prove", expanded=False):
        can_items = "".join(f"<li>{escape(item)}</li>" for item in can_prove)
        cannot_items = "".join(f"<li>{escape(item)}</li>" for item in cannot_prove)
        st.markdown(
            f"<div class='scope-grid'><div class='scope-card'><strong>Can show</strong><ul>{can_items}</ul></div>"
            f"<div class='scope-card'><strong>Cannot establish</strong><ul>{cannot_items}</ul></div></div>",
            unsafe_allow_html=True,
        )


def info_badge(label: str, explanation: str) -> str:
    """Return a hover-first explanation badge with keyboard focus support."""

    return (
        f"<span class='metric-info' tabindex='0' role='note' "
        f"aria-label='{escape(label)}: {escape(explanation)}' title='{escape(explanation)}'>i"
        f"<span class='metric-tooltip' role='tooltip'>{escape(explanation)}</span></span>"
    )


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
        event_record = {
            "event_type": event.get("event_type"),
            "decoded": decoded,
            "techniques": event.get("techniques", []),
            "session_id": event.get("session_id"),
            "source_country_code": event.get("source_country_code"),
            "source_latitude": event.get("source_latitude"),
            "source_longitude": event.get("source_longitude"),
        }
        assessment = assess_event(event_record)
        completeness = assess_evidence_completeness(event_record)
        mapped = bool(event_record["techniques"])
        rows.append(
            {
                "event_id": event.get("event_id"),
                "observed_at": event.get("observed_at"),
                "source": event.get("source_id", event.get("source_ip", "redacted")),
                "protocol": event.get("protocol"),
                "operation": decoded.get("operation", "unknown"),
                "score": assessment.score,
                "priority": assessment.priority,
                "evidence completeness": completeness.label,
                "evidence fields": f"{completeness.checks_met}/{completeness.checks_total}",
                "mapping state": (
                    "mapped hypothesis" if mapped else "insufficient for ATT&CK conclusion"
                ),
                "evidence factors": factor_summary(assessment),
                "analyst note": assessment.analyst_note,
                "session_id": event.get("session_id"),
            }
        )
    return pd.DataFrame(rows)


def investigation_lead(frame: pd.DataFrame) -> dict[str, object] | None:
    """Return one explainable starting point without making an automated decision."""

    queue = build_triage_queue(frame)
    if queue.empty:
        return None
    lead = queue.sort_values(["score", "observed_at"], ascending=[False, False]).iloc[0]
    event_id = str(lead["event_id"])
    matching_events = frame[frame["event_id"].astype(str).eq(event_id)]
    techniques = flatten_techniques(matching_events)
    technique_id = (
        str(techniques.iloc[0]["technique_id"])
        if not techniques.empty and pd.notna(techniques.iloc[0]["technique_id"])
        else None
    )
    return {
        "source": str(lead["source"]),
        "priority": str(lead["priority"]),
        "score": int(lead["score"]),
        "evidence_factors": str(lead["evidence factors"]),
        "next_step": next_step_for_priority(str(lead["priority"])),
        "technique_id": technique_id,
    }


def build_session_triage_queue(event_queue: pd.DataFrame) -> pd.DataFrame:
    """Group event-level review evidence into bounded sessions."""

    if event_queue.empty:
        return event_queue.copy()
    rows: list[dict[str, object]] = []
    for session_id, session in event_queue.groupby("session_id", dropna=False):
        ranked = session.sort_values(["score", "observed_at"], ascending=[False, False])
        top = ranked.iloc[0]
        incomplete = int((session["evidence completeness"] != "complete fields").sum())
        rows.append(
            {
                "session_id": session_id or "missing-session-id",
                "first_seen": session["observed_at"].min(),
                "last_seen": session["observed_at"].max(),
                "source": ", ".join(sorted(session["source"].dropna().astype(str).unique())),
                "protocols": ", ".join(sorted(session["protocol"].dropna().astype(str).unique())),
                "events": len(session),
                "highest score": int(top["score"]),
                "priority": top["priority"],
                "incomplete evidence events": incomplete,
                "top evidence factors": top["evidence factors"],
            }
        )
    return pd.DataFrame(rows).sort_values(
        ["highest score", "last_seen"], ascending=[False, False]
    )


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
if st.session_state.pop("_reset_workspace", False):
    clear_notes = bool(st.session_state.pop("_reset_workspace_clear_notes", False))
    reset_workspace_state(st.session_state, clear_notes=clear_notes)

investigation_state = InvestigationState.from_session(st.session_state)
with st.expander("Save or restore a local investigation", expanded=False):
    st.caption(
        "Save the current filters, map settings and selected public source as a redacted local snapshot. "
        "It never includes raw addresses, payloads or private review notes."
    )
    uploaded_snapshot = st.file_uploader(
        "Load a saved investigation snapshot",
        type=["json"],
        key="investigation_snapshot_upload",
        help="Only OT Sentinel v1 snapshots are accepted; unsupported fields are ignored by the safety gate.",
    )
if uploaded_snapshot is not None:
    snapshot_bytes = uploaded_snapshot.getvalue()
    snapshot_hash = sha256(snapshot_bytes).hexdigest()
    if snapshot_hash != st.session_state.get("_loaded_snapshot_hash"):
        try:
            snapshot_payload = json.loads(snapshot_bytes.decode("utf-8"))
            investigation_state = InvestigationState.from_snapshot(snapshot_payload)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            st.error(f"Snapshot could not be loaded safely: {error}")
        else:
            investigation_state.sync_to_session(st.session_state)
            st.session_state["filter_protocols"] = investigation_state.filters["protocols"]
            st.session_state["filter_severity"] = investigation_state.filters["severity"]
            st.session_state["filter_countries"] = investigation_state.filters["source_countries"]
            st.session_state["filter_confidence"] = investigation_state.filters["mapping_confidence"]
            st.session_state["filter_priorities"] = investigation_state.filters["triage_priorities"]
            st.session_state["filter_control_only"] = investigation_state.filters["control_actions_only"]
            st.session_state["map_mode"] = investigation_state.map_mode
            st.session_state["map_window"] = investigation_state.map_window
            st.session_state["map_theme"] = investigation_state.map_theme
            st.session_state["_loaded_snapshot_hash"] = snapshot_hash
            st.rerun()

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
    clear_notes_on_reset = st.checkbox(
        "Also clear private local review notes",
        value=False,
        key="reset_workspace_clear_notes",
        help="Leave this off to preserve notes and review states stored in this browser session.",
    )
    if st.button("Reset workspace", key="reset_workspace", width="stretch"):
        st.session_state["_reset_workspace_clear_notes"] = clear_notes_on_reset
        st.session_state["_reset_workspace"] = True
        st.rerun()

investigation_state.filters = {
    "protocols": list(selected_protocols),
    "severity": list(selected_severity),
    "source_countries": list(selected_countries),
    "mapping_confidence": list(selected_confidence),
    "triage_priorities": list(selected_priorities),
    "control_actions_only": control_only,
}
investigation_state.sync_to_session(st.session_state)

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
    f"<div class='context-strip'><b>Data &amp; privacy context</b><span>{'Synthetic dataset' if is_demo else 'Sanitized observations'}</span>"
    f"<span>Publication-validated public dataset</span><span>Dataset ends {escape(latest_label)}</span>"
    f"<span>{len(filtered):,} events in scope</span><span>Approximate geography</span>"
    f"<span>No raw IPs or payloads</span></div>",
    unsafe_allow_html=True,
)
chip_selection = investigation_state.selected_source
chip_selection_label = (
    f"{chip_selection['source']} · {chip_selection['protocol'].upper()}"
    if chip_selection
    else "none"
)
accessible_chip = str(st.session_state.get("map_accessible_source", ""))
if not chip_selection and accessible_chip and accessible_chip != "No source selected":
    chip_selection_label = accessible_chip
chip_destination = investigation_state.destination_view or "none"
st.markdown(
    f"<div class='state-chip-row' aria-label='Current investigation state'>"
    f"<span class='state-chip'><strong>VIEW</strong>{escape(investigation_state.active_view)}</span>"
    f"<span class='state-chip'><strong>WINDOW</strong>{escape(str(st.session_state.get('map_window', 'All observations')))}</span>"
    f"<span class='state-chip'><strong>FILTERS</strong>{len(filtered):,} events</span>"
    f"<span class='state-chip'><strong>EVIDENCE</strong>{', '.join(item.upper() for item in selected_confidence) or 'NONE'}</span>"
    f"<span class='state-chip'><strong>SELECTED</strong>{escape(chip_selection_label)}</span>"
    f"<span class='state-chip{' warning' if chip_destination != 'none' else ''}'><strong>NEXT</strong>{escape(chip_destination)}</span>"
    f"</div>",
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

with st.expander("Understand these numbers", expanded=False):
    st.markdown(
        "- **Observed events** are individual protocol telemetry matches in the selected view.\n"
        "- **Sessions** are bounded connections, not people or separate intrusions.\n"
        "- **Source groups** are pseudonymous public identifiers, not verified identities.\n"
        "- **Control actions** are requests that can change the fictional decoy state.\n"
        "- **Evidence confidence** describes the ATT&CK mapping evidence, not certainty about intent.\n"
        "- **Severity** is a label for the recorded protocol behavior; it is not a probability of harm.\n"
        "- **Priority** is the recommended order for human review; it is not a prediction of compromise.\n"
        "- **ATT&CK hypothesis** is a standardized behavior description supported by the record; it is not proof that an attack succeeded.\n"
        "- **Detection Preview** is an offline rule match; it is not a live alert from Wazuh, Suricata or a SIEM.\n"
        "- **STIX** is a portable JSON format for sharing structured security observations."
    )
    st.caption(
        "Counts describe recorded telemetry matches. They are not a count of unique intrusions, attackers, victims, or countries of origin."
    )

st.markdown(
    f"""
<div class="telemetry-strip" aria-label="Current filtered telemetry summary">
  <div class="telemetry-cell"><div class="telemetry-label">Observed events {info_badge('Observed events', 'Individual protocol records matching the current filters. Several records can come from one session, so this is not a count of attacks.')}</div><div class="telemetry-value">{events_count:,}</div></div>
  <div class="telemetry-cell"><div class="telemetry-label">Sessions {info_badge('Sessions', 'Bounded network connections to the decoy. A session is not a person, attacker or confirmed intrusion.')}</div><div class="telemetry-value">{sessions:,}</div></div>
  <div class="telemetry-cell"><div class="telemetry-label">Source groups {info_badge('Source groups', 'Privacy-safe labels that group records from the same source. They are pseudonyms, not verified identities.')}</div><div class="telemetry-value">{sources:,}</div></div>
  <div class="telemetry-cell"><div class="telemetry-label">Control actions {info_badge('Control actions', 'Write, command or program-transfer requests sent to the fictional decoy. They do not prove that a real machine or process was changed.')}</div><div class="telemetry-value">{commands:,}</div></div>
</div>
""",
    unsafe_allow_html=True,
)

with st.expander("Guided investigation path", expanded=False):
    lead = investigation_lead(filtered)
    investigation_state.walkthrough_step = min(
        5, max(0, int(st.session_state.get("_walkthrough_step", investigation_state.walkthrough_step)))
    )
    st.markdown(
        "<div class='guided-path'><div class='guided-kicker'>Five-minute walkthrough</div>"
        "<div class='guided-title'>Move from observation to a reviewable conclusion</div>"
        "<p class='guided-copy'>A short, deterministic path for a first-time reviewer. It uses only the current recorded dataset and never pretends to be a live response workflow.</p>"
        "<div class='guided-step'><b>1. Scope:</b> confirm the filters, time window and privacy boundary.</div>"
        "<div class='guided-step'><b>2. Select:</b> choose one pseudonymous source group on the map or accessible table.</div>"
        "<div class='guided-step'><b>3. Explain:</b> read the evidence, mapping confidence and review-priority factors.</div>"
        "<div class='guided-step'><b>4. Validate:</b> follow the prepared source into Session Explorer, ATT&amp;CK or Detection Preview.</div>"
        "<div class='guided-step'><b>5. Export:</b> save a redacted local snapshot that can reload this view.</div>"
        "</div>",
        unsafe_allow_html=True,
    )
    walkthrough_left, walkthrough_right = st.columns([1, 2], gap="large")
    with walkthrough_left:
        if walkthrough_left.button(
            "Start / restart walkthrough",
            key="walkthrough_start",
            width="stretch",
        ):
            investigation_state.walkthrough_step = 1
            investigation_state.sync_to_session(st.session_state)
            st.rerun()
        if investigation_state.walkthrough_step:
            st.progress(investigation_state.walkthrough_step / 5, text=f"Step {investigation_state.walkthrough_step} of 5")
            walkthrough_back, walkthrough_next = st.columns(2)
            if walkthrough_back.button(
                "Back",
                key="walkthrough_back",
                width="stretch",
                disabled=investigation_state.walkthrough_step <= 1,
            ):
                investigation_state.walkthrough_step -= 1
                investigation_state.sync_to_session(st.session_state)
                st.rerun()
            if walkthrough_next.button(
                "Continue",
                key="walkthrough_next",
                width="stretch",
                disabled=investigation_state.walkthrough_step >= 5,
            ):
                investigation_state.walkthrough_step += 1
                investigation_state.sync_to_session(st.session_state)
                st.rerun()
    with walkthrough_right:
        if lead is None:
            st.info("No observation matches the current filters. Widen the scope before beginning a review.")
        else:
            st.caption(
                f"Suggested starting point: {lead['priority']} ({lead['score']}/100) for source group {lead['source']}. "
                "This is a review order, not an automated decision or a claim of compromise."
            )
            st.write(f"**Why it is ranked:** {lead['evidence_factors']}")
            st.write(f"**Recommended next step:** {lead['next_step']}")
            prepare_session, prepare_attack = st.columns(2)
            if prepare_session.button(
                "Prepare lead source in Session Explorer",
                key="guided_prepare_session",
                width="stretch",
            ):
                st.session_state["session_focus_source"] = lead["source"]
                investigation_state.destination_view = "Session Explorer"
                investigation_state.sync_to_session(st.session_state)
                st.success("Session Explorer is prepared. Open that labelled tab to continue; your filters and source context will remain.")
            if prepare_attack.button(
                "Prepare ATT&CK evidence review",
                key="guided_prepare_attack",
                width="stretch",
                disabled=lead["technique_id"] is None,
            ):
                st.session_state["attack_focus_technique"] = lead["technique_id"]
                investigation_state.destination_view = "ATT&CK Analysis"
                investigation_state.sync_to_session(st.session_state)
                st.success("ATT&CK Analysis is prepared. Open that labelled tab to continue; your filters and source context will remain.")

if investigation_state.destination_view:
    st.markdown(
        f"<div class='route-banner' role='status'><span><b>Next view ready:</b> {escape(investigation_state.destination_view)} · context is preserved.</span>"
        "<span>Use the labelled workspace tab above to continue.</span></div>",
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
    render_scope_panel(
        "the Observatory",
        [
            "Counts and trends in the selected public telemetry window.",
            "Approximate country-level patterns for pseudonymous source groups.",
        ],
        [
            "A person's identity, physical location, motive or attribution.",
            "Successful exploitation, compromise or impact on a real process.",
        ],
    )
    with st.expander("How to use this workspace", expanded=False):
        st.markdown(
            "**1. Observe** — choose a map mode and time window. **2. Investigate** — select a source bubble or use the accessible source table. **3. Validate** — follow the evidence into ATT&CK, Detection Preview, Triage or Session Explorer."
        )
        st.caption(
            "A source group is a privacy-safe identifier, a session is one bounded connection, and a technique is an evidence-qualified hypothesis—not proof of intent or compromise."
        )

    control1, control2, control3, control4, control5, control6 = st.columns([1.25, 1.1, 1, 1.1, 0.9, 0.9])
    map_mode = control1.selectbox("Map mode", MAP_MODES, key="map_mode")
    time_preset = control2.selectbox(
        "Observation window",
        ["All observations", "Last 24 hours", "Last 7 days", "Last 14 days", "Custom UTC range"],
        key="map_window",
    )
    show_labels = control3.toggle(
        "Place labels",
        value=True,
        key="map_labels",
        help="Show country and place names in the detailed map background.",
    )
    show_flows = control4.toggle(
        "Observation paths",
        value=True,
        disabled=map_mode != "Flow view",
        key="map_flows",
        help="Paths indicate network observations, not a proven physical attacker route.",
    )
    if control5.button("Reset camera", width="stretch"):
        investigation_state.map_camera = "overview"
        investigation_state.map_focus = None
        investigation_state.sync_to_session(st.session_state)
        st.session_state["_map_revision"] = st.session_state.get("_map_revision", 0) + 1
    if control6.button(
        "Fit visible data",
        width="stretch",
        help="Center the map on the currently visible, safely mappable observations.",
    ):
        investigation_state.map_camera = "fit"
        investigation_state.map_focus = None
        investigation_state.sync_to_session(st.session_state)
        st.session_state["_map_revision"] = st.session_state.get("_map_revision", 0) + 1
    investigation_state.map_mode = map_mode
    investigation_state.map_window = time_preset
    offline_map = st.checkbox(
        "Offline map fallback",
        value=False,
        key="map_offline",
        help="Use a tile-free geographic view when external CARTO/OpenStreetMap tiles are blocked.",
    )
    map_theme = st.selectbox(
        "Map theme",
        ["Dark operations", "Detailed place names", "Low-clutter background"],
        key="map_theme",
        help="Dark operations is the default presentation view. This changes only the visual background, never the observations or their privacy-safe precision.",
    )
    investigation_state.map_theme = map_theme
    investigation_state.sync_to_session(st.session_state)

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
    map_center = None
    map_zoom = None
    if investigation_state.map_camera == "fit":
        map_center, map_zoom = map_viewpoint(map_points)
    elif investigation_state.map_camera == "focus" and investigation_state.map_focus:
        map_center, map_zoom = map_viewpoint(map_points, focus=investigation_state.map_focus)
    source_count = int(map_points["source"].nunique()) if not map_points.empty else 0
    protocol_count = int(map_points["protocol"].nunique()) if not map_points.empty else 0
    st.markdown(
        f"""
<div class="map-stat-grid">
  <div class="map-stat"><div class="label">Visible events {info_badge('Visible events', 'Number of events matching the selected filters and observation window. This is not a count of unique attacks.')}</div><div class="value">{quality['events']:,}</div></div>
  <div class="map-stat"><div class="label">Mapped sources {info_badge('Mapped sources', 'Unique pseudonymous source groups with usable, deliberately coarse public map coordinates. Locations are approximate.')}</div><div class="value">{source_count:,}</div></div>
  <div class="map-stat"><div class="label">Countries {info_badge('Countries', 'Countries represented by the filtered, sanitized records. A country does not identify a person or organization.')}</div><div class="value">{quality['countries']:,}</div></div>
  <div class="map-stat"><div class="label">Protocols active {info_badge('Protocols active', 'Different OT protocols present in the filtered map data: Modbus, S7 or IEC-104.')}</div><div class="value">{protocol_count:,}</div></div>
</div>
""",
        unsafe_allow_html=True,
    )
    st.markdown(
        f"<div class='context-strip'><b>Map window</b><span>{escape(time_preset)}</span>"
        f"<span>{quality['plotted_events']:,} mapped events</span><span>{quality['unmapped_events']:,} excluded for coordinate quality</span></div>",
        unsafe_allow_html=True,
    )
    if not map_points.empty:
        lead_point = map_points.sort_values(
            ["events", "public_review_score", "country"], ascending=[False, False, True]
        ).iloc[0]
        protocol_events = map_points.groupby("protocol", observed=True)["events"].sum()
        leading_protocol = str(protocol_events.idxmax()).upper()
        leading_protocol_events = int(protocol_events.max())
        visible_controls = int(map_points["control_attempts"].sum())
        st.markdown(
            "<div class='map-story'>"
            "<div class='map-story-card primary'><span class='map-story-label'>What stands out</span>"
            f"<b>{escape(str(lead_point['country']))}</b> has the most visible activity: <b>{int(lead_point['events']):,} observations</b>. Click its bubble to investigate.</div>"
            "<div class='map-story-card'><span class='map-story-label'>Most active protocol</span>"
            f"<b>{escape(leading_protocol)}</b> accounts for <b>{leading_protocol_events:,} observations</b> in this window.</div>"
            "<div class='map-story-card'><span class='map-story-label'>How to read it</span>"
            f"Bubble size = observations; colour = protocol; {visible_controls:,} visible control actions are shown only in the click detail.</div>"
            "</div>",
            unsafe_allow_html=True,
        )
    st.markdown(
        "<div class='map-legend' aria-label='Map legend'>"
        "<span><i class='legend-dot' style='background:#EF4444'></i>Modbus</span>"
        "<span><i class='legend-dot' style='background:#3B82F6'></i>S7</span>"
        "<span><i class='legend-dot' style='background:#FBBF24'></i>IEC-104</span>"
        "<span>Bubble size = recorded observations</span>"
        "<span><i class='legend-dot' style='background:#F8FAFC'></i>Halo = elevated severity</span>"
        "<span>Labels = country and place names</span>"
        "<span><i class='legend-line'></i>Observation relationship</span>"
        "<span>White endpoint = approximate UAE region</span>"
        "</div>",
        unsafe_allow_html=True,
    )
    if duration is not None and pd.notna(latest_observation):
        with st.expander("Compare with the previous equal window", expanded=False):
            current_start = latest_observation - duration
            previous_frame = filter_time_window(
                filtered,
                latest_observation - (duration * 2),
                current_start - timedelta(microseconds=1),
            )
            compare = build_window_comparison(map_frame, previous_frame)
            st.markdown("<div class='detail-label'>What changed</div>", unsafe_allow_html=True)
            st.info(summarize_window_change(compare))
            st.dataframe(compare, width="stretch", hide_index=True)
            st.caption("This compares recorded windows only; it is not a live-rate or attribution signal.")

    map_column, detail_column = st.columns([2.5, 0.9], gap="large")
    with map_column:
        if map_points.empty:
            st.info("No safely mappable observations match the current filters and time window.")
            map_selection = None
        else:
            map_styles = {
                "Dark operations": "carto-darkmatter",
                "Detailed place names": "carto-positron",
                "Low-clutter background": "carto-positron-nolabels",
            }
            map_style = map_styles[map_theme] if show_labels else "carto-positron-nolabels"
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
                map_center=map_center,
                map_zoom=map_zoom,
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
                investigation_state.selected_source = map_selection
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
                accessible_table = accessible_table.assign(
                    selection_label=(
                        accessible_table["source"].astype(str)
                        + " · "
                        + accessible_table["country"].astype(str)
                        + " · "
                        + accessible_table["protocol"].astype(str).str.upper()
                    )
                )
                accessible_choice = st.selectbox(
                    "Inspect map observation",
                    ["No source selected"] + accessible_table["selection_label"].tolist(),
                    key="map_accessible_source",
                )
                if accessible_choice != "No source selected":
                    selected_row = accessible_table[
                        accessible_table["selection_label"] == accessible_choice
                    ].iloc[0]
                    accessible_selection = map_selection_from_row(
                        map_points[
                            (map_points["source"] == selected_row["source"])
                            & (map_points["country"] == selected_row["country"])
                            & (map_points["protocol"] == selected_row["protocol"])
                        ].iloc[0]
                    )

        with st.expander("Compare map observations (up to 3)", expanded=False):
            comparison_options = map_points.copy()
            comparison_options["comparison_label"] = (
                comparison_options["source"].astype(str)
                + " · "
                + comparison_options["country"].astype(str)
                + " · "
                + comparison_options["protocol"].astype(str).str.upper()
            )
            compare_sources = st.multiselect(
                "Map observations to compare",
                comparison_options["comparison_label"].tolist(),
                max_selections=3,
                key="map_compare_sources",
                help="Compares only reviewed map aggregates in this map window.",
            )
            source_comparison = build_source_comparison(
                comparison_options[comparison_options["comparison_label"].isin(compare_sources)]
            )
            if compare_sources:
                st.dataframe(
                    source_comparison,
                    width="stretch",
                    hide_index=True,
                    column_config={
                        "public_review_score": st.column_config.ProgressColumn(
                            "Highest public review score", min_value=0, max_value=100
                        ),
                        "latest_observation": st.column_config.TextColumn("Latest observation"),
                    },
                )
                st.caption(
                    "This is an aggregate comparison, not an identity, attribution, or automatic escalation decision."
                )
            else:
                st.caption(
                    "Choose up to three map observations to compare activity, sessions, public review score, and mapped techniques."
                )

        selected = map_selection or accessible_selection or st.session_state.get("_selected_map_source")
        if selected:
            selection_visible = (
                not map_points.empty
                and (
                    (map_points["source"] == selected["source"])
                    & (map_points["country"] == selected["country"])
                    & (map_points["protocol"] == selected["protocol"])
                ).any()
            )
            if not selection_visible:
                st.session_state.pop("_selected_map_source", None)
                investigation_state.selected_source = None
                selected = None
        investigation_state.selected_source = selected
        investigation_state.sync_to_session(st.session_state)
        if selected and st.button(
            "Focus selected source",
            key="focus_selected_source",
            help="Center and zoom on the selected pseudonymous source group. The zoom is visual only and does not increase geographic precision.",
        ):
            investigation_state.map_camera = "focus"
            investigation_state.map_focus = {
                key: str(selected[key]) for key in ("source", "country", "protocol")
            }
            investigation_state.sync_to_session(st.session_state)
            st.session_state["_map_revision"] = st.session_state.get("_map_revision", 0) + 1
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
        protocol_colors = {"modbus": "#EF4444", "s7": "#3B82F6", "iec104": "#FBBF24"}
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
            f"<div class='rail-card critical'><div class='rail-label'>High-severity observations</div><div class='rail-value red'>{critical_count:,}</div>"
            "<div class='rail-trend' style='color:#d32f2f'>High-severity events in the current filter</div></div>",
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
                & map_frame["source_country"].astype(str).eq(str(selected["country"]))
            ].copy()
            selected_techniques = flatten_techniques(selected_events)
            selected_triage = build_triage_queue(selected_events)
            top_triage = (
                selected_triage.sort_values(["score", "observed_at"], ascending=[False, False]).iloc[0]
                if not selected_triage.empty
                else None
            )
            review_scope = "|".join(
                str(selected[key]) for key in ("source", "country", "protocol")
            )
            review_key = sha256(review_scope.encode("utf-8")).hexdigest()[:16]
            confidence_values = (
                selected_techniques["confidence"].dropna().astype(str).str.lower().unique().tolist()
                if not selected_techniques.empty and "confidence" in selected_techniques
                else []
            )
            confidence_badges = "".join(
                f"<span class='evidence-badge'>{escape(value.upper())} confidence</span>"
                for value in sorted(confidence_values, key=lambda item: CONFIDENCE_ORDER.get(item, -1), reverse=True)
            ) or "<span class='evidence-badge'>No mapped confidence</span>"
            completeness_counts = (
                selected_triage["evidence completeness"].value_counts().to_dict()
                if not selected_triage.empty
                else {}
            )
            complete_fields = int(completeness_counts.get("complete fields", 0))
            detection_records = []
            for _, selected_event in selected_events.iterrows():
                decoded = {
                    column.removeprefix("decoded."): selected_event[column]
                    for column in selected_events.columns
                    if column.startswith("decoded.") and pd.notna(selected_event[column])
                }
                detection_records.append(
                    {
                        "event_id": str(selected_event.get("event_id", "sanitized-event")),
                        "event_type": str(selected_event.get("event_type", "")),
                        "protocol": str(selected_event.get("protocol", "")),
                        "decoded": decoded,
                    }
                )
            try:
                selected_predictions = preview_detections(detection_records, root=ROOT)
            except ValueError:
                selected_predictions = []
            detection_summary = (
                f"{len(selected_predictions):,} offline rule matches"
                if selected_predictions
                else "No offline rule match in this selected evidence"
            )
            st.markdown(
                f"""
<div class="investigation-drawer" aria-label="Selected source investigation drawer">
  <div class="drawer-kicker">Selected evidence drawer</div>
  <div class="drawer-title">Review this pseudonymous source group</div>
  <div class="detail-label">Pseudonymous source</div><div class="detail-value"><code>{safe['source']}</code></div>
  <div class="detail-label">Country / protocol</div><div class="detail-value">{safe['country']} · {safe['protocol'].upper()}</div>
  <div class="detail-label">Observed activity</div><div class="detail-value">{safe['events']} events · {safe['sessions']} sessions · {safe['control_attempts']} control attempts</div>
  <div class="detail-label">Repeat observations</div><div class="detail-value">{max(int(selected['events']) - int(selected['sessions']), 0)} after the first session</div>
  <div class="detail-label">Highest severity</div><div class="detail-value">{safe['max_severity'].upper()}</div>
  <div class="detail-label">Latest observation</div><div class="detail-value">{safe['last_seen']}</div>
  <div class="detail-label">ATT&amp;CK hypotheses</div><div class="detail-value">{safe['techniques']}</div>
  <div class="detail-label">Evidence confidence</div><div class="detail-value">{confidence_badges}</div>
  <div class="detail-label">Evidence completeness</div><div class="detail-value">{complete_fields:,}/{len(selected_triage):,} rows have the expected public fields</div>
  <div class="detail-label">Detection mapping</div><div class="detail-value">{escape(detection_summary)} · offline preview only</div>
  <div class="detail-label">Public review score</div><div class="detail-value">{int(top_triage['score']) if top_triage is not None else 0}/100 · {escape(str(top_triage['priority'])) if top_triage is not None else 'informational'}</div>
  <div class="detail-label">Why this public score is ranked</div><div class="detail-value">{escape(str(top_triage['evidence factors'])) if top_triage is not None else 'No scored protocol evidence.'}</div>
  <div class="detail-label">Recommended next step</div><div class="detail-value">{escape(next_step_for_priority(str(top_triage['priority'])) if top_triage is not None else 'Review the recorded evidence before deciding on any next action.')}</div>
  <div class="privacy-note">This panel contains reviewed public fields only. Raw IP addresses and payloads are never exposed.</div>
</div>
""",
                unsafe_allow_html=True,
            )
            action_left, action_right = st.columns(2)
            if action_left.button("Prepare Session Explorer", key="prepare_session_view", width="stretch"):
                st.session_state["session_focus_source"] = selected["source"]
                investigation_state.destination_view = "Session Explorer"
                investigation_state.sync_to_session(st.session_state)
                st.info("Session Explorer is ready for this source group. Open that labelled tab; filters and selection are preserved.")
            if action_right.button("Prepare ATT&CK review", key="prepare_attack_view", width="stretch"):
                if not selected_techniques.empty:
                    st.session_state["attack_focus_technique"] = str(selected_techniques.iloc[0]["technique_id"])
                investigation_state.destination_view = "ATT&CK Analysis"
                investigation_state.sync_to_session(st.session_state)
                st.info("ATT&CK Analysis is ready for this source context. Open that labelled tab; filters and selection are preserved.")
            with st.expander("Private local review note", expanded=False):
                st.selectbox(
                    "Review state",
                    ["Unreviewed", "Reviewed", "Needs more context", "False positive"],
                    key=f"local_review_state_{review_key}",
                )
                st.text_area(
                    "Analyst note (local session only)",
                    key=f"local_review_note_{review_key}",
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
        investigation_snapshot = investigation_state.to_snapshot(
            dataset_status="synthetic" if is_demo else "sanitized",
            fixture_version="demo_events.v1",
            quality=quality,
            filtered_events=len(filtered),
            mapped_sources=source_count,
            mapped_countries=int(map_points["country"].nunique()) if not map_points.empty else 0,
            excluded_events=int(quality["unmapped_events"]),
        )
        st.download_button(
            "Save local investigation snapshot",
            data=json.dumps(investigation_snapshot, indent=2) + "\n",
            file_name="ot-sentinel-investigation-snapshot.json",
            mime="application/json",
            width="stretch",
            help="Saves the current filters, map settings, selection and aggregate quality counts. Raw addresses, payloads and private notes are excluded.",
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
            color_discrete_map={"modbus": "#EF4444", "s7": "#3B82F6", "iec104": "#FBBF24"},
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
    render_scope_panel(
        "ATT&CK Analysis",
        [
            "Which evidence-qualified technique hypotheses occur in the filtered records.",
            "The recorded confidence and rationale attached to each mapping.",
        ],
        [
            "That a technique succeeded or that an intrusion occurred.",
            "Attribution, intent or the behavior of all UAE OT environments.",
        ],
    )
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
            "These numbers count matching activity records, not separate attacks. Each record still includes its confidence level and explanation."
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
    render_scope_panel(
        "Detection Preview",
        [
            "Which committed rule conditions match sanitized records offline.",
            "The last documented native result for controlled synthetic fixtures.",
        ],
        [
            "That a currently running SIEM or IDS fired on these dashboard records.",
            "Production detection quality, tuning suitability or attacker intent.",
        ],
    )
    st.info(
        "Offline prediction only. These matches use local rule logic and are not proof that a native Sigma, Wazuh or Suricata engine fired."
    )
    native_evidence = load_native_validation_evidence(str(NATIVE_VALIDATION_RECORD))
    evidence_left, evidence_mid, evidence_right = st.columns(3)
    evidence_left.metric(
        "Current view",
        "Offline prediction",
        help="Calculated now with the committed Python rule-matching logic.",
    )
    if native_evidence is None:
        evidence_mid.metric("Native Wazuh fixture", "Not recorded")
        evidence_right.metric("Native Suricata fixture", "Not recorded")
    else:
        evidence_mid.metric(
            "Native Wazuh fixture",
            "Passed",
            f"v{native_evidence.wazuh_version} · {native_evidence.validated_on}",
            delta_color="off",
            help="Historical local result using synthetic positive and negative fixtures.",
        )
        evidence_right.metric(
            "Native Suricata fixture",
            "Passed",
            f"v{native_evidence.suricata_version} · {native_evidence.validated_on}",
            delta_color="off",
            help="Historical local result using a synthetic offline PCAP.",
        )
    st.caption(
        "Native fixture status is historical evidence, not current runtime health. Re-run the documented tests after changing rules, images or lab isolation."
    )
    visible_event_ids = set(filtered["event_id"].astype(str))
    preview_records = [
        record for record in public_records if str(record.get("event_id", "")) in visible_event_ids
    ]
    backlog = detection_coverage_backlog(preview_records, root=ROOT)
    st.markdown("<div class='section-title'>Detection coverage backlog</div>", unsafe_allow_html=True)
    st.caption(
        "This is an engineering worklist for the selected synthetic or sanitized observations. "
        "A missing rule match is not proof of a detection gap, and a covered row is not proof of production effectiveness."
    )
    if not backlog:
        st.info("No decoded behavior is available for a coverage review in the current filters.")
    else:
        backlog_frame = pd.DataFrame(item.to_dict() for item in backlog)
        covered_behaviors = int((backlog_frame["status"] == "covered in pack").sum())
        follow_up_behaviors = int((backlog_frame["status"] != "covered in pack").sum())
        coverage_left, coverage_mid, coverage_right = st.columns(3)
        coverage_left.metric("Observed behaviors", f"{len(backlog_frame):,}")
        coverage_mid.metric("Covered in committed pack", f"{covered_behaviors:,}")
        coverage_right.metric(
            "Needs engineering review",
            f"{follow_up_behaviors:,}",
            help="This prioritizes review work; it does not claim a missing control or an incident.",
        )
        st.dataframe(
            backlog_frame[
                [
                    "protocol",
                    "operation",
                    "observed_events",
                    "mapped_techniques",
                    "rule_engines",
                    "fixture_coverage",
                    "status",
                    "next_action",
                ]
            ],
            width="stretch",
            hide_index=True,
            column_config={
                "observed_events": st.column_config.NumberColumn("Observed events", format="%d"),
                "mapped_techniques": "Mapped ATT&CK hypotheses",
                "rule_engines": "Offline rule engines",
                "fixture_coverage": "Fixture evidence",
                "next_action": "Recommended engineering action",
            },
        )
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
        selected_engines = p1.multiselect(
            "Detection engine", engines, default=engines, key="detection_engines"
        )
        selected_preview_protocols = p2.multiselect(
            "Detection protocol",
            protocols_for_preview,
            default=protocols_for_preview,
            key="detection_protocols",
        )
        selected_rules = p3.multiselect(
            "Detection rule", rules_for_preview, default=rules_for_preview, key="detection_rules"
        )
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
    render_scope_panel(
        "Triage",
        [
            "A reproducible priority order based on recorded protocol evidence.",
            "Whether required public evidence fields are complete, partial or limited.",
        ],
        [
            "Threat likelihood, business risk, compromise or required response.",
            "Identity, intent, attribution or confidence beyond the recorded evidence.",
        ],
    )
    st.caption(
        "Public review scores prioritize recorded decoy interactions using public-safe evidence. They do not establish attacker intent, identity, attribution, or compromise."
    )
    with st.expander("How the public review score is calculated", expanded=False):
        st.markdown(
            "- **Controller program transfer:** +45; **control command:** +40.\n"
            "- **Process read:** +15; **protocol-aware probe:** +10.\n"
            "- **Evidence-qualified ATT&CK mapping:** +5 low, +10 medium, +20 high confidence.\n"
            "- Private repeat and novelty indexing are intentionally excluded from this public dashboard."
        )
        st.caption("The result is capped at 100 and prioritizes human review. It is not a likelihood, identity, or automated-response score.")
    triage = build_triage_queue(filtered)
    if triage.empty:
        st.info("No events match the current filters.")
    else:
        scored = int((triage["score"] > 0).sum())
        high_review = int((triage["score"] >= 50).sum())
        top_score = int(triage["score"].max())
        complete_evidence = int((triage["evidence completeness"] == "complete fields").sum())
        q1, q2, q3, q4 = st.columns(4)
        q1.metric("Scored interactions", f"{scored:,}")
        q2.metric("High / urgent review", f"{high_review:,}")
        q3.metric("Highest public review score", f"{top_score}/100")
        q4.metric(
            "Complete evidence fields",
            f"{complete_evidence:,}/{len(triage):,}",
            help="Structural field completeness only; this is separate from review priority and does not prove the evidence is true.",
        )

        group_sessions = st.toggle(
            "Group review queue by session",
            value=True,
            key="triage_group_sessions",
            help="Combine events from the same bounded connection into one review row.",
        )
        review_queue = build_session_triage_queue(triage) if group_sessions else triage
        st.caption(
            "Review priority ranks behavior; evidence completeness reports field availability. Neither is a probability of compromise."
        )

        queue_col, chart_col = st.columns([1.65, 1], gap="large")
        with queue_col:
            st.dataframe(
                (
                    review_queue
                    if group_sessions
                    else review_queue.sort_values(
                        ["score", "observed_at"], ascending=[False, False]
                    )
                ),
                width="stretch",
                hide_index=True,
                column_config=(
                    {
                        "first_seen": st.column_config.DatetimeColumn(
                            "First seen (UTC)", format="YYYY-MM-DD HH:mm:ss"
                        ),
                        "last_seen": st.column_config.DatetimeColumn(
                            "Last seen (UTC)", format="YYYY-MM-DD HH:mm:ss"
                        ),
                        "highest score": st.column_config.ProgressColumn(
                            "Highest public review score", min_value=0, max_value=100
                        ),
                    }
                    if group_sessions
                    else {
                        "observed_at": st.column_config.DatetimeColumn(
                            "Observed (UTC)", format="YYYY-MM-DD HH:mm:ss"
                        ),
                        "score": st.column_config.ProgressColumn(
                            "Public review score", min_value=0, max_value=100
                        ),
                    }
                ),
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
    render_scope_panel(
        "Session Explorer",
        [
            "The time-ordered sanitized events associated with a bounded connection.",
            "Protocols, operations and mapped hypotheses recorded in that session.",
        ],
        [
            "That separate sessions belong to one person or coordinated campaign.",
            "Raw payload content, raw addresses, compromise or operational impact.",
        ],
    )
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
    display["evidence completeness"] = display["event_id"].map(
        triage_lookup["evidence completeness"] if not triage_all.empty else {}
    )
    display["mapping state"] = display["event_id"].map(
        triage_lookup["mapping state"] if not triage_all.empty else {}
    )
    columns = [
        "observed_at",
        "source",
        "source_country",
        "source_asn",
        "protocol",
        "operation",
        "severity",
        "evidence completeness",
        "mapping state",
        "techniques",
        "session_id",
    ]
    st.dataframe(
        display[columns].sort_values("observed_at", ascending=False),
        width="stretch",
        hide_index=True,
        column_config={"observed_at": st.column_config.DatetimeColumn("Observed (UTC)", format="YYYY-MM-DD HH:mm:ss")},
    )

with methodology:
    render_scope_panel(
        "Methodology",
        [
            "The documented collection, sanitization, mapping and validation boundaries.",
            "Which claims the project intentionally permits or rejects.",
        ],
        [
            "Regulatory compliance, production readiness or universal representativeness.",
            "Independent assurance beyond the tests and evidence recorded in this repository.",
        ],
    )
    st.markdown("<div class='section-title'>Read-only operator assurance</div>", unsafe_allow_html=True)
    st.caption(
        "Dashboard availability and dataset loading do not prove a sensor is running. This optional panel reads only allowlisted aggregate counters from a local health snapshot; it never connects to cloud infrastructure or reads raw events."
    )
    assurance = load_operator_assurance(ASSURANCE_HEALTH_PATH)
    if assurance is None:
        st.info("No local operator health snapshot is connected. Set OT_ASSURANCE_HEALTH_PATH to an approved local health JSON file to display redacted status.")
    else:
        assurance_left, assurance_mid, assurance_right, assurance_storage = st.columns(4)
        assurance_left.metric("Sensor report", assurance.state)
        assurance_mid.metric("Queue state", assurance.queue_state)
        assurance_right.metric("Delivery state", assurance.delivery_state)
        assurance_storage.metric("Private storage", assurance.storage_state)
        st.caption(
            f"Last health snapshot: {assurance.generated_at or 'not reported'} · Last event: {assurance.last_event_at or 'not reported'} · Total events: {assurance.total_events if assurance.total_events is not None else 'not reported'} · Capacity: {assurance.capacity_state}."
        )
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
    "<div class='footer-note'>Project by <a href='https://github.com/Afnan16312' target='_blank'>Mir Afnan Ali (@Afnan16312)</a> · OT Sentinel research build 0.3.0 · Times shown in UTC · MITRE ATT&CK® is a registered trademark of The MITRE Corporation.</div>",
    unsafe_allow_html=True,
)
