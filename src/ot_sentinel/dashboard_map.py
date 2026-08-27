"""Privacy-safe preparation and rendering for the public threat-observation map."""

from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

PROTOCOL_COLORS = {
    "modbus": "#4E8FB8",
    "s7": "#6A4DA0",
    "iec104": "#8175A8",
    "unknown": "#70808D",
}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
CONTROL_OPERATIONS = {
    "write_single",
    "write_multiple",
    "single_command",
    "setpoint_command",
    "program_download",
}
MAP_MODES = ("Flow view", "Source bubbles", "Density", "Time playback")
UAE_REGION = {"latitude": 24.4, "longitude": 54.4, "label": "UAE sensor region"}
MAX_FLOW_PATHS = 60
PUBLIC_COORDINATE_PRECISION = 1


def _series(frame: pd.DataFrame, name: str, default: Any) -> pd.Series:
    if name in frame:
        return frame[name]
    return pd.Series([default] * len(frame), index=frame.index)


def _highest_severity(values: Iterable[object]) -> str:
    normalized = [str(value).lower() for value in values if pd.notna(value)]
    return max(normalized, key=lambda item: SEVERITY_ORDER.get(item, -1), default="info")


def _flatten_techniques(values: Iterable[object]) -> str:
    technique_ids: set[str] = set()
    for value in values:
        if not isinstance(value, list):
            continue
        for technique_id in value:
            if technique_id:
                technique_ids.add(str(technique_id))
    return ", ".join(sorted(technique_ids)) or "None"


def _safe_iso(value: object) -> str:
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def filter_time_window(
    frame: pd.DataFrame,
    start: datetime | pd.Timestamp | None,
    end: datetime | pd.Timestamp | None,
) -> pd.DataFrame:
    """Return records inside an inclusive UTC window without mutating the input."""
    if frame.empty or "observed_at" not in frame:
        return frame.copy()

    observed = pd.to_datetime(frame["observed_at"], utc=True, errors="coerce")
    mask = observed.notna()
    if start is not None:
        start_time = pd.Timestamp(start)
        start_time = (
            start_time.tz_localize("UTC")
            if start_time.tzinfo is None
            else start_time.tz_convert("UTC")
        )
        mask &= observed >= start_time
    if end is not None:
        end_time = pd.Timestamp(end)
        end_time = (
            end_time.tz_localize("UTC") if end_time.tzinfo is None else end_time.tz_convert("UTC")
        )
        mask &= observed <= end_time
    result = frame.loc[mask].copy()
    result["observed_at"] = observed.loc[mask]
    return result


def prepare_map_points(frame: pd.DataFrame) -> pd.DataFrame:
    """Aggregate safe public events into selectable, deliberately coarse map points."""
    columns = [
        "source",
        "country",
        "latitude",
        "longitude",
        "protocol",
        "events",
        "sessions",
        "first_seen",
        "last_seen",
        "max_severity",
        "control_attempts",
        "public_review_score",
        "techniques",
    ]
    if frame.empty or not {"source_latitude", "source_longitude", "protocol"}.issubset(frame):
        return pd.DataFrame(columns=columns)

    working = frame.copy()
    working["_latitude"] = pd.to_numeric(working["source_latitude"], errors="coerce")
    working["_longitude"] = pd.to_numeric(working["source_longitude"], errors="coerce")
    valid = (
        working["_latitude"].between(-90, 90)
        & working["_longitude"].between(-180, 180)
    )
    working = working.loc[valid].copy()
    if working.empty:
        return pd.DataFrame(columns=columns)

    working["source"] = _series(working, "source_id", "redacted").fillna("redacted").astype(str)
    working["country"] = (
        _series(working, "source_country", "Unknown").fillna("Unknown").astype(str)
    )
    working["protocol"] = working["protocol"].fillna("unknown").astype(str).str.lower()
    working["session"] = _series(working, "session_id", "unknown").fillna("unknown").astype(str)
    working["severity_value"] = (
        _series(working, "severity", "info").fillna("info").astype(str).str.lower()
    )
    working["operation"] = (
        _series(working, "decoded.operation", "unknown").fillna("unknown").astype(str)
    )
    working["review_score"] = pd.to_numeric(
        _series(working, "triage_score", 0), errors="coerce"
    ).fillna(0)
    working["technique_value"] = _series(working, "technique_ids", [])
    working["observed"] = pd.to_datetime(
        _series(working, "observed_at", pd.NaT), utc=True, errors="coerce"
    )
    working["event_marker"] = 1

    group_columns = ["source", "country", "protocol"]
    grouped = working.groupby(group_columns, dropna=False, observed=True)
    points = grouped.agg(
        latitude=("_latitude", "median"),
        longitude=("_longitude", "median"),
        events=("event_marker", "sum"),
        sessions=("session", "nunique"),
        first_seen=("observed", "min"),
        last_seen=("observed", "max"),
        max_severity=("severity_value", _highest_severity),
        control_attempts=("operation", lambda values: int(values.isin(CONTROL_OPERATIONS).sum())),
        public_review_score=("review_score", "max"),
        techniques=("technique_value", _flatten_techniques),
    ).reset_index()
    # Public visualization is intentionally coarser than the input telemetry.
    points["latitude"] = points["latitude"].round(PUBLIC_COORDINATE_PRECISION)
    points["longitude"] = points["longitude"].round(PUBLIC_COORDINATE_PRECISION)
    points["public_review_score"] = points["public_review_score"].astype(int)
    return points[columns].sort_values(["events", "last_seen"], ascending=[False, False])


def prepare_playback_points(frame: pd.DataFrame, cadence: str = "6h") -> pd.DataFrame:
    """Create coarse temporal points for user-triggered map playback."""
    if frame.empty or "observed_at" not in frame:
        return pd.DataFrame()

    working = frame.copy()
    working["observed_at"] = pd.to_datetime(working["observed_at"], utc=True, errors="coerce")
    working["source_latitude"] = pd.to_numeric(working.get("source_latitude"), errors="coerce")
    working["source_longitude"] = pd.to_numeric(working.get("source_longitude"), errors="coerce")
    working = working[
        working["observed_at"].notna()
        & working["source_latitude"].between(-90, 90)
        & working["source_longitude"].between(-180, 180)
    ].copy()
    if working.empty:
        return pd.DataFrame()

    working["latitude"] = working["source_latitude"].round(PUBLIC_COORDINATE_PRECISION)
    working["longitude"] = working["source_longitude"].round(PUBLIC_COORDINATE_PRECISION)
    working["source"] = _series(working, "source_id", "redacted").fillna("redacted").astype(str)
    working["country"] = (
        _series(working, "source_country", "Unknown").fillna("Unknown").astype(str)
    )
    working["protocol"] = working["protocol"].fillna("unknown").astype(str).str.lower()
    working["time_bucket"] = working["observed_at"].dt.floor(cadence)
    result = (
        working.groupby(
            ["time_bucket", "source", "country", "latitude", "longitude", "protocol"],
            observed=True,
        )
        .size()
        .reset_index(name="events")
    )
    result = result.sort_values(["time_bucket", "events"], ascending=[True, False])
    result["time_bucket"] = result["time_bucket"].dt.strftime("%Y-%m-%d · %H:%M")
    return result


def _complete_playback_protocol_grid(playback: pd.DataFrame) -> pd.DataFrame:
    """Keep Plotly animation trace indexes stable when a protocol is absent in a frame."""
    if playback.empty:
        return playback.copy()

    buckets = playback["time_bucket"].drop_duplicates().tolist()
    protocols = sorted(playback["protocol"].dropna().unique().tolist())
    present = set(zip(playback["time_bucket"], playback["protocol"], strict=False))
    placeholders: list[dict[str, object]] = []
    for bucket in buckets:
        for protocol in protocols:
            if (bucket, protocol) in present:
                continue
            placeholders.append(
                {
                    "time_bucket": bucket,
                    "source": "No observation",
                    "country": "No observation in this window",
                    "latitude": 0.0,
                    "longitude": 0.0,
                    "protocol": protocol,
                    "events": 0,
                }
            )
    if not placeholders:
        return playback.copy()
    return pd.concat([playback, pd.DataFrame(placeholders)], ignore_index=True).sort_values(
        ["time_bucket", "protocol", "events"], ascending=[True, True, False]
    )


def _attach_playback_investigation_fields(
    playback: pd.DataFrame, points: pd.DataFrame
) -> pd.DataFrame:
    """Attach the same reviewed selection contract used by non-animated map modes."""
    summary = points[
        [
            "source",
            "country",
            "protocol",
            "events",
            "sessions",
            "max_severity",
            "first_seen",
            "last_seen",
            "control_attempts",
            "techniques",
        ]
    ].rename(columns={"events": "visible_events"})
    result = playback.merge(summary, on=["source", "country", "protocol"], how="left")
    numeric_defaults = {"visible_events": 0, "sessions": 0, "control_attempts": 0}
    text_defaults = {
        "max_severity": "info",
        "first_seen": "",
        "last_seen": "",
        "techniques": "None",
    }
    for column, default in numeric_defaults.items():
        result[column] = result[column].fillna(default).astype(int)
    for column, default in text_defaults.items():
        result[column] = result[column].fillna(default)
    return result


def map_quality(frame: pd.DataFrame) -> dict[str, int]:
    """Return explainable map coverage counts for the current filtered window."""
    if frame.empty:
        return {"events": 0, "plotted_events": 0, "unmapped_events": 0, "countries": 0}
    latitude = pd.to_numeric(_series(frame, "source_latitude", None), errors="coerce")
    longitude = pd.to_numeric(_series(frame, "source_longitude", None), errors="coerce")
    valid = latitude.between(-90, 90) & longitude.between(-180, 180)
    country = _series(frame.loc[valid], "source_country", "Unknown")
    return {
        "events": len(frame),
        "plotted_events": int(valid.sum()),
        "unmapped_events": int((~valid).sum()),
        "countries": int(country.dropna().nunique()),
    }


def build_window_comparison(current: pd.DataFrame, previous: pd.DataFrame) -> pd.DataFrame:
    """Compare two recorded windows using aggregate fields only."""

    def metrics(frame: pd.DataFrame) -> dict[str, int]:
        points = prepare_map_points(frame)
        operations = _series(frame, "decoded.operation", "unknown")
        return {
            "Events": len(frame),
            "Sessions": int(_series(frame, "session_id", "unknown").nunique()),
            "Control actions": int(operations.isin(CONTROL_OPERATIONS).sum()),
            "Mapped sources": int(points["source"].nunique()) if not points.empty else 0,
        }

    current_metrics = metrics(current)
    previous_metrics = metrics(previous)
    return pd.DataFrame(
        {
            "metric": list(current_metrics),
            "Current window": list(current_metrics.values()),
            "Previous window": [previous_metrics[name] for name in current_metrics],
        }
    ).assign(Change=lambda result: result["Current window"] - result["Previous window"])


def summarize_window_change(comparison: pd.DataFrame) -> str:
    """Turn a safe aggregate comparison into cautious, readable copy."""

    if comparison.empty:
        return "No recorded-window comparison is available."

    changed = comparison[comparison["Change"] != 0]
    if changed.empty:
        return "No aggregate count changed between these recorded windows."

    phrases: list[str] = []
    for _, row in changed.iterrows():
        current = int(row["Current window"])
        previous = int(row["Previous window"])
        if previous == 0 and current > 0:
            phrases.append(f"{row['metric']}: {current:,} in the current window; no prior records")
            continue
        direction = "increased" if int(row["Change"]) > 0 else "decreased"
        phrases.append(
            f"{row['metric']} {direction} by {abs(int(row['Change'])):,} "
            f"({previous:,} to {current:,})"
        )
    return "; ".join(phrases[:2]) + ". Counts compare recorded windows only; they do not prove a rate, cause, or attribution."


def build_source_comparison(points: pd.DataFrame) -> pd.DataFrame:
    """Return an allowlisted comparison for selected map aggregates."""

    columns = [
        "source",
        "country",
        "protocol",
        "events",
        "sessions",
        "control_attempts",
        "public_review_score",
        "latest_observation",
        "techniques",
    ]
    if points.empty:
        return pd.DataFrame(columns=columns)

    result = points.reindex(columns=columns[:-2] + ["last_seen", "techniques"]).rename(
        columns={"last_seen": "latest_observation"}
    )
    result["public_review_score"] = pd.to_numeric(
        result["public_review_score"], errors="coerce"
    ).fillna(0).astype(int)
    result["latest_observation"] = result["latest_observation"].apply(_safe_iso)
    return result.sort_values(
        ["public_review_score", "events", "source"], ascending=[False, False, True]
    ).reindex(columns=columns)


def _marker_sizes(events: pd.Series) -> list[float]:
    return [min(34.0, 9.0 + math.sqrt(max(float(value), 1.0)) * 3.4) for value in events]


def _custom_data(points: pd.DataFrame) -> list[list[object]]:
    return [
        [
            row.source,
            row.country,
            row.protocol,
            int(row.events),
            int(row.sessions),
            row.max_severity,
            _safe_iso(row.first_seen),
            _safe_iso(row.last_seen),
            int(row.control_attempts),
            row.techniques,
            max(int(row.events) - int(row.sessions), 0),
        ]
        for row in points.itertuples()
    ]


def _great_circle_path(
    start_latitude: float,
    start_longitude: float,
    end_latitude: float,
    end_longitude: float,
    steps: int = 28,
) -> tuple[list[float], list[float]]:
    """Interpolate a stable great-circle path for a restrained flow overlay."""
    lat1, lon1, lat2, lon2 = map(
        math.radians, (start_latitude, start_longitude, end_latitude, end_longitude)
    )
    a = (math.cos(lat1) * math.cos(lon1), math.cos(lat1) * math.sin(lon1), math.sin(lat1))
    b = (math.cos(lat2) * math.cos(lon2), math.cos(lat2) * math.sin(lon2), math.sin(lat2))
    dot = max(-1.0, min(1.0, sum(left * right for left, right in zip(a, b, strict=True))))
    omega = math.acos(dot)
    if abs(omega) < 1e-8:
        return [start_latitude, end_latitude], [start_longitude, end_longitude]

    sin_omega = math.sin(omega)
    latitudes: list[float] = []
    longitudes: list[float] = []
    for index in range(steps):
        fraction = index / (steps - 1)
        first = math.sin((1.0 - fraction) * omega) / sin_omega
        second = math.sin(fraction * omega) / sin_omega
        x = first * a[0] + second * b[0]
        y = first * a[1] + second * b[1]
        z = first * a[2] + second * b[2]
        latitudes.append(math.degrees(math.atan2(z, math.sqrt(x * x + y * y))))
        longitudes.append(math.degrees(math.atan2(y, x)))
    return latitudes, longitudes


def _add_source_markers(fig: go.Figure, points: pd.DataFrame) -> None:
    for protocol in sorted(points["protocol"].unique()):
        protocol_points = points[points["protocol"] == protocol]
        fig.add_trace(
            go.Scattermap(
                lat=protocol_points["latitude"],
                lon=protocol_points["longitude"],
                mode="markers",
                name=protocol.upper(),
                marker={
                    "size": _marker_sizes(protocol_points["events"]),
                    "color": PROTOCOL_COLORS.get(protocol, PROTOCOL_COLORS["unknown"]),
                    "opacity": 0.88,
                },
                customdata=_custom_data(protocol_points),
                hovertemplate=(
                    "<b>%{customdata[1]}</b><br>"
                    "%{customdata[0]} · %{customdata[2]}<br>"
                    "%{customdata[3]} events · %{customdata[4]} sessions<br>"
                    "Repeated observations: %{customdata[10]}<br>"
                    "Highest severity: %{customdata[5]}<br>"
                    "Latest: %{customdata[7]}<br>"
                    "Select for investigation<extra></extra>"
                ),
            )
        )


def _add_offline_source_markers(fig: go.Figure, points: pd.DataFrame) -> None:
    """Render selectable source aggregates without external map tiles."""
    for protocol in sorted(points["protocol"].unique()):
        protocol_points = points[points["protocol"] == protocol]
        fig.add_trace(
            go.Scattergeo(
                lat=protocol_points["latitude"],
                lon=protocol_points["longitude"],
                mode="markers",
                name=protocol.upper(),
                marker={
                    "size": _marker_sizes(protocol_points["events"]),
                    "color": PROTOCOL_COLORS.get(protocol, PROTOCOL_COLORS["unknown"]),
                    "opacity": 0.88,
                    "line": {"color": "#FFFFFF", "width": 1},
                },
                customdata=_custom_data(protocol_points),
                hovertemplate=(
                    "<b>%{customdata[1]}</b><br>"
                    "%{customdata[0]} · %{customdata[2]}<br>"
                    "%{customdata[3]} events · %{customdata[4]} sessions<br>"
                    "Repeated observations: %{customdata[10]}<br>"
                    "Highest severity: %{customdata[5]}<br>"
                    "Select for investigation<extra></extra>"
                ),
            )
        )


def _build_offline_map(
    points: pd.DataFrame,
    *,
    mode: str,
    show_flows: bool,
    show_region: bool,
    revision: str,
) -> go.Figure:
    """Build a tile-free geographic view for disconnected or restricted networks."""
    figure = go.Figure()
    if mode == "Flow view" and show_flows:
        for row in points.nlargest(MAX_FLOW_PATHS, "events").itertuples():
            latitudes, longitudes = _great_circle_path(
                float(row.latitude),
                float(row.longitude),
                float(UAE_REGION["latitude"]),
                float(UAE_REGION["longitude"]),
            )
            figure.add_trace(
                go.Scattergeo(
                    lat=latitudes,
                    lon=longitudes,
                    mode="lines",
                    line={
                        "width": min(3.0, 0.7 + math.log1p(float(row.events)) * 0.55),
                        "color": PROTOCOL_COLORS.get(row.protocol, PROTOCOL_COLORS["unknown"]),
                    },
                    opacity=0.34,
                    hoverinfo="skip",
                    showlegend=False,
                )
            )
    _add_offline_source_markers(figure, points)
    if show_region:
        figure.add_trace(
            go.Scattergeo(
                lat=[UAE_REGION["latitude"]],
                lon=[UAE_REGION["longitude"]],
                mode="markers",
                name="Approximate UAE region",
                marker={"size": 10, "color": "#FFFFFF", "line": {"color": "#667085", "width": 1}},
                hovertemplate="Approximate UAE sensor region<extra></extra>",
                showlegend=False,
            )
        )
    figure.update_layout(
        height=585,
        margin={"l": 0, "r": 0, "t": 0, "b": 0},
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        geo={
            "projection": {"type": "natural earth"},
            "showland": True,
            "landcolor": "#EEF1F5",
            "showocean": True,
            "oceancolor": "#F5F9FC",
            "showlakes": True,
            "lakecolor": "#F5F9FC",
            "showcoastlines": True,
            "coastlinecolor": "#B8C2CF",
            "showframe": False,
        },
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 0.01,
            "xanchor": "left",
            "x": 0.015,
            "bgcolor": "rgba(255,255,255,.92)",
            "bordercolor": "#D1D5DB",
            "borderwidth": 1,
            "font": {"color": "#414751", "size": 11},
        },
        hoverlabel={"bgcolor": "#FFFFFF", "bordercolor": "#D1D5DB", "font_color": "#1A1C1E"},
        uirevision=revision,
        clickmode="event+select",
        dragmode="pan",
    )
    return figure


def _add_region_marker(fig: go.Figure) -> None:
    # Use a native MapLibre circle layer instead of a symbol trace. This keeps the
    # broad public region visible without requesting an external marker sprite.
    fig.update_layout(
        map_layers=[
            {
                "type": "circle",
                "source": {
                    "type": "FeatureCollection",
                    "features": [
                        {
                            "type": "Feature",
                            "properties": {},
                            "geometry": {
                                "type": "Point",
                                "coordinates": [
                                    UAE_REGION["longitude"],
                                    UAE_REGION["latitude"],
                                ],
                            },
                        }
                    ],
                },
                "circle": {"radius": 8},
                "color": "#D5DEE5",
                "opacity": 1,
            }
        ]
    )


def _base_layout(fig: go.Figure, map_style: str, revision: str) -> go.Figure:
    fig.update_layout(
        height=585,
        margin={"l": 0, "r": 0, "t": 0, "b": 0},
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        map={
            "style": map_style,
            "center": {"lat": 18, "lon": 25},
            "zoom": 0.75,
            "bearing": 0,
            "pitch": 0,
        },
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 0.01,
            "xanchor": "left",
            "x": 0.015,
            "bgcolor": "rgba(255,255,255,.92)",
            "bordercolor": "#D1D5DB",
            "borderwidth": 1,
            "font": {"color": "#414751", "size": 11},
        },
        hoverlabel={"bgcolor": "#FFFFFF", "bordercolor": "#D1D5DB", "font_color": "#1A1C1E"},
        uirevision=revision,
        clickmode="event+select",
        dragmode="pan",
    )
    return fig


def build_threat_map(
    points: pd.DataFrame,
    *,
    mode: str,
    event_frame: pd.DataFrame | None = None,
    show_flows: bool = True,
    show_region: bool = True,
    map_style: str = "carto-positron-nolabels",
    revision: str = "ot-sentinel-map-v1",
    offline_map: bool = False,
) -> go.Figure:
    """Build one of the supported MapLibre investigation views."""
    if mode not in MAP_MODES:
        raise ValueError(f"Unsupported map mode: {mode}")

    if points.empty:
        figure = go.Figure()
        return _base_layout(figure, map_style, revision)

    if offline_map and mode != "Time playback":
        return _build_offline_map(
            points,
            mode=mode,
            show_flows=show_flows,
            show_region=show_region,
            revision=revision,
        )

    if mode == "Time playback":
        playback = prepare_playback_points(event_frame if event_frame is not None else pd.DataFrame())
        if playback.empty:
            return _base_layout(go.Figure(), map_style, revision)
        playback = _complete_playback_protocol_grid(playback)
        playback = _attach_playback_investigation_fields(playback, points)
        bucket_order = playback["time_bucket"].drop_duplicates().tolist()
        protocol_order = sorted(playback["protocol"].dropna().unique().tolist())
        figure = px.scatter_map(
            playback,
            lat="latitude",
            lon="longitude",
            color="protocol",
            size="events",
            animation_frame="time_bucket",
            hover_name="country",
            hover_data={"source": True, "events": True, "latitude": False, "longitude": False},
            custom_data=[
                "source",
                "country",
                "protocol",
                "visible_events",
                "sessions",
                "max_severity",
                "first_seen",
                "last_seen",
                "control_attempts",
                "techniques",
            ],
            color_discrete_map=PROTOCOL_COLORS,
            category_orders={"time_bucket": bucket_order, "protocol": protocol_order},
            size_max=30,
        )
        figure.update_layout(transition={"duration": 160})
        for menu in figure.layout.updatemenus:
            if not menu.buttons:
                continue
            menu.buttons[0].args = [
                None,
                {
                    "frame": {"duration": 250, "redraw": False},
                    "mode": "immediate",
                    "fromcurrent": True,
                    "transition": {"duration": 160, "easing": "linear"},
                },
            ]
            # Plotly's generated pause button rejects its animation promise when
            # embedded in Streamlit. Keep a finite Play action and draggable
            # timeline instead of exposing a control that logs a browser error.
            menu.buttons = [menu.buttons[0]]
        for slider in figure.layout.sliders:
            slider.currentvalue = {
                "prefix": "UTC window: ",
                "font": {"color": "#414751", "size": 11},
            }
        if show_region:
            _add_region_marker(figure)
        return _base_layout(figure, map_style, revision)

    figure = go.Figure()
    if mode == "Flow view" and show_flows:
        for row in points.nlargest(MAX_FLOW_PATHS, "events").itertuples():
            latitudes, longitudes = _great_circle_path(
                float(row.latitude),
                float(row.longitude),
                float(UAE_REGION["latitude"]),
                float(UAE_REGION["longitude"]),
            )
            figure.add_trace(
                go.Scattermap(
                    lat=latitudes,
                    lon=longitudes,
                    mode="lines",
                    line={
                        "width": min(3.0, 0.7 + math.log1p(float(row.events)) * 0.55),
                        "color": PROTOCOL_COLORS.get(row.protocol, PROTOCOL_COLORS["unknown"]),
                    },
                    opacity=0.34,
                    hoverinfo="skip",
                    showlegend=False,
                )
            )

    if mode == "Density":
        figure.add_trace(
            go.Densitymap(
                lat=points["latitude"],
                lon=points["longitude"],
                z=points["events"],
                radius=34,
                colorscale=[
                    [0.0, "rgba(14,23,30,0)"],
                    [0.25, "#9CC4E8"],
                    [0.6, "#B8A4D6"],
                    [1.0, "#D32F2F"],
                ],
                showscale=False,
                hoverinfo="skip",
                name="Event density",
            )
        )

    _add_source_markers(figure, points)
    if show_region:
        _add_region_marker(figure)
    return _base_layout(figure, map_style, revision)


def selection_from_plotly_state(state: Any) -> dict[str, object] | None:
    """Extract only the known privacy-safe fields from a Streamlit Plotly selection."""
    if not state:
        return None
    try:
        selected_points = state["selection"]["points"]
    except (KeyError, TypeError):
        return None
    if not selected_points:
        return None
    custom = selected_points[-1].get("customdata")
    if not isinstance(custom, (list, tuple)) or len(custom) < 10:
        return None
    return {
        "source": str(custom[0]),
        "country": str(custom[1]),
        "protocol": str(custom[2]),
        "events": int(custom[3]),
        "sessions": int(custom[4]),
        "max_severity": str(custom[5]),
        "first_seen": str(custom[6]),
        "last_seen": str(custom[7]),
        "control_attempts": int(custom[8]),
        "techniques": str(custom[9]),
    }


def map_points_csv(points: pd.DataFrame) -> str:
    """Export only the reviewed, coarse aggregate schema used by the map."""
    safe_columns = [
        "source",
        "country",
        "latitude",
        "longitude",
        "protocol",
        "events",
        "sessions",
        "first_seen",
        "last_seen",
        "max_severity",
        "control_attempts",
        "techniques",
    ]
    return points.reindex(columns=safe_columns).to_csv(index=False)
