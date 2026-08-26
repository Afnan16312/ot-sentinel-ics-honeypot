from __future__ import annotations

import json
from datetime import UTC, datetime

import pandas as pd
import pytest

from ot_sentinel.dashboard_map import (
    MAP_MODES,
    MAX_FLOW_PATHS,
    build_threat_map,
    filter_time_window,
    map_points_csv,
    map_quality,
    prepare_map_points,
    selection_from_plotly_state,
)


def event(
    event_id: str,
    *,
    observed_at: str = "2026-08-01T00:00:00+00:00",
    source: str = "src-public-01",
    country: str = "Exampleland",
    latitude: float | None = 25.12345,
    longitude: float | None = 55.98765,
    protocol: str = "modbus",
    operation: str = "device_probe",
    severity: str = "info",
) -> dict:
    return {
        "event_id": event_id,
        "session_id": f"session-{event_id}",
        "observed_at": observed_at,
        "source_id": source,
        "source_country": country,
        "source_latitude": latitude,
        "source_longitude": longitude,
        "protocol": protocol,
        "decoded.operation": operation,
        "severity": severity,
        "technique_ids": ["T0846.001"],
        # These hostile/private-looking fields must never reach a map output.
        "source_ip": "198.51.100.77",
        "raw_payload_hex": "736563726574",
        "cloud_ocid": "ocid1.example.private",
    }


def frame(*records: dict) -> pd.DataFrame:
    result = pd.DataFrame(records)
    result["observed_at"] = pd.to_datetime(result["observed_at"], utc=True)
    return result


def test_time_window_is_inclusive_and_normalizes_naive_boundaries():
    records = frame(
        event("a", observed_at="2026-08-01T00:00:00+00:00"),
        event("b", observed_at="2026-08-02T00:00:00+00:00"),
        event("c", observed_at="2026-08-03T00:00:00+00:00"),
    )

    result = filter_time_window(
        records,
        pd.Timestamp("2026-08-01"),
        datetime(2026, 8, 2, tzinfo=UTC),
    )

    assert result["event_id"].tolist() == ["a", "b"]


def test_map_points_cluster_by_pseudonymous_source_protocol_and_round_coordinates():
    records = frame(
        event("a", latitude=25.12, longitude=55.98, operation="write_single", severity="high"),
        event("b", latitude=25.18, longitude=56.02),
        event("c", protocol="s7"),
    )

    points = prepare_map_points(records)

    assert len(points) == 2
    modbus = points[points["protocol"] == "modbus"].iloc[0]
    assert modbus["events"] == 2
    assert modbus["sessions"] == 2
    assert modbus["control_attempts"] == 1
    assert modbus["max_severity"] == "high"
    assert modbus["latitude"] == 25.2
    assert modbus["longitude"] == 56.0


@pytest.mark.parametrize(
    ("latitude", "longitude"),
    [(None, 55.0), (25.0, None), (91.0, 55.0), (25.0, 181.0)],
)
def test_invalid_or_missing_coordinates_are_excluded(latitude, longitude):
    records = frame(event("bad", latitude=latitude, longitude=longitude))

    assert prepare_map_points(records).empty
    assert map_quality(records) == {
        "events": 1,
        "plotted_events": 0,
        "unmapped_events": 1,
        "countries": 0,
    }


def test_all_map_modes_build_and_playback_has_frames():
    records = frame(
        event("a", observed_at="2026-08-01T00:00:00+00:00"),
        event("b", observed_at="2026-08-01T06:00:00+00:00", protocol="s7"),
        event("c", observed_at="2026-08-01T12:00:00+00:00", protocol="iec104"),
    )
    points = prepare_map_points(records)

    figures = {
        mode: build_threat_map(points, mode=mode, event_frame=records) for mode in MAP_MODES
    }

    assert all(figure.layout.map.style == "carto-positron-nolabels" for figure in figures.values())
    assert all(len(figure.layout.map.layers) == 1 for figure in figures.values())
    assert len(figures["Flow view"].data) > len(figures["Source bubbles"].data)
    assert any(trace.type == "densitymap" for trace in figures["Density"].data)
    assert len(figures["Time playback"].frames) == 3
    playback = figures["Time playback"]
    assert len(playback.data) == 3
    assert all(len(animation_frame.data) == len(playback.data) for animation_frame in playback.frames)
    assert len(playback.layout.updatemenus[0].buttons) == 1
    assert playback.layout.updatemenus[0].buttons[0].args[1]["frame"]["redraw"] is False
    visible_custom_data = next(
        row
        for trace in playback.data
        for row in trace.customdata
        if row[0] != "No observation"
    )
    assert len(visible_custom_data) >= 10
    assert selection_from_plotly_state(
        {"selection": {"points": [{"customdata": list(visible_custom_data)}]}}
    ) == {
        "source": str(visible_custom_data[0]),
        "country": str(visible_custom_data[1]),
        "protocol": str(visible_custom_data[2]),
        "events": int(visible_custom_data[3]),
        "sessions": int(visible_custom_data[4]),
        "max_severity": str(visible_custom_data[5]),
        "first_seen": str(visible_custom_data[6]),
        "last_seen": str(visible_custom_data[7]),
        "control_attempts": int(visible_custom_data[8]),
        "techniques": str(visible_custom_data[9]),
    }


def test_flow_layer_is_bounded_for_rendering_reliability():
    records = frame(
        *[
            event(
                f"event-{index}",
                source=f"source-{index}",
                latitude=-70 + index,
                longitude=-150 + index,
            )
            for index in range(MAX_FLOW_PATHS + 15)
        ]
    )
    points = prepare_map_points(records)

    figure = build_threat_map(points, mode="Flow view", event_frame=records)
    line_traces = [trace for trace in figure.data if trace.mode == "lines"]

    assert len(line_traces) == MAX_FLOW_PATHS


def test_flow_overlay_can_be_disabled_without_removing_interactive_sources():
    records = frame(
        event("a", protocol="modbus"),
        event("b", protocol="s7"),
    )
    points = prepare_map_points(records)

    figure = build_threat_map(
        points,
        mode="Flow view",
        event_frame=records,
        show_flows=False,
    )

    assert not [trace for trace in figure.data if trace.mode == "lines"]
    assert {trace.name for trace in figure.data} == {"MODBUS", "S7"}


def test_offline_map_fallback_uses_tile_free_geo_and_preserves_selection_data():
    records = frame(event("a"), event("b", protocol="s7"))
    figure = build_threat_map(
        prepare_map_points(records),
        mode="Source bubbles",
        event_frame=records,
        offline_map=True,
    )

    assert figure.layout.geo.projection.type == "natural earth"
    assert figure.layout.map.style is None
    assert all(trace.customdata is not None for trace in figure.data if trace.name in {"MODBUS", "S7"})


def test_sensor_region_uses_a_native_circle_layer_instead_of_an_external_sprite():
    records = frame(event("a"))
    figure = build_threat_map(
        prepare_map_points(records),
        mode="Source bubbles",
        event_frame=records,
    )

    assert len(figure.layout.map.layers) == 1
    region_layer = figure.layout.map.layers[0]
    assert region_layer.type == "circle"
    assert region_layer.circle.radius == 8
    assert all(trace.name != "UAE sensor region" for trace in figure.data)


def test_map_outputs_are_privacy_safe():
    records = frame(event("private-test"))
    points = prepare_map_points(records)
    figure = build_threat_map(points, mode="Source bubbles", event_frame=records)

    serialized = json.dumps(figure.to_plotly_json())
    exported = map_points_csv(points)
    for private_value in ("198.51.100.77", "736563726574", "ocid1.example.private"):
        assert private_value not in serialized
        assert private_value not in exported
    for private_field in ("source_ip", "raw_payload_hex", "cloud_ocid"):
        assert private_field not in exported


def test_selection_extracts_only_the_reviewed_contract():
    state = {
        "selection": {
            "points": [
                {
                    "customdata": [
                        "src-public-01",
                        "Exampleland",
                        "modbus",
                        12,
                        3,
                        "high",
                        "2026-08-01T00:00:00+00:00",
                        "2026-08-02T00:00:00+00:00",
                        2,
                        "T0846.001",
                    ]
                }
            ]
        }
    }

    result = selection_from_plotly_state(state)

    assert result == {
        "source": "src-public-01",
        "country": "Exampleland",
        "protocol": "modbus",
        "events": 12,
        "sessions": 3,
        "max_severity": "high",
        "first_seen": "2026-08-01T00:00:00+00:00",
        "last_seen": "2026-08-02T00:00:00+00:00",
        "control_attempts": 2,
        "techniques": "T0846.001",
    }
    assert selection_from_plotly_state({"selection": {"points": []}}) is None
    assert selection_from_plotly_state({"selection": {"points": [{"customdata": ["short"]}]}}) is None


def test_unknown_mode_fails_closed():
    records = frame(event("a"))
    with pytest.raises(ValueError, match="Unsupported map mode"):
        build_threat_map(prepare_map_points(records), mode="Unknown", event_frame=records)
