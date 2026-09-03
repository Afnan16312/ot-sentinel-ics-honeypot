import json

import pytest

from ot_sentinel.investigation_state import SNAPSHOT_SCHEMA, InvestigationState


def test_state_round_trips_only_reviewable_fields():
    state = InvestigationState(
        active_view="Session Explorer",
        destination_view="ATT&CK Analysis",
        selected_source={
            "source": "src-001",
            "country": "United Arab Emirates",
            "protocol": "modbus",
            "events": 4,
            "sessions": 2,
            "max_severity": "high",
            "first_seen": "2026-07-14T18:00:00Z",
            "last_seen": "2026-07-14T18:30:00Z",
            "control_attempts": 1,
            "techniques": "T0842",
            "source_ip": "192.0.2.10",
            "payload": "must never be exported",
        },
        map_camera="focus",
        map_mode="Source bubbles",
        map_window="Last 7 days",
        filters={"protocols": ["modbus"], "control_actions_only": True},
        walkthrough_step=3,
    )

    snapshot = state.to_snapshot(
        dataset_status="synthetic",
        fixture_version="demo_events.v1",
        quality={"plotted_events": 4},
        filtered_events=5,
        mapped_sources=1,
        mapped_countries=1,
        excluded_events=1,
    )
    encoded = json.dumps(snapshot)
    assert SNAPSHOT_SCHEMA in encoded
    assert "source_ip" not in encoded
    assert "must never be exported" not in encoded

    restored = InvestigationState.from_snapshot(snapshot)
    assert restored.active_view == "Session Explorer"
    assert restored.destination_view == "ATT&CK Analysis"
    assert restored.selected_source["source"] == "src-001"
    assert restored.map_camera == "focus"
    assert restored.walkthrough_step == 3
    assert restored.filters["control_actions_only"] is True


def test_state_syncs_legacy_widget_bindings_without_competing_selection_keys():
    session = {
        "map_mode": "Density",
        "map_window": "Last 24 hours",
        "map_theme": "Dark operations",
        "filter_protocols": ["s7"],
        "filter_control_only": True,
        "_selected_map_source": {
            "source": "src-002",
            "country": "Germany",
            "protocol": "s7",
            "events": 1,
        },
    }
    state = InvestigationState.from_session(session)
    assert state.map_mode == "Density"
    assert state.map_window == "Last 24 hours"
    assert state.filters["protocols"] == ["s7"]
    assert state.filters["control_actions_only"] is True
    assert state.selected_source["source"] == "src-002"

    state.destination_view = "Triage"
    state.sync_to_session(session)
    assert session["_investigation_state"] is state
    assert session["_next_view"] == "Triage"


def test_invalid_snapshot_is_rejected():
    with pytest.raises(ValueError, match="schema"):
        InvestigationState.from_snapshot({"schema_version": "old"})
