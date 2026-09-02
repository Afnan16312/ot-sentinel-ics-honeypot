"""Small, privacy-safe state contract for the dashboard investigation workflow."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

SNAPSHOT_SCHEMA = "ot-sentinel-investigation-snapshot.v1"
VIEW_NAMES = (
    "Observatory",
    "ATT&CK Analysis",
    "Detection Preview",
    "Triage",
    "Session Explorer",
    "Methodology",
)
MAP_MODES = ("Flow view", "Source bubbles", "Density", "Time playback")
MAP_WINDOWS = (
    "All observations",
    "Last 24 hours",
    "Last 7 days",
    "Last 14 days",
    "Custom UTC range",
)
MAP_THEMES = ("Dark operations", "Detailed place names", "Low-clutter background")
FILTER_NAMES = (
    "protocols",
    "severity",
    "source_countries",
    "mapping_confidence",
    "triage_priorities",
    "control_actions_only",
)
SELECTION_FIELDS = (
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
)


def _safe_selection(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    required = {"source", "country", "protocol"}
    if not required.issubset(value):
        return None
    result: dict[str, object] = {}
    for field_name in SELECTION_FIELDS:
        item = value.get(field_name)
        if field_name in {"events", "sessions", "control_attempts"}:
            try:
                result[field_name] = max(0, int(item))
            except (TypeError, ValueError):
                result[field_name] = 0
        else:
            result[field_name] = str(item or "")
    return result


def _safe_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return sorted({str(item) for item in value if str(item)})


@dataclass
class InvestigationState:
    """The single workflow state shared by the dashboard views.

    Streamlit widget keys are treated as UI bindings. This object is the
    canonical, exportable representation used when a view prepares the next
    investigation step or a user saves a local snapshot.
    """

    active_view: str = "Observatory"
    destination_view: str | None = None
    selected_source: dict[str, object] | None = None
    selected_event_id: str | None = None
    map_focus: dict[str, str] | None = None
    map_camera: str = "overview"
    map_mode: str = "Flow view"
    map_window: str = "All observations"
    map_theme: str = "Dark operations"
    walkthrough_step: int = 0
    filters: dict[str, object] = field(default_factory=dict)

    @classmethod
    def from_session(cls, session: Mapping[str, object]) -> InvestigationState:
        saved = session.get("_investigation_state")
        if isinstance(saved, cls):
            state = saved
        else:
            state = cls()
        state.active_view = _valid_view(session.get("_active_view", state.active_view))
        state.destination_view = _valid_view(session.get("_next_view", state.destination_view), allow_none=True)
        state.selected_source = _safe_selection(
            session.get("_selected_map_source", state.selected_source)
        )
        event_id = session.get("_selected_event_id", state.selected_event_id)
        state.selected_event_id = str(event_id) if event_id else None
        focus = session.get("_map_focus", state.map_focus)
        state.map_focus = (
            {"source": str(focus.get("source", "")), "country": str(focus.get("country", "")), "protocol": str(focus.get("protocol", ""))}
            if isinstance(focus, Mapping) and focus.get("source")
            else None
        )
        state.map_camera = str(session.get("_map_camera", state.map_camera))
        state.map_mode = str(session.get("map_mode", state.map_mode))
        state.map_window = str(session.get("map_window", state.map_window))
        state.map_theme = str(session.get("map_theme", state.map_theme))
        try:
            state.walkthrough_step = min(5, max(0, int(session.get("_walkthrough_step", state.walkthrough_step))))
        except (TypeError, ValueError):
            state.walkthrough_step = 0
        state.filters = {
            "protocols": _safe_list(session.get("filter_protocols", state.filters.get("protocols", []))),
            "severity": _safe_list(session.get("filter_severity", state.filters.get("severity", []))),
            "source_countries": _safe_list(session.get("filter_countries", state.filters.get("source_countries", []))),
            "mapping_confidence": _safe_list(session.get("filter_confidence", state.filters.get("mapping_confidence", []))),
            "triage_priorities": _safe_list(session.get("filter_priorities", state.filters.get("triage_priorities", []))),
            "control_actions_only": bool(session.get("filter_control_only", state.filters.get("control_actions_only", False))),
        }
        return state

    def sync_to_session(self, session: MutableMapping[str, object]) -> None:
        session["_investigation_state"] = self
        session["_active_view"] = self.active_view
        if self.destination_view:
            session["_next_view"] = self.destination_view
        else:
            session.pop("_next_view", None)
        if self.selected_source:
            session["_selected_map_source"] = dict(self.selected_source)
        else:
            session.pop("_selected_map_source", None)
        if self.selected_event_id:
            session["_selected_event_id"] = self.selected_event_id
        else:
            session.pop("_selected_event_id", None)
        if self.map_focus:
            session["_map_focus"] = dict(self.map_focus)
        else:
            session.pop("_map_focus", None)
        session["_map_camera"] = self.map_camera
        session["_walkthrough_step"] = self.walkthrough_step

    def to_snapshot(
        self,
        *,
        dataset_status: str,
        fixture_version: str,
        quality: Mapping[str, int],
        filtered_events: int,
        mapped_sources: int,
        mapped_countries: int,
        excluded_events: int,
    ) -> dict[str, object]:
        """Return a reloadable snapshot containing aggregate fields only."""
        return {
            "schema_version": SNAPSHOT_SCHEMA,
            "generated_at": datetime.now(UTC).isoformat(),
            "source": "local-dashboard",
            "fixture_version": fixture_version,
            "dataset_status": "synthetic" if dataset_status == "synthetic" else "sanitized",
            "view": {
                "active": _valid_view(self.active_view),
                "destination": _valid_view(self.destination_view, allow_none=True),
                "map_mode": self.map_mode if self.map_mode in MAP_MODES else MAP_MODES[0],
                "map_window": self.map_window if self.map_window in MAP_WINDOWS else MAP_WINDOWS[0],
                "map_theme": self.map_theme if self.map_theme in MAP_THEMES else MAP_THEMES[0],
                "map_camera": self.map_camera if self.map_camera in {"overview", "fit", "focus"} else "overview",
                "walkthrough_step": min(5, max(0, int(self.walkthrough_step))),
            },
            "filters": {
                "protocols": _safe_list(self.filters.get("protocols", [])),
                "severity": _safe_list(self.filters.get("severity", [])),
                "source_countries": _safe_list(self.filters.get("source_countries", [])),
                "mapping_confidence": _safe_list(self.filters.get("mapping_confidence", [])),
                "triage_priorities": _safe_list(self.filters.get("triage_priorities", [])),
                "control_actions_only": bool(self.filters.get("control_actions_only", False)),
            },
            "selection": _safe_selection(self.selected_source),
            "map_quality": {
                "filtered_events": int(filtered_events),
                "mapped_events": int(quality.get("plotted_events", 0)),
                "excluded_events": int(excluded_events),
                "mapped_sources": int(mapped_sources),
                "mapped_countries": int(mapped_countries),
            },
            "disclosures": {
                "geography": "Approximate, rounded public coordinates only.",
                "identity": "Pseudonymous source groups; no attribution.",
                "raw_data": "Raw IP addresses and payloads are excluded.",
                "operations": "Read-only research view; no real OT control action is performed.",
                "snapshot": "Saved locally for review; not a server-backed shared investigation.",
            },
        }

    @classmethod
    def from_snapshot(cls, payload: Mapping[str, object]) -> InvestigationState:
        if payload.get("schema_version") != SNAPSHOT_SCHEMA:
            raise ValueError("Unsupported or missing snapshot schema version.")
        view = payload.get("view")
        filters = payload.get("filters")
        if not isinstance(view, Mapping) or not isinstance(filters, Mapping):
            raise TypeError("Snapshot is missing its view or filter state.")
        state = cls(
            active_view=_valid_view(view.get("active")),
            destination_view=_valid_view(view.get("destination"), allow_none=True),
            map_mode=str(view.get("map_mode", MAP_MODES[0])),
            map_window=str(view.get("map_window", MAP_WINDOWS[0])),
            map_theme=str(view.get("map_theme", MAP_THEMES[0])),
            map_camera=str(view.get("map_camera", "overview")),
            filters={
                "protocols": _safe_list(filters.get("protocols")),
                "severity": _safe_list(filters.get("severity")),
                "source_countries": _safe_list(filters.get("source_countries")),
                "mapping_confidence": _safe_list(filters.get("mapping_confidence")),
                "triage_priorities": _safe_list(filters.get("triage_priorities")),
                "control_actions_only": bool(filters.get("control_actions_only", False)),
            },
        )
        if state.map_mode not in MAP_MODES or state.map_window not in MAP_WINDOWS or state.map_theme not in MAP_THEMES:
            raise ValueError("Snapshot contains an unsupported map setting.")
        if state.map_camera not in {"overview", "fit", "focus"}:
            state.map_camera = "overview"
        try:
            state.walkthrough_step = min(5, max(0, int(view.get("walkthrough_step", 0))))
        except (TypeError, ValueError):
            state.walkthrough_step = 0
        state.selected_source = _safe_selection(payload.get("selection"))
        return state


def _valid_view(value: object, *, allow_none: bool = False) -> str | None:
    if allow_none and value is None:
        return None
    return str(value) if str(value) in VIEW_NAMES else "Observatory"
