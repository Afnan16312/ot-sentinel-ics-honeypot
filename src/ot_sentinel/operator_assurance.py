from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SAFE_HEALTH_FIELDS = {
    "status",
    "generated_at",
    "last_event_at",
    "total_events",
    "alert_queue_drops",
    "collector_queue_drops",
    "delivery_failures",
    "collector_queue_depth",
    "collector_queue_age_seconds",
    "collector_storage_ready",
    "max_concurrent_sessions",
    "active_sessions",
    "rejected_sessions",
}


@dataclass(frozen=True)
class OperatorAssurance:
    state: str
    generated_at: str | None
    last_event_at: str | None
    total_events: int | None
    queue_state: str
    delivery_state: str
    capacity_state: str
    storage_state: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _integer(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def assurance_from_snapshot(snapshot: Mapping[str, object]) -> OperatorAssurance:
    """Translate a redacted health snapshot into explicit, non-secret assurance states."""

    queue_drops = _integer(snapshot.get("alert_queue_drops")) + _integer(
        snapshot.get("collector_queue_drops")
    )
    delivery_failures = _integer(snapshot.get("delivery_failures"))
    rejected_sessions = _integer(snapshot.get("rejected_sessions"))
    return OperatorAssurance(
        state="reported healthy" if snapshot.get("status") == "ok" else "reported unhealthy",
        generated_at=snapshot.get("generated_at") if isinstance(snapshot.get("generated_at"), str) else None,
        last_event_at=snapshot.get("last_event_at") if isinstance(snapshot.get("last_event_at"), str) else None,
        total_events=_integer(snapshot.get("total_events")),
        queue_state="attention needed" if queue_drops else "no drops reported",
        delivery_state="attention needed" if delivery_failures else "no failures reported",
        capacity_state="sessions rejected" if rejected_sessions else "no rejections reported",
        storage_state=(
            "not writable"
            if snapshot.get("collector_storage_ready") is False
            else "ready" if snapshot.get("collector_storage_ready") is True else "not reported"
        ),
    )


def load_operator_assurance(path: Path | None) -> OperatorAssurance | None:
    """Load only allowlisted aggregate counters from an explicitly configured local file."""

    if path is None or not path.is_file() or path.stat().st_size > 64 * 1024:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, Mapping):
        return None
    safe = {key: value[key] for key in SAFE_HEALTH_FIELDS if key in value}
    return assurance_from_snapshot(safe)
