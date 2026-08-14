from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .mapper import map_event
from .model import Event


def normalize_conpot(record: dict[str, Any], sensor_id: str = "conpot-01") -> Event:
    """Normalize common Conpot JSON fields into the OT Sentinel event model."""
    remote = record.get("remote") or record.get("src_ip") or "0.0.0.0"
    if isinstance(remote, (list, tuple)):
        source_ip = str(remote[0])
        source_port = int(remote[1]) if len(remote) > 1 else 0
    elif ":" in str(remote) and str(remote).count(":") == 1:
        source_ip, port = str(remote).rsplit(":", 1)
        source_port = int(port) if port.isdigit() else 0
    else:
        source_ip, source_port = str(remote), int(record.get("src_port", 0))

    protocol = str(record.get("protocol") or record.get("data_type") or "unknown").lower()
    decoded = record.get("decoded") or record.get("request") or {}
    if not isinstance(decoded, dict):
        decoded = {"message": str(decoded)[:256]}
    event_type = "protocol_request" if decoded else "connection"
    observed = record.get("timestamp") or record.get("observed_at")
    if not observed:
        observed = datetime.now(UTC).isoformat(timespec="milliseconds")

    event = Event(
        protocol=protocol,
        source_ip=source_ip,
        source_port=source_port,
        destination_port=int(record.get("dst_port") or record.get("port") or 0),
        event_type=event_type,
        sensor_id=sensor_id,
        observed_at=str(observed),
        byte_count=int(record.get("bytes") or record.get("byte_count") or 0),
        raw_payload_hex=str(record.get("raw_payload_hex") or "")[:1024],
        decoded=decoded,
        tags=["conpot"],
    )
    event.techniques = map_event(protocol, event_type, decoded)
    event.severity = severity_for(event.techniques)
    return event


def severity_for(techniques: list) -> str:
    ids = {getattr(item, "technique_id", "") for item in techniques}
    if ids & {"T0843", "T0866", "T1692.001"}:
        return "high"
    if ids & {"T0836", "T0806", "T0877"}:
        return "medium"
    return "info"

