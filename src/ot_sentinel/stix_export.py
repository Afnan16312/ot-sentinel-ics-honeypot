from __future__ import annotations

import base64
import ipaddress
import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from uuid import UUID, uuid5

from .mapper import CATALOG, map_event
from .privacy import pseudonymize_ip

STIX_VERSION = "2.1"
ATTACK_ICS_URL = "https://attack.mitre.org/techniques/"

# UUIDv5 is recommended for deterministic STIX Cyber-observable Object identifiers.
_STIX_SCO_NAMESPACE = UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
_PROJECT_NAMESPACE = UUID("019d173a-60a8-760c-a2aa-30e8c4869313")

_CONFIDENCE = {"low": 25, "medium": 50, "high": 75}
_PUBLIC_DECODED_FIELDS = {
    "address",
    "apdu_length",
    "cotp_pdu_type",
    "declared_length",
    "error",
    "frame_type",
    "function_code",
    "function_name",
    "operation",
    "parameter_length",
    "protocol_id",
    "rosctr",
    "s7_function",
    "tpkt_length",
    "transaction_id",
    "type_id",
    "u_function",
    "unit_id",
    "valid",
    "value_or_quantity",
}
_PUBLIC_EVENT_FIELDS = {
    "byte_count",
    "data_notice",
    "destination_port",
    "event_id",
    "event_type",
    "is_demo",
    "observed_at",
    "protocol",
    "sensor_id",
    "session_id",
    "severity",
    "source_asn",
    "source_country",
    "source_country_code",
    "source_id",
    "source_port",
    "tags",
    "techniques",
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _id(object_type: str, material: Any, *, sco: bool = False) -> str:
    namespace = _STIX_SCO_NAMESPACE if sco else _PROJECT_NAMESPACE
    return f"{object_type}--{uuid5(namespace, _canonical([object_type, material]))}"


def _timestamp(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("Every event must have an observed_at timestamp")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"Invalid observed_at timestamp: {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _technique_url(technique_id: str) -> str:
    parts = technique_id.split(".", maxsplit=1)
    suffix = "/".join(parts)
    return f"{ATTACK_ICS_URL}{suffix}/"


def _public_decoded(decoded: Any) -> dict[str, Any]:
    if not isinstance(decoded, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in sorted(_PUBLIC_DECODED_FIELDS):
        value = decoded.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = value
    return result


def _public_event(event: Mapping[str, Any], salt: str | None) -> dict[str, Any]:
    clean = {key: event[key] for key in _PUBLIC_EVENT_FIELDS if key in event}
    source_id = str(event.get("source_id", "")).strip()
    source_ip = str(event.get("source_ip", "")).strip()
    if not source_id:
        if not source_ip:
            raise ValueError("A public export requires source_id or source_ip")
        if not salt:
            raise ValueError(
                "A salt is required to pseudonymize source_ip for the public profile"
            )
        source_id = pseudonymize_ip(source_ip, salt)
    clean["source_id"] = source_id
    clean["decoded"] = _public_decoded(event.get("decoded", {}))
    clean["techniques"] = []
    for technique in _techniques(event):
        technique_id = technique["technique_id"]
        if technique_id not in CATALOG:
            continue
        name, tactic = CATALOG[technique_id]
        confidence = technique.get("confidence", "low")
        clean["techniques"].append(
            {
                "technique_id": technique_id,
                "name": name,
                "tactic": tactic,
                "confidence": confidence if confidence in _CONFIDENCE else "low",
                "rationale": "Mapped from allow-listed OT protocol evidence by OT Sentinel.",
            }
        )
    clean["sanitized"] = True
    return clean


def _techniques(event: Mapping[str, Any]) -> list[dict[str, str]]:
    supplied = event.get("techniques")
    if supplied is None:
        matches = map_event(
            str(event.get("protocol", "unknown")),
            str(event.get("event_type", "connection")),
            dict(event.get("decoded", {})),
        )
        return [
            {
                "technique_id": match.technique_id,
                "name": match.name,
                "tactic": match.tactic,
                "confidence": match.confidence,
                "rationale": match.rationale,
            }
            for match in matches
        ]

    result: list[dict[str, str]] = []
    for match in supplied:
        if not isinstance(match, Mapping):
            match = vars(match)
        technique_id = str(match.get("technique_id", "")).strip()
        if not technique_id:
            continue
        catalog_name, catalog_tactic = CATALOG.get(technique_id, (technique_id, "Unknown"))
        result.append(
            {
                "technique_id": technique_id,
                "name": str(match.get("name") or catalog_name),
                "tactic": str(match.get("tactic") or catalog_tactic),
                "confidence": str(match.get("confidence") or "low").lower(),
                "rationale": str(match.get("rationale") or "Local evidence-based mapping."),
            }
        )
    return result


def _identity() -> dict[str, Any]:
    created = "2026-01-01T00:00:00.000Z"
    return {
        "type": "identity",
        "spec_version": STIX_VERSION,
        "id": _id("identity", "OT Sentinel"),
        "created": created,
        "modified": created,
        "name": "OT Sentinel",
        "description": "Producer of evidence-qualified OT/ICS honeypot telemetry.",
        "identity_class": "system",
    }


def _attack_pattern(technique: Mapping[str, str], identity_id: str) -> dict[str, Any]:
    technique_id = technique["technique_id"]
    created = "2026-01-01T00:00:00.000Z"
    return {
        "type": "attack-pattern",
        "spec_version": STIX_VERSION,
        "id": _id("attack-pattern", ["mitre-attack-ics", technique_id]),
        "created_by_ref": identity_id,
        "created": created,
        "modified": created,
        "name": technique["name"],
        "description": (
            "A local reference to a MITRE ATT&CK for ICS technique. Relationships to this "
            "object are hypotheses based on honeypot evidence, not attribution or proof of compromise."
        ),
        "external_references": [
            {
                "source_name": "mitre-attack-ics",
                "external_id": technique_id,
                "url": _technique_url(technique_id),
            }
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack-ics",
                "phase_name": technique["tactic"].lower().replace(" ", "-"),
            }
        ],
        "x_ot_sentinel_provenance": {
            "catalog": "MITRE ATT&CK for ICS",
            "mapping_source": "OT Sentinel evidence-aware mapper",
            "external_id": technique_id,
        },
    }


def _source_object(source_ip: str) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise ValueError(f"Private STIX export received an invalid source_ip: {source_ip!r}") from exc
    object_type = "ipv4-addr" if address.version == 4 else "ipv6-addr"
    value = address.compressed
    return {
        "type": object_type,
        "spec_version": STIX_VERSION,
        "id": _id(object_type, {"value": value}, sco=True),
        "value": value,
    }


def _public_source_object(source_id: str) -> dict[str, Any]:
    # A reserved .invalid name gives network-traffic a standards-compatible src_ref
    # without presenting the pseudonym as a routable address or real DNS name.
    value = f"{source_id.lower()}.invalid"
    return {
        "type": "domain-name",
        "spec_version": STIX_VERSION,
        "id": _id("domain-name", {"value": value}, sco=True),
        "value": value,
    }


def _artifact(payload_hex: str) -> dict[str, Any] | None:
    if not payload_hex:
        return None
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as exc:
        raise ValueError("raw_payload_hex must contain hexadecimal bytes") from exc
    encoded = base64.b64encode(payload).decode("ascii")
    digest = sha256(payload).hexdigest()
    return {
        "type": "artifact",
        "spec_version": STIX_VERSION,
        "id": _id("artifact", {"payload_bin": encoded}, sco=True),
        "mime_type": "application/octet-stream",
        "payload_bin": encoded,
        "hashes": {"SHA-256": digest},
    }


def _network_traffic(
    event: Mapping[str, Any], source_ref: str, payload_ref: str | None
) -> dict[str, Any]:
    protocols = ["tcp"]
    properties: dict[str, Any] = {"protocols": protocols}
    source_port = int(event.get("source_port") or 0)
    destination_port = int(event.get("destination_port") or 0)
    if source_port:
        properties["src_port"] = source_port
    if destination_port:
        properties["dst_port"] = destination_port
    byte_count = int(event.get("byte_count") or 0)
    if byte_count:
        properties["src_byte_count"] = byte_count
    properties["src_ref"] = source_ref
    if payload_ref:
        properties["src_payload_ref"] = payload_ref
    return {
        "type": "network-traffic",
        "spec_version": STIX_VERSION,
        "id": _id("network-traffic", properties, sco=True),
        **properties,
    }


def _observed_data(
    event: Mapping[str, Any],
    identity_id: str,
    object_refs: list[str],
    profile: str,
) -> dict[str, Any]:
    observed_at = _timestamp(event.get("observed_at"))
    event_id = str(event.get("event_id") or _canonical(event))
    is_demo = bool(event.get("is_demo", False))
    decoded = event.get("decoded", {})
    observed: dict[str, Any] = {
        "type": "observed-data",
        "spec_version": STIX_VERSION,
        "id": _id("observed-data", [profile, event_id]),
        "created_by_ref": identity_id,
        "created": observed_at,
        "modified": observed_at,
        "first_observed": observed_at,
        "last_observed": observed_at,
        "number_observed": 1,
        "object_refs": object_refs,
        "labels": ["ot-honeypot", "synthetic" if is_demo else "live-observation"],
        "x_ot_sentinel_profile": profile,
        "x_ot_sentinel_data_classification": "synthetic" if is_demo else "live",
        "x_ot_sentinel_event_id": event_id,
        "x_ot_sentinel_event_type": str(event.get("event_type", "")),
        "x_ot_sentinel_protocol": str(event.get("protocol", "unknown")),
        "x_ot_sentinel_severity": str(event.get("severity", "info")),
    }
    session_id = str(event.get("session_id", "")).strip()
    sensor_id = str(event.get("sensor_id", "")).strip()
    if session_id:
        observed["x_ot_sentinel_session_id"] = session_id
    if sensor_id:
        observed["x_ot_sentinel_sensor_id"] = sensor_id
    if isinstance(decoded, Mapping) and decoded:
        observed["x_ot_sentinel_decoded"] = dict(decoded)
    for field in ("source_id", "source_country", "source_country_code", "source_asn", "data_notice"):
        value = event.get(field)
        if isinstance(value, str) and value.strip():
            observed[f"x_ot_sentinel_{field}"] = value
    tags = event.get("tags")
    if isinstance(tags, list) and tags:
        observed["x_ot_sentinel_tags"] = [str(tag) for tag in tags]
    return observed


def _relationship(
    observed_id: str,
    attack_pattern_id: str,
    technique: Mapping[str, str],
    identity_id: str,
    observed_at: str,
) -> dict[str, Any]:
    confidence = technique.get("confidence", "low")
    return {
        "type": "relationship",
        "spec_version": STIX_VERSION,
        "id": _id("relationship", [observed_id, attack_pattern_id, technique["technique_id"]]),
        "created_by_ref": identity_id,
        "created": observed_at,
        "modified": observed_at,
        "relationship_type": "related-to",
        "source_ref": observed_id,
        "target_ref": attack_pattern_id,
        "description": technique["rationale"],
        "confidence": _CONFIDENCE.get(confidence, 25),
        "x_ot_sentinel_confidence_label": confidence,
        "x_ot_sentinel_mapping_status": "evidence-based-hypothesis",
    }


def _contains_ip_literal(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_ip_literal(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_ip_literal(item) for item in value)
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def export_events(
    events: Iterable[Mapping[str, Any]],
    *,
    profile: str = "public",
    salt: str | None = None,
) -> dict[str, Any]:
    """Convert OT Sentinel events to a deterministic STIX 2.1 JSON Bundle.

    ``public`` removes raw addresses and payloads and exports only allow-listed decoded
    metadata. ``private`` retains source IPs and payload bytes as standard STIX SCOs.
    """
    if profile not in {"public", "private"}:
        raise ValueError("profile must be 'public' or 'private'")

    source_events = [dict(event) for event in events]
    if not source_events:
        raise ValueError("At least one event is required for a STIX export")

    identity = _identity()
    objects: list[dict[str, Any]] = [identity]
    object_ids: list[str] = []
    patterns: dict[str, dict[str, Any]] = {}
    relationships: list[dict[str, Any]] = []
    classifications: set[str] = set()

    for original in source_events:
        event = _public_event(original, salt) if profile == "public" else original
        is_demo = bool(event.get("is_demo", False))
        classifications.add("synthetic" if is_demo else "live")

        refs: list[str] = []
        payload_ref: str | None = None
        if profile == "private":
            source_ip = str(event.get("source_ip", "")).strip()
            if not source_ip:
                raise ValueError("A private STIX export requires source_ip")
            source = _source_object(source_ip)
            source_ref = source["id"]
            objects.append(source)
            refs.append(source_ref)
            artifact = _artifact(str(event.get("raw_payload_hex", "")))
            if artifact:
                objects.append(artifact)
                payload_ref = artifact["id"]
                refs.append(payload_ref)
        else:
            source = _public_source_object(str(event["source_id"]))
            source_ref = source["id"]
            objects.append(source)
            refs.append(source_ref)

        traffic = _network_traffic(event, source_ref, payload_ref)
        objects.append(traffic)
        refs.append(traffic["id"])
        observed = _observed_data(event, identity["id"], refs, profile)
        objects.append(observed)
        object_ids.append(observed["id"])

        for technique in _techniques(event):
            pattern = _attack_pattern(technique, identity["id"])
            patterns.setdefault(pattern["id"], pattern)
            relationships.append(
                _relationship(
                    observed["id"], pattern["id"], technique, identity["id"], observed["created"]
                )
            )

    objects.extend(patterns[key] for key in sorted(patterns))
    objects.extend(sorted(relationships, key=lambda item: item["id"]))
    object_ids.extend(sorted(patterns))
    object_ids.extend(item["id"] for item in relationships)

    timestamps = [_timestamp(event.get("observed_at")) for event in source_events]
    dataset_class = "mixed" if len(classifications) > 1 else next(iter(classifications))
    grouping = {
        "type": "grouping",
        "spec_version": STIX_VERSION,
        "id": _id(
            "grouping",
            [profile, dataset_class, sorted(str(event.get("event_id", "")) for event in source_events)],
        ),
        "created_by_ref": identity["id"],
        "created": min(timestamps),
        "modified": max(timestamps),
        "name": f"OT Sentinel {profile} honeypot export",
        "description": (
            "Synthetic demonstration telemetry; not observed attacker activity."
            if dataset_class == "synthetic"
            else "Honeypot observations. Technique relationships remain analytical hypotheses."
        ),
        "context": "suspicious-activity",
        "object_refs": sorted(set(object_ids)),
        "x_ot_sentinel_export_profile": profile,
        "x_ot_sentinel_data_classification": dataset_class,
    }
    objects.append(grouping)

    # SCOs may be reused between events; a Bundle should contain each object once.
    unique = {item["id"]: item for item in objects}
    ordered = sorted(unique.values(), key=lambda item: (item["type"], item["id"]))
    bundle = {
        "type": "bundle",
        "id": _id("bundle", [profile, [item["id"] for item in ordered]]),
        "objects": ordered,
    }
    if profile == "public":
        serialized = _canonical(bundle)
        if "raw_payload_hex" in serialized or "payload_bin" in serialized:
            raise AssertionError("Public STIX output contains a payload field")
        if _contains_ip_literal(bundle):
            raise AssertionError("Public STIX output contains an IP address literal")
        raw_sources = {
            str(event.get("source_ip", "")).strip()
            for event in source_events
            if event.get("source_ip")
        }
        if any(source_ip in serialized for source_ip in raw_sources):
            raise AssertionError("Public STIX output contains a raw source IP")
    return bundle


def load_jsonl(path: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number} of {path}") from exc
    return events
