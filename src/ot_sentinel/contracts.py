from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from .model import Event

OBSERVATION_SCHEMA_VERSION = "ot-sentinel.observation/v1"
ANALYSIS_SCHEMA_VERSION = "ot-sentinel.analysis/v1"
ANALYTIC_FIELDS = {"techniques", "severity", "triage", "detection_results"}


def _record(event: Event | Mapping[str, Any]) -> dict[str, Any]:
    return event.to_dict() if isinstance(event, Event) else deepcopy(dict(event))


def _classification(record: Mapping[str, Any]) -> str:
    if record.get("is_demo") is True:
        return "synthetic"
    if record.get("sanitized") is True:
        return "sanitized_private"
    return "raw_private"


def canonical_digest(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def observation_from_event(
    event: Event | Mapping[str, Any], *, sensor_version: str = "0.3.0-dev"
) -> dict[str, Any]:
    """Create immutable capture evidence without mapper, triage, or rule conclusions."""
    record = _record(event)
    for field in ANALYTIC_FIELDS:
        record.pop(field, None)
    record["schema_version"] = OBSERVATION_SCHEMA_VERSION
    record["data_classification"] = _classification(record)
    record["capture"] = {"sensor_version": sensor_version}
    validate_observation(record)
    return record


def validate_observation(record: Mapping[str, Any]) -> None:
    required = {"schema_version", "event_id", "session_id", "sensor_id", "observed_at", "protocol", "event_type"}
    if record.get("schema_version") != OBSERVATION_SCHEMA_VERSION:
        raise ValueError("unsupported observation schema")
    if not required.issubset(record):
        raise ValueError("observation is missing required fields")
    if any(not isinstance(record[field], str) or not record[field] for field in required):
        raise ValueError("observation required fields must be non-empty strings")
    if not isinstance(record.get("capture"), Mapping):
        raise TypeError("observation capture metadata must be an object")
    if record.get("data_classification") not in {"raw_private", "sanitized_private", "synthetic"}:
        raise ValueError("observation has an invalid data classification")
    if ANALYTIC_FIELDS & set(record):
        raise ValueError("observation must not contain analytical conclusions")


def legacy_to_contracts(record: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Adapt an existing mixed event without mutating historical JSONL."""
    raw = _record(record)
    observation = observation_from_event(raw, sensor_version="legacy-v0")
    observation["capture"]["legacy_import"] = True
    analysis = None
    if any(field in raw for field in ANALYTIC_FIELDS):
        analysis = {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "analysis_id": f"legacy-{raw['event_id']}",
            "analysis_run_id": "legacy-import-v0",
            "event_id": raw["event_id"],
            "input_digest": canonical_digest(observation),
            "executed_at": str(raw.get("observed_at")),
            "versions": {"mapper": "legacy-v0", "triage": "legacy-v0", "rule_catalog": "legacy-v0"},
            "attack_hypotheses": raw.get("techniques", []),
            "severity": raw.get("severity", "info"),
            "triage": raw.get("triage", {}),
            "detection_results": raw.get("detection_results", []),
            "evidence_completeness": {},
        }
        validate_analysis(analysis)
    return observation, analysis


def validate_analysis(record: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "analysis_id",
        "analysis_run_id",
        "event_id",
        "input_digest",
        "executed_at",
        "versions",
        "attack_hypotheses",
        "detection_results",
    }
    if record.get("schema_version") != ANALYSIS_SCHEMA_VERSION:
        raise ValueError("unsupported analysis schema")
    if not required.issubset(record):
        raise ValueError("analysis is missing required fields")
    if any(not isinstance(record[field], str) or not record[field] for field in required - {"versions", "attack_hypotheses", "detection_results"}):
        raise ValueError("analysis identifiers must be non-empty strings")
    if not isinstance(record["versions"], Mapping):
        raise TypeError("analysis versions must be an object")
    if not isinstance(record["attack_hypotheses"], list) or not isinstance(record["detection_results"], list):
        raise TypeError("analysis results must be lists")


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")
