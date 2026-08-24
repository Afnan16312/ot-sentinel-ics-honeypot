from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from ot_sentinel.storage import SQLiteObservationStore
from scripts.export_navigator import build_layer, validate_layer

SECRET = "synthetic-fingerprint-secret-32-characters"
SALT = "synthetic-private-salt-at-least-32-chars"


def store(path: Path) -> SQLiteObservationStore:
    return SQLiteObservationStore(path, fingerprint_secret=SECRET, privacy_salt=SALT)


def event(event_id: str, technique_id: str, confidence: str = "high") -> dict:
    return {
        "event_id": event_id,
        "session_id": f"session-{event_id}",
        "observed_at": "2026-01-01T00:00:00+00:00",
        "protocol": "modbus",
        "event_type": "protocol_request",
        "source_ip": "192.0.2.20",
        "severity": "high",
        "is_demo": True,
        "decoded": {"operation": "write_single"},
        "tags": ["synthetic"],
        "techniques": [{"technique_id": technique_id, "confidence": confidence}],
    }


def test_navigator_scores_sum_repeat_count_and_are_sorted(tmp_path):
    database = tmp_path / "observations.sqlite3"
    index = store(database)
    first = event("one", "T1692.001")
    index.record(first, payload=b"same", now=1000)
    index.record(first, payload=b"same", now=1001)
    index.record(event("two", "T0836", "medium"), payload=b"different", now=1002)

    layer = build_layer(database)

    assert layer["domain"] == "ics-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert [item["techniqueID"] for item in layer["techniques"]] == ["T0836", "T1692.001"]
    assert {item["techniqueID"]: item["score"] for item in layer["techniques"]} == {
        "T0836": 1,
        "T1692.001": 2,
    }
    assert validate_layer(layer) == []


def test_navigator_output_contains_no_identifiers_payloads_or_addresses(tmp_path):
    database = tmp_path / "observations.sqlite3"
    index = store(database)
    index.record(event("private-id", "T0836"), payload=b"payload-example", now=1000)

    serialized = json.dumps(build_layer(database))

    assert "source_id" not in serialized
    assert "session_id" not in serialized
    assert "payload" not in serialized
    assert "192.0.2.20" not in serialized
    assert "private-id" not in serialized


def test_navigator_rejects_unknown_technique_from_database(tmp_path):
    database = tmp_path / "observations.sqlite3"
    index = store(database)
    observation_id = index.record(event("one", "T0836"), payload=b"one", now=1000)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO observation_techniques VALUES (?, ?, ?)",
            (observation_id, "T9999", "high"),
        )

    with pytest.raises(ValueError, match="unsupported ATT&CK"):
        build_layer(database)


def test_layer_validator_rejects_wrong_domain_and_unsafe_content():
    layer = {
        "name": "unsafe",
        "domain": "ics",
        "versions": {"navigator": "4.9.0", "layer": "4.5"},
        "techniques": [{"techniqueID": "T0836", "score": 1, "comment": "192.0.2.1"}],
    }

    errors = validate_layer(layer)

    assert "domain must be ics-attack" in errors
    assert "layer contains an IP address literal" in errors
