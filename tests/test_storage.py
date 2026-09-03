from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ot_sentinel.collector import CollectorReplayError, CollectorVerifier
from ot_sentinel.model import Event
from ot_sentinel.sensor import JsonlWriter
from ot_sentinel.storage import SQLiteObservationStore, SQLiteReplayStore
from ot_sentinel.transport import canonical_signature

SECRET = "synthetic-fingerprint-secret-32-characters"
SALT = "synthetic-private-salt-at-least-32-chars"
SENSOR_SECRET = "synthetic-collector-secret-at-least-32"


def observation(event_id: str = "event-001") -> dict:
    return {
        "event_id": event_id,
        "session_id": "session-001",
        "sensor_id": "synthetic-sensor",
        "observed_at": "2026-01-01T00:00:00+00:00",
        "protocol": "modbus",
        "event_type": "protocol_request",
        "source_ip": "192.0.2.10",
        "severity": "high",
        "is_demo": True,
        "decoded": {"operation": "write_single", "function_code": 6},
        "tags": ["synthetic"],
        "techniques": [
            {"technique_id": "T1692.001", "confidence": "high"},
            {"technique_id": "T0836", "confidence": "medium"},
        ],
    }


def observation_store(path: Path) -> SQLiteObservationStore:
    return SQLiteObservationStore(
        path,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
    )


def signed_envelope(event_id: str = "event-replay") -> tuple[dict[str, str], bytes]:
    timestamp = str(int(time.time()))
    event = observation(event_id)
    event.pop("source_ip")
    envelope = {
        "schema": "ot-sentinel-envelope/1",
        "sensor_id": "synthetic-sensor",
        "sent_at": "2026-01-01T00:00:00+00:00",
        "event": event,
    }
    body = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
    signature = canonical_signature(SENSOR_SECRET.encode(), timestamp, body)
    headers = {
        "X-OT-Sensor": "synthetic-sensor",
        "X-OT-Timestamp": timestamp,
        "X-OT-Signature": f"sha256={signature}",
    }
    return headers, body


def test_replay_reservation_survives_verifier_restart(tmp_path):
    path = tmp_path / "replay.sqlite3"
    headers, body = signed_envelope()
    first = CollectorVerifier(
        {"synthetic-sensor": SENSOR_SECRET}, replay_store=SQLiteReplayStore(path)
    )
    second = CollectorVerifier(
        {"synthetic-sensor": SENSOR_SECRET}, replay_store=SQLiteReplayStore(path)
    )

    first.verify(headers, body)

    try:
        second.verify(headers, body)
    except CollectorReplayError:
        pass
    else:
        raise AssertionError("durable replay reservation was not enforced")


def test_replay_expiry_and_release(tmp_path):
    store = SQLiteReplayStore(tmp_path / "replay.sqlite3")
    assert store.reserve("sensor:event", now=100, ttl=10)
    assert not store.reserve("sensor:event", now=109, ttl=10)
    assert store.reserve("sensor:event", now=110, ttl=10)
    store.release("sensor:event")
    assert store.reserve("sensor:event", now=111, ttl=10)


def test_concurrent_replay_reservation_accepts_exactly_once(tmp_path):
    path = tmp_path / "replay.sqlite3"
    store = SQLiteReplayStore(path)
    with ThreadPoolExecutor(max_workers=12) as executor:
        results = list(
            executor.map(lambda _: store.reserve("sensor:same-key", now=100), range(24))
        )
    assert results.count(True) == 1
    assert results.count(False) == 23


def test_replay_database_persists_sensor_event_and_expiry_separately(tmp_path):
    path = tmp_path / "replay.sqlite3"
    store = SQLiteReplayStore(path)
    assert store.reserve("synthetic-sensor:synthetic-event", now=100, ttl=15)
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT sensor_id, event_id, expires_at_epoch FROM replay_keys"
        ).fetchone()
    assert row == ("synthetic-sensor", "synthetic-event", 115)


def test_persistent_replay_release_allows_legitimate_storage_retry(tmp_path):
    path = tmp_path / "replay.sqlite3"
    headers, body = signed_envelope("storage-retry")
    verifier = CollectorVerifier(
        {"synthetic-sensor": SENSOR_SECRET}, replay_store=SQLiteReplayStore(path)
    )
    accepted = verifier.verify(headers, body)
    verifier.release_replay(accepted)
    restarted = CollectorVerifier(
        {"synthetic-sensor": SENSOR_SECRET}, replay_store=SQLiteReplayStore(path)
    )
    assert restarted.verify(headers, body)["event_id"] == "storage-retry"


def test_observation_repeat_count_and_expiry(tmp_path):
    store = observation_store(tmp_path / "observations.sqlite3")
    event = observation()

    first_id = store.record(event, payload=b"payload", now=1000)
    repeated_id = store.record(event, payload=b"payload", now=1000 + 1799)
    new_id = store.record(event, payload=b"payload", now=1000 + 3600)
    rows = store.observations()

    assert repeated_id == first_id
    assert new_id != first_id
    assert [row["repeat_count"] for row in rows] == [2, 1]


def test_private_index_persists_explainable_repeat_and_novelty_score(tmp_path):
    store = observation_store(tmp_path / "observations.sqlite3")
    event = observation()

    first = store.record_with_assessment(event, payload=b"payload", now=1000)
    repeated = store.record_with_assessment(event, payload=b"payload", now=1001)
    row = store.observations()[0]

    assert first.novel_payload is True
    assert repeated.novel_payload is False
    assert repeated.repeat_source_count == 2
    assert repeated.assessment.score > first.assessment.score
    assert "repeat_source" in [factor.code for factor in repeated.assessment.factors]
    assert row["threat_score"] == repeated.assessment.score
    assert row["threat_priority"] == repeated.assessment.priority
    assert "repeat_source" in row["threat_factors_json"]


def test_observation_fingerprint_includes_source_protocol_and_payload(tmp_path):
    store = observation_store(tmp_path / "observations.sqlite3")
    event = observation()
    first = store.record(event, payload=b"one", now=1000)
    second = store.record(event, payload=b"two", now=1000)
    third = store.record({**event, "protocol": "s7"}, payload=b"one", now=1000)
    fourth = store.record({**event, "source_ip": "198.51.100.7"}, payload=b"one", now=1000)

    assert len({first, second, third, fourth}) == 4


def test_concurrent_observation_deduplication_is_atomic(tmp_path):
    store = observation_store(tmp_path / "observations.sqlite3")
    event = observation()
    with ThreadPoolExecutor(max_workers=12) as executor:
        list(executor.map(lambda _: store.record(event, payload=b"same", now=1000), range(20)))

    rows = store.observations()
    assert len(rows) == 1
    assert rows[0]["repeat_count"] == 20


def test_observation_database_excludes_raw_source_payload_and_secret(tmp_path):
    path = tmp_path / "observations.sqlite3"
    store = observation_store(path)
    store.record(observation(), payload=b"private-payload-example", now=1000)

    database_bytes = path.read_bytes()
    assert b"192.0.2.10" not in database_bytes
    assert b"private-payload-example" not in database_bytes
    assert SECRET.encode() not in database_bytes
    assert SALT.encode() not in database_bytes


def test_jsonl_remains_authoritative_when_optional_database_fails(tmp_path):
    class FailingStore:
        def record(self, event, *, payload, now=None):
            raise sqlite3.OperationalError("synthetic storage failure")

    path = tmp_path / "events.jsonl"
    writer = JsonlWriter(path, FailingStore())
    event = Event(
        protocol="modbus",
        source_ip="192.0.2.10",
        source_port=12345,
        destination_port=502,
        event_type="protocol_request",
        raw_payload_hex="0102",
        is_demo=True,
    )

    asyncio.run(writer.append(event))

    assert json.loads(path.read_text(encoding="utf-8"))["event_id"] == event.event_id
    assert writer.database_failures == 1


def test_observation_rejects_payload_over_hard_limit(tmp_path):
    store = observation_store(tmp_path / "observations.sqlite3")
    try:
        store.record(observation(), payload=b"x" * 513, now=1000)
    except ValueError as exc:
        assert "512 bytes" in str(exc)
    else:
        raise AssertionError("oversized observation payload was accepted")
