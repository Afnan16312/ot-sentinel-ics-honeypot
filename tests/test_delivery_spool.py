from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path

import pytest

from ot_sentinel.model import Event
from ot_sentinel.operations import HealthTracker
from ot_sentinel.sensor import JsonlWriter, LowInteractionSensor
from ot_sentinel.transport import (
    DeliverySpoolCorruptionError,
    RemoteCollectorSink,
    SQLiteDeliverySpool,
)

SECRET = "synthetic-delivery-secret-32-characters"


def event(event_id: str = "event-one", *, marker: str = "") -> Event:
    return Event(
        "modbus",
        "192.0.2.40",
        41000,
        502,
        "protocol_request",
        sensor_id="synthetic-sensor",
        event_id=event_id,
        decoded={"operation": "write_single", "marker": marker},
    )


class RecordingSink(RemoteCollectorSink):
    def __init__(self, path: Path, *, fail: bool = False) -> None:
        super().__init__(
            "http://127.0.0.1:9443/v1/events",
            "synthetic-sensor",
            SECRET,
            HealthTracker("synthetic-sensor"),
            spool_path=path,
        )
        self.fail = fail
        self.sent: list[str] = []

    def _post(self, item):
        if self.fail:
            raise OSError("synthetic delivery failure")
        data = item.to_dict() if isinstance(item, Event) else item
        self.sent.append(str(data["event_id"]))


async def wait_until(predicate, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("condition was not reached")
        await asyncio.sleep(0.02)


def test_spool_survives_restart_and_stores_no_transport_secret(tmp_path):
    path = tmp_path / "delivery.sqlite3"
    first = SQLiteDeliverySpool(path)
    assert first.enqueue(event().to_dict(), now=1000)

    restarted = SQLiteDeliverySpool(path)
    item = restarted.next_due(now=1000)
    assert item is not None
    assert item.event["event_id"] == "event-one"
    database = path.read_bytes()
    assert SECRET.encode() not in database
    assert b"X-OT-Signature" not in database
    assert b"sha256=" not in database


def test_spool_bounds_rows_and_estimated_bytes(tmp_path):
    rows = SQLiteDeliverySpool(tmp_path / "rows.sqlite3", max_rows=2)
    assert rows.enqueue(event("one").to_dict(), now=1000)
    assert rows.enqueue(event("two").to_dict(), now=1000)
    assert not rows.enqueue(event("three").to_dict(), now=1000)
    assert rows.depth() == 2

    byte_bound = SQLiteDeliverySpool(tmp_path / "bytes.sqlite3", max_bytes=1600)
    assert byte_bound.enqueue(event("large", marker="x" * 600).to_dict(), now=1000)
    assert not byte_bound.enqueue(event("overflow", marker="x" * 600).to_dict(), now=1000)


def test_failed_delivery_uses_bounded_exponential_backoff(tmp_path):
    spool = SQLiteDeliverySpool(
        tmp_path / "retry.sqlite3", backoff_base=0.25, backoff_max=0.5
    )
    assert spool.enqueue(event().to_dict(), now=1000)
    first = spool.next_due(now=1000)
    assert first is not None
    assert spool.mark_failed(first, now=1000) == 0.25
    assert spool.next_due(now=1000.24) is None
    second = spool.next_due(now=1000.25)
    assert second is not None and second.attempts == 1
    assert spool.mark_failed(second, now=1001) == 0.5


def test_corrupt_row_is_discarded_with_privacy_safe_error(tmp_path):
    path = tmp_path / "corrupt-row.sqlite3"
    spool = SQLiteDeliverySpool(path)
    assert spool.enqueue(event().to_dict(), now=1000)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE delivery_spool SET event_json = ?", ("{private-marker",))
    with pytest.raises(DeliverySpoolCorruptionError) as caught:
        spool.next_due(now=1000)
    assert "private-marker" not in str(caught.value)
    assert spool.depth() == 0


def test_successful_drain_after_sink_restart(tmp_path):
    async def scenario():
        path = tmp_path / "restart.sqlite3"
        first = RecordingSink(path)
        assert await first.submit(event("persisted"))
        assert first.queue_depth == 1

        restarted = RecordingSink(path)
        await restarted.start()
        await wait_until(lambda: restarted.queue_depth == 0)
        await restarted.close()
        assert restarted.sent == ["persisted"]

    asyncio.run(scenario())


def test_queue_full_is_counted_and_jsonl_survives_forwarding_failure(tmp_path):
    async def scenario():
        health = HealthTracker("synthetic-sensor")
        sink = RemoteCollectorSink(
            "http://127.0.0.1:9443/v1/events",
            "synthetic-sensor",
            SECRET,
            health,
            queue_size=1,
        )
        assert await sink.submit(event("fills-memory-queue"))
        writer = JsonlWriter(tmp_path / "events.jsonl")
        sensor = LowInteractionSensor(
            "127.0.0.1",
            {"modbus": 0},
            writer,
            "synthetic-sensor",
            collector=sink,
        )
        await sensor.emit(event("must-remain-local"))
        assert health.collector_queue_drops == 1
        lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
        assert "must-remain-local" in lines

    asyncio.run(scenario())


def test_optional_metadata_keeps_envelope_version_one_compatible(tmp_path):
    sink = RemoteCollectorSink(
        "http://localhost:9443/v1/events",
        "synthetic-sensor",
        SECRET,
        HealthTracker("synthetic-sensor"),
        spool_path=tmp_path / "metadata.sqlite3",
        configuration_version="synthetic-config-v2",
        include_heartbeat=True,
    )
    envelope = json.loads(sink.build_request(event()).data)
    assert envelope["schema"] == "ot-sentinel-envelope/1"
    assert envelope["configuration_version"] == "synthetic-config-v2"
    assert set(envelope["heartbeat"]) == {"queue_depth", "oldest_age_seconds"}


def test_spool_metrics_are_exposed_in_health_snapshot(tmp_path):
    async def scenario():
        sink = RecordingSink(tmp_path / "health.sqlite3")
        assert await sink.submit(event("queued-for-health"))
        snapshot = sink.health.snapshot()
        assert snapshot["collector_queue_depth"] == 1
        assert snapshot["collector_queue_age_seconds"] >= 0
        assert snapshot["collector_storage_ready"] is True

    asyncio.run(scenario())


def test_spool_delete_failure_stops_worker_and_marks_storage_unready(tmp_path):
    async def scenario():
        sink = RecordingSink(tmp_path / "delete-failure.sqlite3")
        assert sink.spool is not None

        def fail_delete(row_id):
            raise DeliverySpoolCorruptionError("synthetic delete failure")

        sink.spool.mark_delivered = fail_delete
        assert await sink.submit(event("delete-failure"))
        await sink.start()
        await wait_until(lambda: sink._worker is not None and sink._worker.done())
        assert sink.health.collector_storage_ready is False
        assert sink.health.delivery_failures == 1
        await sink.close()

    asyncio.run(scenario())
