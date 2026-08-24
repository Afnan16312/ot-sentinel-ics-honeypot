from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sqlite3
import time
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .model import Event
from .operations import HealthTracker


def canonical_signature(secret: bytes, timestamp: str, body: bytes) -> str:
    material = timestamp.encode() + b"\n" + body
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


class DeliverySpoolError(RuntimeError):
    """Privacy-safe base error for the optional private delivery spool."""


class DeliverySpoolCorruptionError(DeliverySpoolError):
    pass


@dataclass(frozen=True)
class SpoolItem:
    row_id: int
    event: dict[str, Any]
    created_at: float
    attempts: int


class SQLiteDeliverySpool:
    """Bounded, durable private queue containing events but no transport secret."""

    def __init__(
        self,
        path: Path,
        *,
        max_rows: int = 5000,
        max_bytes: int = 32 * 1024 * 1024,
        backoff_base: float = 0.2,
        backoff_max: float = 30.0,
    ) -> None:
        self.path = path
        self.max_rows = max(1, min(max_rows, 100_000))
        self.max_bytes = max(1024, min(max_bytes, 1024 * 1024 * 1024))
        self.backoff_base = max(0.01, min(backoff_base, 60.0))
        self.backoff_max = max(self.backoff_base, min(backoff_max, 3600.0))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._initialize()
        except sqlite3.DatabaseError as exc:
            raise DeliverySpoolCorruptionError("delivery spool database is unreadable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS delivery_spool (
                    id INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    event_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    available_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    estimated_bytes INTEGER NOT NULL CHECK(estimated_bytes > 0)
                );
                CREATE INDEX IF NOT EXISTS idx_delivery_spool_due
                    ON delivery_spool(available_at, id);
                """
            )

    def enqueue(self, event: Mapping[str, Any], *, now: float | None = None) -> bool:
        event_id = str(event.get("event_id", "")).strip()
        if not event_id:
            raise ValueError("spooled event requires event_id")
        encoded = json.dumps(dict(event), separators=(",", ":"), sort_keys=True)
        estimated_bytes = len(encoded.encode("utf-8"))
        created_at = time.time() if now is None else now
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    duplicate = connection.execute(
                        "SELECT 1 FROM delivery_spool WHERE event_id = ?", (event_id,)
                    ).fetchone()
                    if duplicate is not None:
                        connection.execute("COMMIT")
                        return True
                    usage = connection.execute(
                        "SELECT COUNT(*) AS rows, COALESCE(SUM(estimated_bytes), 0) AS bytes "
                        "FROM delivery_spool"
                    ).fetchone()
                    if (
                        int(usage["rows"]) >= self.max_rows
                        or int(usage["bytes"]) + estimated_bytes > self.max_bytes
                    ):
                        connection.execute("ROLLBACK")
                        return False
                    connection.execute(
                        """
                        INSERT INTO delivery_spool(
                            event_id, event_json, created_at, available_at, attempts, estimated_bytes
                        ) VALUES (?, ?, ?, ?, 0, ?)
                        """,
                        (event_id, encoded, created_at, created_at, estimated_bytes),
                    )
                    connection.execute("COMMIT")
                    return True
                except Exception:
                    connection.execute("ROLLBACK")
                    raise
        except sqlite3.DatabaseError as exc:
            raise DeliverySpoolCorruptionError("delivery spool write failed") from exc

    def next_due(self, *, now: float | None = None) -> SpoolItem | None:
        current = time.time() if now is None else now
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT id, event_json, created_at, attempts
                    FROM delivery_spool
                    WHERE available_at <= ?
                    ORDER BY available_at, id LIMIT 1
                    """,
                    (current,),
                ).fetchone()
                if row is None:
                    return None
                try:
                    event = json.loads(row["event_json"])
                    if not isinstance(event, dict):
                        raise TypeError("event is not an object")
                except (json.JSONDecodeError, TypeError) as exc:
                    connection.execute("DELETE FROM delivery_spool WHERE id = ?", (row["id"],))
                    raise DeliverySpoolCorruptionError(
                        "discarded unreadable delivery spool row"
                    ) from exc
                return SpoolItem(
                    int(row["id"]), event, float(row["created_at"]), int(row["attempts"])
                )
        except DeliverySpoolCorruptionError:
            raise
        except sqlite3.DatabaseError as exc:
            raise DeliverySpoolCorruptionError("delivery spool read failed") from exc

    def mark_delivered(self, row_id: int) -> None:
        try:
            with self._connect() as connection:
                connection.execute("DELETE FROM delivery_spool WHERE id = ?", (row_id,))
        except sqlite3.DatabaseError as exc:
            raise DeliverySpoolCorruptionError("delivery spool delete failed") from exc

    def mark_failed(self, item: SpoolItem, *, now: float | None = None) -> float:
        current = time.time() if now is None else now
        delay = min(self.backoff_max, self.backoff_base * (2**item.attempts))
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    UPDATE delivery_spool
                    SET attempts = attempts + 1, available_at = ?
                    WHERE id = ?
                    """,
                    (current + delay, item.row_id),
                )
        except sqlite3.DatabaseError as exc:
            raise DeliverySpoolCorruptionError("delivery spool retry update failed") from exc
        return delay

    def depth(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM delivery_spool").fetchone()[0])

    def estimated_bytes(self) -> int:
        with self._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COALESCE(SUM(estimated_bytes), 0) FROM delivery_spool"
                ).fetchone()[0]
            )

    def oldest_age_seconds(self, *, now: float | None = None) -> float:
        current = time.time() if now is None else now
        with self._connect() as connection:
            value = connection.execute("SELECT MIN(created_at) FROM delivery_spool").fetchone()[0]
        return 0.0 if value is None else max(0.0, current - float(value))


class RemoteCollectorSink:
    """Asynchronously forwards events to an authenticated HTTPS collector."""

    def __init__(
        self,
        url: str,
        sensor_id: str,
        secret: str,
        health: HealthTracker,
        *,
        queue_size: int = 500,
        timeout: float = 5.0,
        spool_path: Path | None = None,
        spool_max_rows: int = 5000,
        spool_max_bytes: int = 32 * 1024 * 1024,
        configuration_version: str | None = None,
        include_heartbeat: bool = False,
    ) -> None:
        parsed = urlparse(url)
        is_loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback):
            raise ValueError("collector transport requires HTTPS; HTTP is allowed only on loopback")
        if len(secret) < 16:
            raise ValueError("collector secret must contain at least 16 characters")
        self.url = url
        self.sensor_id = sensor_id
        self.secret = secret.encode()
        self.health = health
        self.timeout = min(max(timeout, 1.0), 15.0)
        self.configuration_version = str(configuration_version or "").strip() or None
        self.include_heartbeat = include_heartbeat
        self.queue: asyncio.Queue[Event | None] = asyncio.Queue(
            maxsize=max(1, min(queue_size, 5000))
        )
        self.spool = (
            SQLiteDeliverySpool(
                spool_path, max_rows=spool_max_rows, max_bytes=spool_max_bytes
            )
            if spool_path is not None
            else None
        )
        if self.spool is not None:
            self.health.collector_storage_ready = True
        self._worker: asyncio.Task | None = None
        self._wake = asyncio.Event()
        self._closing = False
        self._update_health()

    @property
    def queue_depth(self) -> int:
        return self.spool.depth() if self.spool is not None else self.queue.qsize()

    @property
    def queue_age_seconds(self) -> float:
        return self.spool.oldest_age_seconds() if self.spool is not None else 0.0

    def _update_health(self) -> None:
        try:
            self.health.collector_queue_depth = self.queue_depth
            self.health.collector_queue_age_seconds = self.queue_age_seconds
        except sqlite3.DatabaseError:
            self.health.collector_storage_ready = False

    async def start(self) -> None:
        if self._worker is None:
            self._closing = False
            target = self._run_spool() if self.spool is not None else self._run()
            self._worker = asyncio.create_task(target)

    async def close(self) -> None:
        if self._worker is None:
            return
        self._closing = True
        if self.spool is None:
            await self.queue.put(None)
        else:
            self._wake.set()
        await self._worker
        self._worker = None

    async def submit(self, event: Event) -> bool:
        if self.spool is not None:
            try:
                accepted = await asyncio.to_thread(self.spool.enqueue, event.to_dict())
            except DeliverySpoolError:
                self.health.collector_storage_ready = False
                self.health.delivery_failures += 1
                return False
            if not accepted:
                self.health.collector_queue_drops += 1
                self._update_health()
                return False
            self.health.collector_storage_ready = True
            self._wake.set()
            self._update_health()
            return True
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.health.collector_queue_drops += 1
            self._update_health()
            return False
        self._update_health()
        return True

    async def _run_spool(self) -> None:
        assert self.spool is not None
        while True:
            if self._closing:
                return
            try:
                item = await asyncio.to_thread(self.spool.next_due)
            except DeliverySpoolCorruptionError:
                self.health.collector_storage_ready = False
                self.health.collector_queue_drops += 1
                self.health.delivery_failures += 1
                self._update_health()
                continue
            if item is None:
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=0.1)
                except TimeoutError:
                    pass
                continue
            try:
                await asyncio.to_thread(self._post, item.event)
                await asyncio.to_thread(self.spool.mark_delivered, item.row_id)
                self.health.collector_storage_ready = True
                self._update_health()
            except DeliverySpoolCorruptionError:
                self.health.collector_storage_ready = False
                self.health.delivery_failures += 1
                self._update_health()
                return
            except (OSError, TimeoutError):
                self.health.delivery_failures += 1
                try:
                    await asyncio.to_thread(self.spool.mark_failed, item)
                except DeliverySpoolCorruptionError:
                    self.health.collector_storage_ready = False
                    self._update_health()
                    return
                self.health.collector_storage_ready = True
                self._update_health()

    async def _run(self) -> None:
        while True:
            event = await self.queue.get()
            try:
                if event is None:
                    return
                delivered = False
                for attempt in range(3):
                    try:
                        await asyncio.to_thread(self._post, event)
                        delivered = True
                        break
                    except (OSError, TimeoutError):
                        if attempt < 2:
                            await asyncio.sleep(0.2 * (2**attempt))
                if not delivered:
                    self.health.delivery_failures += 1
            finally:
                self.queue.task_done()
                self._update_health()

    def build_request(self, event: Event | Mapping[str, Any]) -> urllib.request.Request:
        event_data = event.to_dict() if isinstance(event, Event) else dict(event)
        envelope = {
            "schema": "ot-sentinel-envelope/1",
            "sensor_id": self.sensor_id,
            "sent_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "event": event_data,
        }
        if self.configuration_version is not None:
            envelope["configuration_version"] = self.configuration_version
        if self.include_heartbeat:
            envelope["heartbeat"] = {
                "queue_depth": self.queue_depth,
                "oldest_age_seconds": round(self.queue_age_seconds, 3),
            }
        body = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
        timestamp = str(int(time.time()))
        signature = canonical_signature(self.secret, timestamp, body)
        return urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ot-sentinel-sensor/0.2",
                "X-OT-Sensor": self.sensor_id,
                "X-OT-Timestamp": timestamp,
                "X-OT-Signature": f"sha256={signature}",
            },
        )

    def _post(self, event: Event | Mapping[str, Any]) -> None:
        request = self.build_request(event)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if not 200 <= response.status < 300:
                raise OSError(f"collector returned HTTP {response.status}")
