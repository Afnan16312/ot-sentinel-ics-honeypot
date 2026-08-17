from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from .model import Event


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass
class HealthTracker:
    sensor_id: str
    started_at: str = field(default_factory=_utc_now)
    last_event_at: str | None = None
    total_events: int = 0
    alert_queue_drops: int = 0
    collector_queue_drops: int = 0
    delivery_failures: int = 0
    protocol_events: Counter[str] = field(default_factory=Counter)
    event_types: Counter[str] = field(default_factory=Counter)

    def record(self, event: Event) -> None:
        self.total_events += 1
        self.last_event_at = event.observed_at
        self.protocol_events[event.protocol] += 1
        self.event_types[event.event_type] += 1

    def snapshot(self, queue_depth: int = 0, collector_queue_depth: int = 0) -> dict:
        return {
            "status": "ok",
            "sensor_id": self.sensor_id,
            "started_at": self.started_at,
            "last_event_at": self.last_event_at,
            "total_events": self.total_events,
            "protocol_events": dict(sorted(self.protocol_events.items())),
            "event_types": dict(sorted(self.event_types.items())),
            "alert_queue_depth": queue_depth,
            "collector_queue_depth": collector_queue_depth,
            "alert_queue_drops": self.alert_queue_drops,
            "collector_queue_drops": self.collector_queue_drops,
            "delivery_failures": self.delivery_failures,
            "generated_at": _utc_now(),
        }

    def write(
        self, path: Path, queue_depth: int = 0, collector_queue_depth: int = 0
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(
                self.snapshot(queue_depth, collector_queue_depth), indent=2, sort_keys=True
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)


class AlertPolicy:
    """Select only high-confidence, high-severity events for notification."""

    def should_alert(self, event: Event) -> bool:
        return event.severity == "high" and any(
            technique.confidence == "high" for technique in event.techniques
        )

    def redacted_payload(self, event: Event) -> dict:
        return {
            "schema": "ot-sentinel-alert/1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "sensor_id": event.sensor_id,
            "observed_at": event.observed_at,
            "protocol": event.protocol,
            "event_type": event.event_type,
            "operation": str(event.decoded.get("operation", "unknown")),
            "severity": event.severity,
            "technique_ids": [item.technique_id for item in event.techniques],
            "evidence_note": "Review the private sensor log for authorized investigation.",
        }


class WebhookAlerter:
    """Bounded, non-blocking webhook delivery with HMAC signing and deduplication."""

    def __init__(
        self,
        url: str,
        secret: str,
        health: HealthTracker,
        *,
        queue_size: int = 100,
        dedup_seconds: int = 600,
        timeout: float = 5.0,
    ) -> None:
        parsed = urlparse(url)
        is_loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback):
            raise ValueError("alert webhook must use HTTPS; HTTP is allowed only for loopback tests")
        if len(secret) < 16:
            raise ValueError("alert secret must contain at least 16 characters")
        self.url = url
        self.secret = secret.encode()
        self.health = health
        self.policy = AlertPolicy()
        self.queue: asyncio.Queue[dict | None] = asyncio.Queue(maxsize=max(1, min(queue_size, 1000)))
        self.dedup_seconds = max(1, dedup_seconds)
        self.timeout = min(max(timeout, 1.0), 15.0)
        self._seen: dict[str, float] = {}
        self._worker: asyncio.Task | None = None

    async def start(self) -> None:
        if self._worker is None:
            self._worker = asyncio.create_task(self._run())

    async def close(self) -> None:
        if self._worker is None:
            return
        await self.queue.put(None)
        await self._worker
        self._worker = None

    async def submit(self, event: Event) -> bool:
        if not self.policy.should_alert(event):
            return False
        key = f"{event.session_id}|{','.join(item.technique_id for item in event.techniques)}"
        now = time.monotonic()
        self._seen = {
            item: timestamp
            for item, timestamp in self._seen.items()
            if now - timestamp < self.dedup_seconds
        }
        if key in self._seen:
            return False
        self._seen[key] = now
        try:
            self.queue.put_nowait(self.policy.redacted_payload(event))
        except asyncio.QueueFull:
            self.health.alert_queue_drops += 1
            return False
        return True

    async def _run(self) -> None:
        while True:
            payload = await self.queue.get()
            try:
                if payload is None:
                    return
                delivered = False
                for attempt in range(3):
                    try:
                        await asyncio.to_thread(self._post, payload)
                        delivered = True
                        break
                    except (OSError, TimeoutError):
                        if attempt < 2:
                            await asyncio.sleep(0.2 * (2**attempt))
                if not delivered:
                    self.health.delivery_failures += 1
            finally:
                self.queue.task_done()

    def _post(self, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        signature = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        request = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ot-sentinel/0.2",
                "X-OT-Sentinel-Signature": f"sha256={signature}",
            },
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if not 200 <= response.status < 300:
                raise OSError(f"webhook returned HTTP {response.status}")
