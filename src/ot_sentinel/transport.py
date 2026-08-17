from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import urllib.request
from datetime import UTC, datetime
from urllib.parse import urlparse

from .model import Event
from .operations import HealthTracker


def canonical_signature(secret: bytes, timestamp: str, body: bytes) -> str:
    material = timestamp.encode() + b"\n" + body
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


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
        self.queue: asyncio.Queue[Event | None] = asyncio.Queue(
            maxsize=max(1, min(queue_size, 5000))
        )
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
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.health.collector_queue_drops += 1
            return False
        return True

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

    def build_request(self, event: Event) -> urllib.request.Request:
        envelope = {
            "schema": "ot-sentinel-envelope/1",
            "sensor_id": self.sensor_id,
            "sent_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "event": event.to_dict(),
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

    def _post(self, event: Event) -> None:
        request = self.build_request(event)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if not 200 <= response.status < 300:
                raise OSError(f"collector returned HTTP {response.status}")

