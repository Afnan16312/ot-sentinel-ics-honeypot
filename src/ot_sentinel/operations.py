from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import urllib.request
from collections import Counter
from collections.abc import Mapping
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
    collector_queue_depth: int = 0
    collector_queue_age_seconds: float = 0.0
    collector_storage_ready: bool | None = None
    protocol_events: Counter[str] = field(default_factory=Counter)
    event_types: Counter[str] = field(default_factory=Counter)

    def record(self, event: Event) -> None:
        self.total_events += 1
        self.last_event_at = event.observed_at
        self.protocol_events[event.protocol] += 1
        self.event_types[event.event_type] += 1

    def snapshot(
        self, queue_depth: int = 0, collector_queue_depth: int | None = None
    ) -> dict:
        return {
            "status": "ok",
            "sensor_id": self.sensor_id,
            "started_at": self.started_at,
            "last_event_at": self.last_event_at,
            "total_events": self.total_events,
            "protocol_events": dict(sorted(self.protocol_events.items())),
            "event_types": dict(sorted(self.event_types.items())),
            "alert_queue_depth": queue_depth,
            "collector_queue_depth": (
                self.collector_queue_depth
                if collector_queue_depth is None
                else collector_queue_depth
            ),
            "alert_queue_drops": self.alert_queue_drops,
            "collector_queue_drops": self.collector_queue_drops,
            "delivery_failures": self.delivery_failures,
            "collector_queue_age_seconds": round(self.collector_queue_age_seconds, 3),
            "collector_storage_ready": self.collector_storage_ready,
            "generated_at": _utc_now(),
        }

    def write(
        self, path: Path, queue_depth: int = 0, collector_queue_depth: int | None = None
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


@dataclass(frozen=True)
class AlertSettings:
    """Local alert configuration; the file is JSON-compatible YAML by design."""

    enabled: bool
    webhook_url: str
    secret_env: str = "OT_ALERT_SECRET"
    queue_size: int = 100
    timeout_seconds: float = 5.0


def load_alert_settings(path: Path) -> AlertSettings:
    """Load a small, dependency-free alerts.yaml file without accepting executable YAML."""

    if path.stat().st_size > 64 * 1024:
        raise ValueError("alert configuration exceeds 64 KiB")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("alert configuration must use the JSON subset of YAML") from exc
    if not isinstance(data, Mapping):
        raise TypeError("alert configuration must be an object")
    allowed = {"enabled", "webhook_url", "secret_env", "queue_size", "timeout_seconds"}
    if set(data) - allowed:
        raise ValueError("alert configuration contains unsupported fields")
    enabled = data.get("enabled", False)
    if not isinstance(enabled, bool):
        raise TypeError("alert enabled must be a boolean")
    webhook_url = str(data.get("webhook_url", "")).strip()
    secret_env = str(data.get("secret_env", "OT_ALERT_SECRET")).strip()
    if not secret_env.isidentifier() or not secret_env.startswith("OT_"):
        raise ValueError("alert secret_env must be an OT_ environment variable name")
    queue_size = data.get("queue_size", 100)
    timeout_seconds = data.get("timeout_seconds", 5.0)
    if not isinstance(queue_size, int) or not 1 <= queue_size <= 1000:
        raise ValueError("alert queue_size must be between 1 and 1000")
    if not isinstance(timeout_seconds, (int, float)) or not 1 <= timeout_seconds <= 15:
        raise ValueError("alert timeout_seconds must be between 1 and 15")
    if enabled and not webhook_url:
        raise ValueError("enabled alert configuration requires webhook_url")
    return AlertSettings(enabled, webhook_url, secret_env, queue_size, float(timeout_seconds))


class AlertPolicy:
    """Select high-severity events for notification without exposing raw evidence."""

    def should_alert(self, event: Event) -> bool:
        return event.severity.lower() == "high"

    def redacted_payload(self, event: Event, source_hash: str) -> dict:
        return {
            "schema": "ot-sentinel-alert/1",
            "observed_at": event.observed_at,
            "protocol": event.protocol,
            "severity": event.severity,
            "mitre_attack_ids": [item.technique_id for item in event.techniques],
            "source_hash": source_hash,
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
            source_hash = hmac.new(self.secret, event.source_ip.encode(), hashlib.sha256).hexdigest()[:24]
            self.queue.put_nowait(self.policy.redacted_payload(event, source_hash))
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
