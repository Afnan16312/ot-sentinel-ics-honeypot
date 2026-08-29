from __future__ import annotations

import argparse
import asyncio
import binascii
import json
import os
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .mapper import map_event
from .model import Event
from .normalizer import severity_for
from .operations import HealthTracker, WebhookAlerter, load_alert_settings
from .profiles import ProfileRuntime, load_profile
from .protocols import (
    iec104_response,
    modbus_response,
    parse_iec104,
    parse_modbus,
    parse_s7,
    s7_response,
)
from .storage import SQLiteObservationStore
from .transport import RemoteCollectorSink

Parser = Callable[[bytes], dict[str, Any]]
Responder = Callable[[bytes, dict[str, Any]], bytes]


class JsonlWriter:
    def __init__(
        self, path: Path, observation_store: SQLiteObservationStore | None = None
    ) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self.observation_store = observation_store
        self.database_failures = 0

    async def append(self, event: Event) -> bool:
        line = json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True)
        async with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        if self.observation_store is not None:
            try:
                payload = bytes.fromhex(event.raw_payload_hex)
                record = getattr(
                    self.observation_store, "record_with_assessment", self.observation_store.record
                )
                await asyncio.to_thread(
                    record, event.to_dict(), payload=payload
                )
                return True
            except (binascii.Error, OSError, sqlite3.Error, ValueError):
                # JSONL is authoritative; an optional analysis-index failure must not lose it.
                self.database_failures += 1
        return False


class LowInteractionSensor:
    def __init__(
        self,
        host: str,
        ports: dict[str, int],
        writer: JsonlWriter,
        sensor_id: str,
        max_payload: int = 512,
        timeout: float = 8.0,
        profile: ProfileRuntime | None = None,
        health_path: Path | None = None,
        alerter: WebhookAlerter | None = None,
        collector: RemoteCollectorSink | None = None,
    ) -> None:
        self.host = host
        self.ports = ports
        self.writer = writer
        self.sensor_id = sensor_id
        if not 1 <= max_payload <= 512:
            raise ValueError("max_payload must be between 1 and the hard 512-byte limit")
        self.max_payload = max_payload
        self.timeout = min(max(timeout, 1.0), 30.0)
        self.profile = profile
        self.health_path = health_path
        if alerter is not None:
            self.health = alerter.health
        elif collector is not None:
            self.health = collector.health
        else:
            self.health = HealthTracker(sensor_id)
        self.alerter = alerter
        self.collector = collector
        self.servers: list[asyncio.Server] = []

    async def start(self) -> None:
        handlers: dict[str, tuple[Parser, Responder]] = {
            "modbus": (parse_modbus, modbus_response),
            "s7": (parse_s7, s7_response),
            "iec104": (parse_iec104, iec104_response),
        }
        for protocol, port in self.ports.items():
            parser, responder = handlers[protocol]
            server = await asyncio.start_server(
                lambda reader, writer, p=protocol, pa=parser, r=responder: self.handle(
                    reader, writer, p, pa, r
                ),
                self.host,
                port,
                limit=self.max_payload + 64,
            )
            self.servers.append(server)

    async def serve_forever(self) -> None:
        await self.start()
        if self.alerter is not None:
            await self.alerter.start()
        if self.collector is not None:
            await self.collector.start()
        addresses = ", ".join(str(sock.getsockname()) for s in self.servers for sock in s.sockets or [])
        print(f"OT Sentinel listening on {addresses}")
        try:
            async with asyncio.TaskGroup() as group:
                for server in self.servers:
                    group.create_task(server.serve_forever())
        finally:
            if self.alerter is not None:
                await self.alerter.close()
            if self.collector is not None:
                await self.collector.close()

    async def emit(self, event: Event) -> None:
        private_recorded = await self.writer.append(event)
        self.health.record(event)
        if self.alerter is not None and (
            self.writer.observation_store is None or private_recorded
        ):
            await self.alerter.submit(event)
        if self.collector is not None:
            await self.collector.submit(event)
        if self.health_path is not None:
            alert_depth = self.alerter.queue.qsize() if self.alerter is not None else 0
            collector_depth = self.collector.queue_depth if self.collector is not None else 0
            if self.collector is not None:
                self.health.collector_queue_age_seconds = self.collector.queue_age_seconds
            self.health.write(self.health_path, alert_depth, collector_depth)

    async def handle(
        self,
        reader: asyncio.StreamReader,
        stream: asyncio.StreamWriter,
        protocol: str,
        parser: Parser,
        responder: Responder,
    ) -> None:
        peer = stream.get_extra_info("peername") or ("0.0.0.0", 0)
        local = stream.get_extra_info("sockname") or ("0.0.0.0", self.ports[protocol])
        source_ip, source_port = str(peer[0]), int(peer[1])
        session_seed = Event(
            protocol=protocol,
            source_ip=source_ip,
            source_port=source_port,
            destination_port=int(local[1]),
            event_type="connection",
            sensor_id=self.sensor_id,
            tags=["low-interaction", "no-execution"],
        )
        await self.emit(session_seed)
        try:
            payload = await asyncio.wait_for(reader.read(self.max_payload), timeout=self.timeout)
            if payload:
                decoded = parser(payload)
                if self.profile is not None:
                    self.profile.enrich(protocol, decoded)
                tags = ["low-interaction", "no-execution"]
                if self.profile is not None:
                    tags.append(f"profile:{self.profile.definition.profile_id}")
                event = Event(
                    protocol=protocol,
                    source_ip=source_ip,
                    source_port=source_port,
                    destination_port=int(local[1]),
                    event_type="protocol_request",
                    sensor_id=self.sensor_id,
                    session_id=session_seed.session_id,
                    byte_count=len(payload),
                    raw_payload_hex=payload.hex(),
                    decoded=decoded,
                    tags=tags,
                )
                event.techniques = map_event(protocol, event.event_type, decoded)
                event.severity = severity_for(event.techniques)
                await self.emit(event)
                reply = responder(payload, decoded)
                if reply:
                    stream.write(reply)
                    await stream.drain()
        except (TimeoutError, ConnectionError, OSError) as exc:
            error = Event(
                protocol=protocol,
                source_ip=source_ip,
                source_port=source_port,
                destination_port=int(local[1]),
                event_type="session_error",
                sensor_id=self.sensor_id,
                session_id=session_seed.session_id,
                decoded={"error": type(exc).__name__},
                tags=["bounded-error"],
            )
            await self.emit(error)
        finally:
            stream.close()
            try:
                await stream.wait_closed()
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the OT Sentinel low-interaction sensor")
    parser.add_argument("--host", default=os.getenv("OT_BIND_HOST", "0.0.0.0"))
    parser.add_argument("--log", default=os.getenv("OT_LOG_PATH", "logs/events.jsonl"))
    parser.add_argument("--sensor-id", default=os.getenv("OT_SENSOR_ID", "local-lab-01"))
    parser.add_argument("--modbus-port", type=int, default=int(os.getenv("OT_MODBUS_PORT", "1502")))
    parser.add_argument("--s7-port", type=int, default=int(os.getenv("OT_S7_PORT", "1102")))
    parser.add_argument("--iec104-port", type=int, default=int(os.getenv("OT_IEC104_PORT", "2404")))
    parser.add_argument(
        "--max-payload",
        type=int,
        default=int(os.getenv("OT_MAX_PAYLOAD_BYTES", "512")),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.getenv("OT_SESSION_TIMEOUT_SECONDS", "8")),
    )
    parser.add_argument(
        "--profile",
        default=os.getenv("OT_PROFILE_PATH", ""),
        help="Safe JSON-subset-of-YAML fictional process profile",
    )
    parser.add_argument(
        "--health-file",
        default=os.getenv("OT_HEALTH_PATH", ""),
        help="Write an atomic JSON sensor health snapshot after each event",
    )
    parser.add_argument(
        "--alert-webhook",
        default=os.getenv("OT_ALERT_WEBHOOK", ""),
        help="Optional HTTPS endpoint for redacted high-confidence alerts",
    )
    parser.add_argument(
        "--alert-secret",
        default=os.getenv("OT_ALERT_SECRET", ""),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--alerts-config",
        default=os.getenv("OT_ALERTS_CONFIG", ""),
        help="Optional local alerts.yaml configuration (JSON subset of YAML)",
    )
    parser.add_argument(
        "--collector-url",
        default=os.getenv("OT_COLLECTOR_URL", ""),
        help="Optional authenticated HTTPS central collector /v1/events URL",
    )
    parser.add_argument(
        "--collector-secret",
        default=os.getenv("OT_COLLECTOR_SECRET", ""),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--collector-spool",
        default=os.getenv("OT_COLLECTOR_SPOOL", ""),
        help="Optional private SQLite queue for restart-safe collector delivery",
    )
    parser.add_argument(
        "--collector-spool-max-rows",
        type=int,
        default=int(os.getenv("OT_COLLECTOR_SPOOL_MAX_ROWS", "5000")),
    )
    parser.add_argument(
        "--collector-spool-max-bytes",
        type=int,
        default=int(os.getenv("OT_COLLECTOR_SPOOL_MAX_BYTES", str(32 * 1024 * 1024))),
    )
    parser.add_argument(
        "--configuration-version",
        default=os.getenv("OT_CONFIGURATION_VERSION", ""),
    )
    parser.add_argument(
        "--collector-heartbeat",
        action="store_true",
        default=os.getenv("OT_COLLECTOR_HEARTBEAT", "").lower() in {"1", "true", "yes"},
    )
    parser.add_argument(
        "--observation-db",
        default=os.getenv("OT_OBSERVATION_DB", ""),
        help="Optional private SQLite analysis index",
    )
    parser.add_argument(
        "--fingerprint-secret",
        default=os.getenv("OT_FINGERPRINT_SECRET", ""),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--privacy-salt",
        default=os.getenv("OT_PRIVACY_SALT", ""),
        help=argparse.SUPPRESS,
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    profile = ProfileRuntime(load_profile(args.profile)) if args.profile else None
    health = HealthTracker(args.sensor_id)
    alerter = None
    alert_webhook = args.alert_webhook
    alert_secret = args.alert_secret
    alert_queue_size = 100
    alert_timeout = 5.0
    if args.alerts_config:
        if args.alert_webhook:
            raise SystemExit("Use either --alerts-config or --alert-webhook, not both.")
        settings = load_alert_settings(Path(args.alerts_config))
        if settings.enabled:
            if not args.observation_db:
                raise SystemExit("Enabled alerts.yaml requires --observation-db for private alert gating.")
            alert_webhook = settings.webhook_url
            alert_secret = os.getenv(settings.secret_env, "")
            alert_queue_size = settings.queue_size
            alert_timeout = settings.timeout_seconds
    if alert_webhook:
        if not alert_secret:
            raise SystemExit("Set OT_ALERT_SECRET when webhook alerting is configured.")
        alerter = WebhookAlerter(
            alert_webhook,
            alert_secret,
            health,
            queue_size=alert_queue_size,
            timeout=alert_timeout,
        )
    collector = None
    if args.collector_url:
        if not args.collector_secret:
            raise SystemExit("Set OT_COLLECTOR_SECRET when OT_COLLECTOR_URL is configured.")
        collector = RemoteCollectorSink(
            args.collector_url,
            args.sensor_id,
            args.collector_secret,
            health,
            spool_path=Path(args.collector_spool) if args.collector_spool else None,
            spool_max_rows=args.collector_spool_max_rows,
            spool_max_bytes=args.collector_spool_max_bytes,
            configuration_version=args.configuration_version or None,
            include_heartbeat=args.collector_heartbeat,
        )
    observation_store = None
    if args.observation_db:
        if not args.fingerprint_secret or not args.privacy_salt:
            raise SystemExit(
                "Set OT_FINGERPRINT_SECRET and OT_PRIVACY_SALT when observation indexing is enabled."
            )
        observation_store = SQLiteObservationStore(
            Path(args.observation_db),
            fingerprint_secret=args.fingerprint_secret,
            privacy_salt=args.privacy_salt,
        )
    sensor = LowInteractionSensor(
        host=args.host,
        ports={"modbus": args.modbus_port, "s7": args.s7_port, "iec104": args.iec104_port},
        writer=JsonlWriter(Path(args.log), observation_store),
        sensor_id=args.sensor_id,
        max_payload=args.max_payload,
        timeout=args.timeout,
        profile=profile,
        health_path=Path(args.health_file) if args.health_file else None,
        alerter=alerter,
        collector=collector,
    )
    try:
        asyncio.run(sensor.serve_forever())
    except KeyboardInterrupt:
        print("Sensor stopped")


if __name__ == "__main__":
    main()
