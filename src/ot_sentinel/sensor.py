from __future__ import annotations

import argparse
import asyncio
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .mapper import map_event
from .model import Event
from .normalizer import severity_for
from .operations import HealthTracker, WebhookAlerter
from .profiles import ProfileRuntime, load_profile
from .protocols import (
    iec104_response,
    modbus_response,
    parse_iec104,
    parse_modbus,
    parse_s7,
    s7_response,
)
from .transport import RemoteCollectorSink

Parser = Callable[[bytes], dict[str, Any]]
Responder = Callable[[bytes, dict[str, Any]], bytes]


class JsonlWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def append(self, event: Event) -> None:
        line = json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True)
        async with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


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
        self.max_payload = min(max(max_payload, 64), 4096)
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
        await self.writer.append(event)
        self.health.record(event)
        if self.alerter is not None:
            await self.alerter.submit(event)
        if self.collector is not None:
            await self.collector.submit(event)
        if self.health_path is not None:
            alert_depth = self.alerter.queue.qsize() if self.alerter is not None else 0
            collector_depth = self.collector.queue.qsize() if self.collector is not None else 0
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
        "--collector-url",
        default=os.getenv("OT_COLLECTOR_URL", ""),
        help="Optional authenticated HTTPS central collector /v1/events URL",
    )
    parser.add_argument(
        "--collector-secret",
        default=os.getenv("OT_COLLECTOR_SECRET", ""),
        help=argparse.SUPPRESS,
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    profile = ProfileRuntime(load_profile(args.profile)) if args.profile else None
    health = HealthTracker(args.sensor_id)
    alerter = None
    if args.alert_webhook:
        if not args.alert_secret:
            raise SystemExit("Set OT_ALERT_SECRET when OT_ALERT_WEBHOOK is configured.")
        alerter = WebhookAlerter(args.alert_webhook, args.alert_secret, health)
    collector = None
    if args.collector_url:
        if not args.collector_secret:
            raise SystemExit("Set OT_COLLECTOR_SECRET when OT_COLLECTOR_URL is configured.")
        collector = RemoteCollectorSink(
            args.collector_url, args.sensor_id, args.collector_secret, health
        )
    sensor = LowInteractionSensor(
        host=args.host,
        ports={"modbus": args.modbus_port, "s7": args.s7_port, "iec104": args.iec104_port},
        writer=JsonlWriter(Path(args.log)),
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
