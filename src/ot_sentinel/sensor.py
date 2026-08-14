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
from .protocols import (
    iec104_response,
    modbus_response,
    parse_iec104,
    parse_modbus,
    parse_s7,
    s7_response,
)

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
    ) -> None:
        self.host = host
        self.ports = ports
        self.writer = writer
        self.sensor_id = sensor_id
        self.max_payload = min(max(max_payload, 64), 4096)
        self.timeout = min(max(timeout, 1.0), 30.0)
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
        addresses = ", ".join(str(sock.getsockname()) for s in self.servers for sock in s.sockets or [])
        print(f"OT Sentinel listening on {addresses}")
        async with asyncio.TaskGroup() as group:
            for server in self.servers:
                group.create_task(server.serve_forever())

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
        await self.writer.append(session_seed)
        try:
            payload = await asyncio.wait_for(reader.read(self.max_payload), timeout=self.timeout)
            if payload:
                decoded = parser(payload)
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
                    tags=["low-interaction", "no-execution"],
                )
                event.techniques = map_event(protocol, event.event_type, decoded)
                event.severity = severity_for(event.techniques)
                await self.writer.append(event)
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
            await self.writer.append(error)
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
    return parser


def main() -> None:
    args = build_parser().parse_args()
    sensor = LowInteractionSensor(
        host=args.host,
        ports={"modbus": args.modbus_port, "s7": args.s7_port, "iec104": args.iec104_port},
        writer=JsonlWriter(Path(args.log)),
        sensor_id=args.sensor_id,
        max_payload=args.max_payload,
        timeout=args.timeout,
    )
    try:
        asyncio.run(sensor.serve_forever())
    except KeyboardInterrupt:
        print("Sensor stopped")


if __name__ == "__main__":
    main()
