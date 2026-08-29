from __future__ import annotations

import json
import random
import sys
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ot_sentinel.mapper import map_event

SOURCES = [
    ("src-17a8d03c9f41", "Netherlands", "NL", 52.13, 5.29, "AS64501 Example Research Network"),
    ("src-2bc71a408af0", "United States", "US", 37.09, -95.71, "AS64502 Example Cloud"),
    ("src-3d045f9118ac", "Germany", "DE", 51.16, 10.45, "AS64503 Example Hosting"),
    ("src-4425bd7e3a12", "Singapore", "SG", 1.35, 103.82, "AS64504 Example Transit"),
    ("src-596eb139b774", "France", "FR", 46.23, 2.21, "AS64505 Example Network"),
    ("src-6cd28f140b51", "United Kingdom", "GB", 55.38, -3.44, "AS64506 Example VPS"),
    ("src-710cff3d2e90", "Brazil", "BR", -14.24, -51.93, "AS64507 Example Broadband"),
    ("src-8e29f406a718", "Japan", "JP", 36.20, 138.25, "AS64508 Example ISP"),
    ("src-93f8ae185c02", "Canada", "CA", 56.13, -106.35, "AS64509 Example Cloud"),
    ("src-a02e55cf7b31", "India", "IN", 20.59, 78.96, "AS64510 Example Broadband"),
]

OPERATIONS = {
    "modbus": [("device_probe", 0.58), ("write_single", 0.27), ("write_multiple", 0.15)],
    "s7": [("connection_setup", 0.82), ("program_download", 0.18)],
    "iec104": [("interrogation", 0.61), ("single_command", 0.25), ("setpoint_command", 0.14)],
}


def weighted_choice(items: list[tuple[str, float]], rng: random.Random) -> str:
    value = rng.random()
    cumulative = 0.0
    for item, weight in items:
        cumulative += weight
        if value <= cumulative:
            return item
    return items[-1][0]


def generate(count: int = 420) -> list[dict]:
    rng = random.Random(20260814)
    start = datetime(2026, 7, 1, tzinfo=UTC)
    events: list[dict] = []
    for index in range(count):
        protocol = rng.choices(["modbus", "s7", "iec104"], weights=[0.56, 0.24, 0.20])[0]
        operation = weighted_choice(OPERATIONS[protocol], rng)
        source_id, country, code, lat, lon, asn = rng.choice(SOURCES)
        observed = start + timedelta(minutes=rng.randint(0, 14 * 24 * 60), seconds=rng.randint(0, 59))
        decoded: dict = {"operation": operation, "valid": True}
        if protocol == "modbus":
            function_map = {"device_probe": 3, "write_single": 6, "write_multiple": 16}
            decoded.update(
                {
                    "function_code": function_map[operation],
                    "unit_id": rng.choice([1, 1, 1, 2, 7]),
                    "address": rng.randint(0, 180),
                    "value_or_quantity": rng.randint(1, 24),
                }
            )
        elif protocol == "s7":
            decoded.update({"cotp_pdu_type": "0xe0", "rack": 0, "slot": 2})
        else:
            decoded.update({"type_id": rng.choice([45, 46, 100])})
        techniques = [item.__dict__ for item in map_event(protocol, "protocol_request", decoded)]
        high_ids = {"T1692.001", "T0843", "T0866"}
        medium_ids = {"T0836", "T0877", "T0806"}
        ids = {item["technique_id"] for item in techniques}
        severity = "high" if ids & high_ids else "medium" if ids & medium_ids else "info"
        session_material = f"{source_id}|{observed.date()}|{index // 3}"
        events.append(
            {
                "event_id": sha256(f"demo-{index}".encode()).hexdigest()[:24],
                "session_id": sha256(session_material.encode()).hexdigest()[:16],
                "sensor_id": "uae-north-decoy-demo",
                "observed_at": observed.isoformat(timespec="seconds"),
                "protocol": protocol,
                "source_id": source_id,
                "source_port": rng.randint(1024, 65535),
                "destination_port": {"modbus": 502, "s7": 102, "iec104": 2404}[protocol],
                "source_country": country,
                "source_country_code": code,
                "source_latitude": lat + rng.uniform(-0.8, 0.8),
                "source_longitude": lon + rng.uniform(-0.8, 0.8),
                "source_asn": asn,
                "event_type": "protocol_request",
                "byte_count": rng.randint(12, 188),
                "decoded": decoded,
                "techniques": techniques,
                "tags": ["synthetic", "portfolio-demo", "no-real-source"],
                "severity": severity,
                "is_demo": True,
                "sanitized": True,
                "data_notice": "Synthetic event; not an observed attack.",
            }
        )
    return sorted(events, key=lambda item: item["observed_at"])


def main() -> None:
    output = ROOT / "data" / "demo_events.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for event in generate():
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    print(f"Wrote {count_lines(output)} events to {output}")


def count_lines(path: Path) -> int:
    with path.open(encoding="utf-8") as handle:
        return sum(1 for _ in handle)


if __name__ == "__main__":
    main()
