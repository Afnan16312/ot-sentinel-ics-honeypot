from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class TechniqueMatch:
    technique_id: str
    name: str
    tactic: str
    confidence: str
    rationale: str


@dataclass
class Event:
    protocol: str
    source_ip: str
    source_port: int
    destination_port: int
    event_type: str
    sensor_id: str = "local-lab-01"
    observed_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="milliseconds")
    )
    event_id: str = field(default_factory=lambda: str(uuid4()))
    session_id: str = ""
    byte_count: int = 0
    raw_payload_hex: str = ""
    decoded: dict[str, Any] = field(default_factory=dict)
    techniques: list[TechniqueMatch] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    severity: str = "info"
    is_demo: bool = False
    source_country: str = "Unknown"
    source_country_code: str = "ZZ"
    source_latitude: float | None = None
    source_longitude: float | None = None
    source_asn: str = "Unknown"

    def __post_init__(self) -> None:
        if not self.session_id:
            material = f"{self.sensor_id}|{self.source_ip}|{self.source_port}|{self.observed_at}"
            self.session_id = sha256(material.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

