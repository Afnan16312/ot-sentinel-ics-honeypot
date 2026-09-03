import json
from pathlib import Path

import pytest

from scripts.build_public_summary import build_summary


def write_records(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def synthetic_record(event_id: str = "event-001") -> dict:
    return {
        "event_id": event_id,
        "session_id": "session-example",
        "source_id": "src-example",
        "observed_at": "2026-01-02T03:04:05+00:00",
        "protocol": "modbus",
        "event_type": "protocol_request",
        "severity": "medium",
        "techniques": [{"technique_id": "T0846.001"}],
        "is_demo": True,
        "sanitized": True,
    }


def test_summary_contains_only_aggregate_statistics(tmp_path):
    source = tmp_path / "synthetic.jsonl"
    record = synthetic_record()
    write_records(source, [record, {**record, "event_id": "event-002", "protocol": "s7"}])

    summary = build_summary(source)

    assert summary["data_classification"] == "synthetic_demo"
    assert summary["totals"] == {"events": 2, "sessions": 1, "pseudonymous_sources": 1}
    assert summary["protocols"] == {"modbus": 1, "s7": 1}
    serialized = json.dumps(summary)
    assert "src-example" not in serialized
    assert "session-example" not in serialized


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_ip", "192.0.2.10"),
        ("raw_payload_hex", "00010203"),
        ("source_network", "192.0.2.0/24"),
    ],
)
def test_summary_rejects_private_or_address_material(tmp_path, field, value):
    source = tmp_path / "unsafe.jsonl"
    write_records(source, [{**synthetic_record(), field: value}])

    with pytest.raises(ValueError, match="public-data validation"):
        build_summary(source)


def test_summary_rejects_mixed_data_classes(tmp_path):
    source = tmp_path / "mixed.jsonl"
    write_records(source, [synthetic_record(), {**synthetic_record("event-002"), "is_demo": False}])

    with pytest.raises(ValueError, match="must not be mixed"):
        build_summary(source)
