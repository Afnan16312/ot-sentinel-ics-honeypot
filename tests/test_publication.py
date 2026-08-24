from __future__ import annotations

import json
from pathlib import Path

import pytest

from ot_sentinel.publication import (
    PublicationValidationError,
    contains_address_literal,
    load_public_jsonl,
    validate_public_records,
    validate_public_stix_bundle,
)


def record(**overrides):
    value = {
        "event_id": "synthetic-event",
        "source_id": "src-safe-pseudonym",
        "protocol": "modbus",
        "event_type": "protocol_request",
        "decoded": {"operation": "write_single", "function_code": 6},
        "is_demo": True,
        "sanitized": True,
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize(
    "unsafe",
    [
        {"source_ip": "192.0.2.5"},
        {"raw_payload_hex": "00010000"},
        {"source_network": "192.0.2.0/24"},
        {"source_id": "src-192.0.2.5"},
        {"decoded": {"nested": [{"api_token": "synthetic-secret"}]}},
        {"decoded": {"payload": "synthetic-bytes"}},
    ],
)
def test_public_record_gate_rejects_private_material(unsafe):
    with pytest.raises(PublicationValidationError):
        validate_public_records([{**record(), **unsafe}])


def test_address_detection_handles_embedded_ipv4_ipv6_and_prefixes():
    assert contains_address_literal("src-192.0.2.5")
    assert contains_address_literal("2001:db8::1")
    assert contains_address_literal("198.51.100.0/24")
    assert not contains_address_literal("src-a93b8ce2f710")


def test_public_record_gate_rejects_mixed_provenance():
    with pytest.raises(PublicationValidationError, match="must not be mixed"):
        validate_public_records([record(), record(is_demo=False)])


def test_jsonl_loader_fails_closed_on_any_invalid_record(tmp_path):
    path = tmp_path / "public.jsonl"
    path.write_text(
        json.dumps(record()) + "\n" + json.dumps(record(source_ip="192.0.2.7")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PublicationValidationError):
        load_public_jsonl(path)


def test_public_stix_second_gate_rejects_payload_credentials_and_addresses():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "observed-data",
                "x_ot_sentinel_payload": "synthetic-bytes",
                "nested": [{"password": "synthetic-secret"}],
                "source": "192.0.2.9",
            }
        ],
    }
    with pytest.raises(PublicationValidationError) as caught:
        validate_public_stix_bundle(bundle)
    message = str(caught.value)
    assert "forbidden STIX field" in message
    assert "address or network prefix" in message


def test_public_stix_gate_accepts_safe_minimal_bundle():
    validate_public_stix_bundle(
        {
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [{"type": "identity", "name": "Synthetic producer"}],
        }
    )


def test_streamlit_validates_before_normalizing_and_revalidates_stix():
    source = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
    assert source.index("records = load_public_jsonl(path)") < source.index(
        "frame = pd.json_normalize(records)"
    )
    assert "validate_public_stix_bundle(public_stix)" in source
