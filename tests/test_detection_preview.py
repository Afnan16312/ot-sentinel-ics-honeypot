from __future__ import annotations

import json
from pathlib import Path

from ot_sentinel.detection_preview import (
    detection_coverage_backlog,
    load_native_validation_evidence,
    preview_detections,
)

ROOT = Path(__file__).resolve().parents[1]


def event(operation="write_single", *, event_type="protocol_request", function_code=6):
    return {
        "event_id": "synthetic-event",
        "sensor_id": "synthetic-sensor",
        "source_id": "src-safe",
        "protocol": "modbus",
        "event_type": event_type,
        "decoded": {
            "operation": operation,
            "function_code": function_code,
            "unit_id": 1,
        },
        "is_demo": True,
        "sanitized": True,
    }


def test_modbus_write_predicts_sigma_wazuh_and_suricata_rules():
    predictions = preview_detections([event()], root=ROOT)
    assert {prediction.engine for prediction in predictions} == {"Sigma", "Wazuh", "Suricata"}
    assert {prediction.rule_id for prediction in predictions} >= {
        "608780d4-c637-4cc1-ac7a-17545ca5bbdd",
        "110001",
        "4200501",
    }
    assert all(prediction.technique != "not mapped" for prediction in predictions)


def test_connection_only_and_normal_read_predict_no_high_severity_alert():
    connection = event("unknown", event_type="connection", function_code=3)
    read = event("device_probe", function_code=3)
    predictions = preview_detections([connection, read], root=ROOT)
    assert not [prediction for prediction in predictions if prediction.severity in {"high", "critical"}]


def test_preview_contains_no_source_or_payload_material():
    unsafe_private_input = {
        **event(),
        "source_ip": "192.0.2.80",
        "raw_payload_hex": "private-marker",
    }
    encoded = json.dumps(
        [prediction.to_dict() for prediction in preview_detections([unsafe_private_input], root=ROOT)]
    )
    assert "192.0.2.80" not in encoded
    assert "private-marker" not in encoded
    assert "source_ip" not in encoded


def test_native_validation_record_is_dated_and_versioned_without_runtime_claims():
    evidence = load_native_validation_evidence(str(ROOT / "tests" / "soc" / "NATIVE_VALIDATION.md"))

    assert evidence is not None
    assert evidence.status == "passed synthetic fixtures"
    assert evidence.validated_on == "2026-08-25"
    assert evidence.wazuh_version == "4.14.7"
    assert evidence.suricata_version == "8.0.4"


def test_coverage_backlog_distinguishes_covered_and_rule_opportunity_behaviors():
    covered = {
        **event(),
        "techniques": [{"technique_id": "T0836"}],
    }
    uncovered = {
        **event("read_holding_registers", function_code=3),
        "event_id": "mapped-read",
        "techniques": [{"technique_id": "T0877"}],
    }
    rows = detection_coverage_backlog([covered, uncovered], root=ROOT)
    by_operation = {row.operation: row for row in rows}

    assert by_operation["write_single"].status == "covered in pack"
    assert by_operation["write_single"].rule_engines == "Sigma, Suricata, Wazuh"
    assert by_operation["read_holding_registers"].status == "rule opportunity"
    assert "positive and nearest-negative fixtures" in by_operation["read_holding_registers"].next_action
