from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from scripts.check_health import EXIT_CRITICAL, EXIT_OK, EXIT_WARNING, evaluate_health, render_text

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)


def snapshot(**overrides):
    value = {
        "status": "ok",
        "generated_at": (NOW - timedelta(seconds=10)).isoformat(),
        "last_event_at": (NOW - timedelta(seconds=30)).isoformat(),
        "alert_queue_drops": 0,
        "collector_queue_drops": 0,
        "delivery_failures": 0,
        "collector_storage_ready": True,
    }
    value.update(overrides)
    return value


def evaluate(value, **kwargs):
    return evaluate_health(value, now=NOW, disk_free_percent=50.0, **kwargs)


def test_healthy_snapshot_returns_zero():
    result = evaluate(snapshot(), expect_traffic=True)
    assert result.status == "ok"
    assert result.exit_code == EXIT_OK


def test_stale_snapshot_is_critical_and_stale_event_is_warning():
    stale_snapshot = evaluate(
        snapshot(generated_at=(NOW - timedelta(minutes=5)).isoformat())
    )
    assert stale_snapshot.exit_code == EXIT_CRITICAL
    stale_event = evaluate(
        snapshot(last_event_at=(NOW - timedelta(hours=1)).isoformat()),
        expect_traffic=True,
    )
    assert stale_event.exit_code == EXIT_WARNING


def test_low_disk_has_distinct_warning_and_critical_codes():
    warning = evaluate_health(snapshot(), now=NOW, disk_free_percent=7.0)
    critical = evaluate_health(snapshot(), now=NOW, disk_free_percent=2.0)
    assert warning.exit_code == EXIT_WARNING
    assert critical.exit_code == EXIT_CRITICAL


def test_queue_drop_and_delivery_failure_are_warning():
    result = evaluate(snapshot(collector_queue_drops=1, delivery_failures=2))
    assert result.exit_code == EXIT_WARNING
    assert {finding.check for finding in result.findings} >= {"queue_drops", "delivery"}


def test_rejected_sessions_are_a_capacity_warning():
    result = evaluate(snapshot(rejected_sessions=1))
    assert result.exit_code == EXIT_WARNING
    assert any(finding.check == "session_capacity" for finding in result.findings)


def test_storage_failure_is_critical():
    result = evaluate(snapshot(collector_storage_ready=False))
    assert result.exit_code == EXIT_CRITICAL
    assert any(finding.check == "collector_storage" for finding in result.findings)


def test_process_failure_is_critical():
    result = evaluate(snapshot(), process_running=False)
    assert result.exit_code == EXIT_CRITICAL
    assert any(finding.check == "process" for finding in result.findings)


def test_outputs_are_privacy_safe():
    value = snapshot(source_ip="192.0.2.55", raw_payload_hex="private-marker")
    result = evaluate(value)
    encoded = json.dumps(result.to_dict()) + render_text(result)
    assert "192.0.2.55" not in encoded
    assert "private-marker" not in encoded
    assert "source_ip" not in encoded
