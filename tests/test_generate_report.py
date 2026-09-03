from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ot_sentinel.storage import SQLiteObservationStore
from scripts.generate_report import build_report

SECRET = "synthetic-fingerprint-secret-32-characters"
SALT = "synthetic-private-salt-at-least-32-chars"
AS_OF = datetime(2026, 1, 8, tzinfo=UTC)


def store(path: Path) -> SQLiteObservationStore:
    return SQLiteObservationStore(path, fingerprint_secret=SECRET, privacy_salt=SALT)


def event(
    event_id: str,
    *,
    source_ip: str = "192.0.2.30",
    protocol: str = "modbus",
    technique_id: str = "T0836",
    confidence: str = "medium",
    is_demo: bool = True,
) -> dict:
    return {
        "event_id": event_id,
        "session_id": f"session-{event_id}",
        "observed_at": "2026-01-07T00:00:00+00:00",
        "protocol": protocol,
        "event_type": "protocol_request",
        "source_ip": source_ip,
        "severity": "high",
        "is_demo": is_demo,
        "decoded": {"operation": "write_single"},
        "tags": ["synthetic"] if is_demo else [],
        "techniques": [{"technique_id": technique_id, "confidence": confidence}],
    }


def test_report_includes_required_sections_repeat_counts_and_honesty(tmp_path):
    database = tmp_path / "observations.sqlite3"
    index = store(database)
    first = event("one")
    now = int(datetime(2026, 1, 7, tzinfo=UTC).timestamp())
    index.record(first, payload=b"same", now=now)
    index.record(first, payload=b"same", now=now + 1)
    index.record(event("two", protocol="s7", technique_id="T0843"), payload=b"two", now=now)

    report, is_demo = build_report(database, as_of=AS_OF)

    assert is_demo is True
    assert report.startswith("# Weekly OT Threat Intelligence Brief")
    assert "Total sessions represented: **2**" in report
    assert "Total events including repetitions: **3**" in report
    assert "| modbus | 2 |" in report
    assert "| s7 | 1 |" in report
    assert "T0836" in report and "medium: 2" in report
    assert "not proof of intent or compromise" in report


def test_report_empty_window_is_explicit_and_safe(tmp_path):
    database = tmp_path / "observations.sqlite3"
    store(database)

    report, is_demo = build_report(database, as_of=AS_OF)

    assert is_demo is True
    assert "Total sessions represented: **0**" in report
    assert "| None | 0 | No mapped techniques" in report


def test_report_rejects_mixed_classification(tmp_path):
    database = tmp_path / "observations.sqlite3"
    index = store(database)
    now = int(datetime(2026, 1, 7, tzinfo=UTC).timestamp())
    index.record(event("demo"), payload=b"demo", now=now)
    index.record(event("observed", is_demo=False), payload=b"observed", now=now)

    with pytest.raises(ValueError, match="must not be mixed"):
        build_report(database, as_of=AS_OF)


def test_report_ties_are_ordered_deterministically(tmp_path):
    database = tmp_path / "observations.sqlite3"
    index = store(database)
    now = int(datetime(2026, 1, 7, tzinfo=UTC).timestamp())
    index.record(event("one", technique_id="T1692.001"), payload=b"one", now=now)
    index.record(event("two", technique_id="T0836"), payload=b"two", now=now)

    report, _ = build_report(database, as_of=AS_OF)

    assert report.index("| T0836 |") < report.index("| T1692.001 |")


def test_report_contains_only_salted_source_pseudonym(tmp_path):
    database = tmp_path / "observations.sqlite3"
    index = store(database)
    now = int(datetime(2026, 1, 7, tzinfo=UTC).timestamp())
    index.record(event("one", source_ip="198.51.100.40"), payload=b"one", now=now)

    report, _ = build_report(database, as_of=AS_OF)

    assert "198.51.100.40" not in report
    assert "src-" in report
