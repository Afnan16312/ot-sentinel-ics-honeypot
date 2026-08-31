from __future__ import annotations

import asyncio
import json

from ot_sentinel.contract_migrations import migrate_record
from ot_sentinel.contracts import observation_from_event
from ot_sentinel.model import Event, TechniqueMatch
from ot_sentinel.sensor import JsonlWriter
from ot_sentinel.storage import SQLiteObservationStore
from scripts.migrate_contracts import migrate

SECRET = "synthetic-fingerprint-secret-32-characters"
SALT = "synthetic-private-salt-at-least-32-chars"


def event() -> Event:
    value = Event(
        "modbus", "192.0.2.10", 12345, 502, "protocol_request", raw_payload_hex="0102"
    )
    value.techniques = [TechniqueMatch("T0877", "I/O Image", "Collection", "low", "read")]
    value.severity = "medium"
    return value


def test_observation_contract_removes_analytical_conclusions():
    observation = observation_from_event(event())
    assert observation["schema_version"] == "ot-sentinel.observation/v1"
    assert observation["data_classification"] == "raw_private"
    assert "techniques" not in observation
    assert "severity" not in observation


def test_legacy_migration_preserves_evidence_and_moves_analysis():
    observation, analysis = migrate_record(event().to_dict())
    assert observation["capture"]["legacy_import"] is True
    assert analysis is not None
    assert analysis["event_id"] == observation["event_id"]
    assert analysis["attack_hypotheses"][0]["technique_id"] == "T0877"


def test_writer_keeps_observation_and_analysis_in_separate_stores(tmp_path):
    store = SQLiteObservationStore(
        tmp_path / "observations.sqlite3", fingerprint_secret=SECRET, privacy_salt=SALT
    )
    path = tmp_path / "events.jsonl"
    asyncio.run(JsonlWriter(path, store).append(event()))
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["schema_version"] == "ot-sentinel.observation/v1"
    assert "techniques" not in stored
    result = json.loads(store.analysis_results()[0]["result_json"])
    assert result["schema_version"] == "ot-sentinel.analysis/v1"
    assert result["attack_hypotheses"][0]["technique_id"] == "T0877"


def test_migration_writes_separate_contract_files_without_changing_legacy_input(tmp_path):
    source = tmp_path / "legacy.jsonl"
    legacy_line = json.dumps(event().to_dict()) + "\n"
    source.write_text(legacy_line, encoding="utf-8")
    observations = tmp_path / "observations-v1.jsonl"
    analyses = tmp_path / "analyses-v1.jsonl"

    assert migrate(source, observations, analyses, dry_run=True) == {"observations": 1, "analyses": 1}
    assert not observations.exists()
    assert migrate(source, observations, analyses, dry_run=False) == {"observations": 1, "analyses": 1}
    assert source.read_text(encoding="utf-8") == legacy_line
    assert json.loads(observations.read_text(encoding="utf-8"))["schema_version"] == "ot-sentinel.observation/v1"
    assert json.loads(analyses.read_text(encoding="utf-8"))["schema_version"] == "ot-sentinel.analysis/v1"
