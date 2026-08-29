from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from ot_sentinel.finalize import finalize_collection
from ot_sentinel.handoff import (
    MAX_JSONL_RECORD_BYTES,
    PreflightValidationError,
    atomic_write_bytes,
    import_sanitized_jsonl,
    inspect_jsonl,
    require_valid_preflight,
)
from ot_sentinel.storage import SQLiteObservationStore
from ot_sentinel.wazuh_ingest import _append_once, _connect_ledger, stage_wazuh_dataset

ROOT = Path(__file__).resolve().parents[1]
SALT = "synthetic-unit-test-privacy-salt-32-characters"
SECRET = "synthetic-unit-test-fingerprint-secret-32-chars"


def event(
    event_id: str = "handoff-event-001",
    *,
    is_demo: bool = True,
    sanitized: bool = True,
    operation: str = "write_single",
) -> dict:
    record = {
        "event_id": event_id,
        "session_id": f"session-{event_id}",
        "sensor_id": "synthetic-handoff-test",
        "observed_at": "2026-08-25T09:00:00+00:00",
        "protocol": "modbus",
        "source_port": 41000,
        "destination_port": 502,
        "event_type": "protocol_request",
        "byte_count": 12,
        "decoded": {"operation": operation, "function_code": 6},
        "techniques": [
            {
                "technique_id": "T1692.001",
                "name": "Unauthorized Message: Command Message",
                "tactic": "Impair Process Control",
                "confidence": "high",
                "rationale": "Synthetic validation fixture.",
            }
        ],
        "tags": ["synthetic-test-fixture"],
        "severity": "high",
        "is_demo": is_demo,
    }
    if sanitized:
        record.update({"source_id": "src-synthetic-safe", "sanitized": True})
    else:
        record.update({"source_ip": "192.0.2.10", "raw_payload_hex": "00010203"})
    return record


def write_jsonl(path: Path, records: list[dict], *, trailing_newline: bool = True) -> Path:
    content = "\n".join(json.dumps(record) for record in records)
    if trailing_newline:
        content += "\n"
    path.write_text(content, encoding="utf-8")
    return path


def test_preflight_accepts_valid_synthetic_and_sanitized_observed(tmp_path):
    synthetic = write_jsonl(tmp_path / "synthetic.jsonl", [event()])
    observed = write_jsonl(
        tmp_path / "observed.jsonl",
        [event("observed-001", is_demo=False)],
    )

    synthetic_report, _ = require_valid_preflight(synthetic)
    observed_report, _ = require_valid_preflight(observed)

    assert synthetic_report.data_classification == "synthetic"
    assert observed_report.data_classification == "observed"
    assert observed_report.sanitized_input is True
    assert synthetic_report.sha256 != observed_report.sha256


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (lambda records: records + [records[0]], "duplicate_event_id"),
        (
            lambda records: records
            + [event("observed-002", is_demo=False)],
            "mixed_classification",
        ),
        (
            lambda records: [{**records[0], "unknown_schema_field": True}],
            "unexpected_top_level_fields",
        ),
        (
            lambda records: [{key: value for key, value in records[0].items() if key != "sensor_id"}],
            "missing_required_fields",
        ),
        (
            lambda records: [{**records[0], "observed_at": "not-a-time"}],
            "invalid_timestamp",
        ),
        (
            lambda records: [{**records[0], "is_demo": "yes"}],
            "invalid_classification",
        ),
    ],
)
def test_preflight_fails_closed_for_duplicate_mixed_and_unknown_schema(
    tmp_path, mutator, code
):
    path = write_jsonl(tmp_path / "bad.jsonl", mutator([event()]))
    report, _ = inspect_jsonl(path)
    assert not report.valid
    assert report.error_codes[code] >= 1
    with pytest.raises(PreflightValidationError):
        require_valid_preflight(path)


def test_preflight_rejects_malformed_incomplete_and_oversized_without_leaking(tmp_path):
    private_marker = "192.0.2.99"
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text('{"source_ip":"' + private_marker + '"', encoding="utf-8")
    report, _ = inspect_jsonl(malformed)
    serialized = json.dumps(report.to_dict())
    assert not report.valid
    assert report.error_codes["malformed_json"] == 1
    assert report.error_codes["incomplete_final_line"] == 1
    assert private_marker not in serialized

    oversized_record = event()
    oversized_record["decoded"]["padding"] = "x" * MAX_JSONL_RECORD_BYTES
    oversized = write_jsonl(tmp_path / "oversized.jsonl", [oversized_record])
    oversized_report, _ = inspect_jsonl(oversized)
    assert oversized_report.error_codes["oversized_record"] == 1


def test_import_is_transactional_private_and_idempotent(tmp_path):
    source = write_jsonl(
        tmp_path / "events.jsonl",
        [event("one"), event("two", operation="device_probe")],
    )
    database = tmp_path / "private.sqlite3"
    first = import_sanitized_jsonl(
        source,
        database,
        repository_root=ROOT,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
    )
    second = import_sanitized_jsonl(
        source,
        database,
        repository_root=ROOT,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
    )
    assert (first["records_imported"], first["records_skipped"]) == (2, 0)
    assert (second["records_imported"], second["records_skipped"]) == (0, 2)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM imported_events").fetchone()[0] == 2
        assert connection.execute("SELECT SUM(repeat_count) FROM observations").fetchone()[0] == 2
    database_bytes = database.read_bytes()
    assert b"192.0.2.10" not in database_bytes
    assert b"00010203" not in database_bytes
    assert SECRET.encode() not in database_bytes
    assert SALT.encode() not in database_bytes


def test_import_rejects_cross_file_event_id_content_conflict(tmp_path):
    first_source = write_jsonl(tmp_path / "first.jsonl", [event("same-id")])
    conflicting = event("same-id", operation="device_probe")
    second_source = write_jsonl(tmp_path / "second.jsonl", [conflicting])
    database = tmp_path / "private.sqlite3"
    import_sanitized_jsonl(
        first_source,
        database,
        repository_root=ROOT,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
    )
    with pytest.raises(ValueError, match="conflicts"):
        import_sanitized_jsonl(
            second_source,
            database,
            repository_root=ROOT,
            fingerprint_secret=SECRET,
            privacy_salt=SALT,
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM imported_events").fetchone()[0] == 1


def test_import_dry_run_and_secret_and_output_guards(tmp_path):
    source = write_jsonl(tmp_path / "events.jsonl", [event()])
    result = import_sanitized_jsonl(
        source,
        tmp_path / "private.sqlite3",
        repository_root=ROOT,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
        dry_run=True,
    )
    assert result["records_accepted"] == 1
    assert not (tmp_path / "private.sqlite3").exists()
    with pytest.raises(ValueError, match="at least 32"):
        import_sanitized_jsonl(
            source,
            tmp_path / "bad.sqlite3",
            repository_root=ROOT,
            fingerprint_secret="short",
            privacy_salt=SALT,
        )
    with pytest.raises(ValueError, match="not ignored"):
        import_sanitized_jsonl(
            source,
            ROOT / "unsafe-public-output.db",
            repository_root=ROOT,
            fingerprint_secret=SECRET,
            privacy_salt=SALT,
        )


def test_storage_failure_rolls_back_entire_batch(tmp_path, monkeypatch):
    store = SQLiteObservationStore(
        tmp_path / "rollback.sqlite3",
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
    )
    records = [event("one"), event("two")]
    original = SQLiteObservationStore._insert_observation
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic storage failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(SQLiteObservationStore, "_insert_observation", staticmethod(fail_second))
    with pytest.raises(OSError, match="synthetic storage failure"):
        store.import_sanitized(records, input_digest="a" * 64)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM imported_events").fetchone()[0] == 0


def test_atomic_output_is_repeatable_and_rejects_collision(tmp_path):
    target = tmp_path / "artifact.json"
    first = atomic_write_bytes(target, b"same\n")
    second = atomic_write_bytes(target, b"same\n")
    assert first == second
    with pytest.raises(FileExistsError, match="output collision"):
        atomic_write_bytes(target, b"different\n")


def test_wazuh_staging_requires_approval_and_rejects_private_fields(tmp_path):
    safe = write_jsonl(tmp_path / "safe.jsonl", [event()])
    staging = tmp_path / "staging"
    with pytest.raises(ValueError, match="approval"):
        stage_wazuh_dataset(safe, staging, repository_root=ROOT, approved=False)
    result = stage_wazuh_dataset(safe, staging, repository_root=ROOT, approved=True)
    repeated = stage_wazuh_dataset(safe, staging, repository_root=ROOT, approved=True)
    assert result["record_count"] == 1
    assert result["already_staged"] is False
    assert repeated["already_staged"] is True
    assert (staging / result["staged_file"]).exists()
    staged_records = [
        json.loads(line)
        for line in (staging / result["staged_file"]).read_text().splitlines()
    ]
    assert [record["event_id"] for record in staged_records] == ["handoff-event-001"]

    unsafe = event()
    unsafe["decoded"]["api_token"] = "synthetic-secret-value"
    unsafe_path = write_jsonl(tmp_path / "unsafe.jsonl", [unsafe])
    with pytest.raises(ValueError, match="privacy gate"):
        stage_wazuh_dataset(unsafe_path, tmp_path / "unsafe-stage", repository_root=ROOT, approved=True)

    raw_in_sanitized = event()
    raw_in_sanitized["source_ip"] = "192.0.2.50"
    raw_in_sanitized["raw_payload_hex"] = "deadbeef"
    raw_path = write_jsonl(tmp_path / "raw-fields.jsonl", [raw_in_sanitized])
    with pytest.raises(ValueError, match="preflight failed"):
        stage_wazuh_dataset(raw_path, tmp_path / "raw-stage", repository_root=ROOT, approved=True)


def test_wazuh_staging_recovers_an_interrupted_append(tmp_path):
    target = tmp_path / "events.jsonl"
    target.write_bytes(b"existing\n")
    ledger = tmp_path / "staging.sqlite3"
    content = b'{"event_id":"recovered"}\n'
    digest = hashlib.sha256(content).hexdigest()
    with _connect_ledger(ledger) as connection:
        connection.execute(
            """
            INSERT INTO staged_imports(
                input_digest, content_digest, start_offset, byte_count, status,
                created_at_epoch
            ) VALUES (?, ?, ?, ?, 'pending', ?)
            """,
            ("b" * 64, digest, len(b"existing\n"), len(content), 1),
        )
    with target.open("ab") as handle:
        handle.write(content[:7])

    already = _append_once(
        target,
        ledger,
        input_digest="b" * 64,
        content=content,
        content_digest=digest,
    )
    assert already is False
    assert target.read_bytes() == b"existing\n" + content


def test_wazuh_staging_blocks_a_new_dataset_behind_an_unrecovered_import(tmp_path):
    target = tmp_path / "events.jsonl"
    target.touch()
    ledger = tmp_path / "staging.sqlite3"
    with _connect_ledger(ledger) as connection:
        connection.execute(
            """
            INSERT INTO staged_imports(
                input_digest, content_digest, start_offset, byte_count, status,
                created_at_epoch
            ) VALUES (?, ?, 0, 10, 'pending', 1)
            """,
            ("a" * 64, "c" * 64),
        )
    with pytest.raises(RuntimeError, match="different interrupted"):
        _append_once(
            target,
            ledger,
            input_digest="b" * 64,
            content=b"safe\n",
            content_digest=hashlib.sha256(b"safe\n").hexdigest(),
        )


def test_final_processor_private_only_is_idempotent_and_manifest_safe(tmp_path):
    source = write_jsonl(tmp_path / "observed.jsonl", [event(is_demo=False)])
    workspace = tmp_path / "handoff"
    first = finalize_collection(
        source,
        workspace,
        repository_root=ROOT,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
    )
    second = finalize_collection(
        source,
        workspace,
        repository_root=ROOT,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
    )
    assert first["data_classification"] == "sanitized_observed_private"
    assert "aggregate_streamlit_candidate" not in first["outputs"]
    assert second["rerun_status"] == "already_complete_and_verified"
    serialized = json.dumps(first)
    assert "192.0.2." not in serialized
    assert "raw_payload_hex" not in serialized
    assert SECRET not in serialized
    assert SALT not in serialized
    assert str(tmp_path) not in serialized
    assert first["approval"]["publication"] is False


def test_final_processor_requires_explicit_public_candidate_approval(tmp_path):
    source = write_jsonl(tmp_path / "synthetic.jsonl", [event()])
    workspace = tmp_path / "handoff"
    dry_run = finalize_collection(
        source,
        workspace,
        repository_root=ROOT,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
        dry_run=True,
    )
    assert not workspace.exists()
    assert "aggregate_streamlit_candidate" not in dry_run["planned_stages"]

    approved = finalize_collection(
        source,
        workspace,
        repository_root=ROOT,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
        approve_public_candidates=True,
    )
    assert "aggregate_streamlit_candidate" in approved["outputs"]
    assert "public_profile_stix_candidate" in approved["outputs"]
    assert approved["approval"]["public_candidate_creation"] is True
    assert approved["approval"]["publication"] is False


def test_final_processor_sanitizes_raw_fixture_and_requires_strong_secrets(tmp_path):
    raw = write_jsonl(tmp_path / "raw.jsonl", [event(is_demo=False, sanitized=False)])
    with pytest.raises(ValueError, match="at least 32"):
        finalize_collection(
            raw,
            tmp_path / "weak",
            repository_root=ROOT,
            fingerprint_secret="weak",
            privacy_salt=SALT,
        )
    manifest = finalize_collection(
        raw,
        tmp_path / "safe",
        repository_root=ROOT,
        fingerprint_secret=SECRET,
        privacy_salt=SALT,
    )
    run_directory = next((tmp_path / "safe").iterdir())
    sanitized = (run_directory / manifest["outputs"]["sanitized_candidate"]["path"]).read_text()
    assert "192.0.2.10" not in sanitized
    assert "raw_payload_hex" not in sanitized
    assert '"sanitized":true' in sanitized


def test_private_output_directories_are_not_tracked():
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "data/private",
            "reports/private",
            "exports/private",
            "tests/soc/staging",
            "tests/soc/generated",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == ""
