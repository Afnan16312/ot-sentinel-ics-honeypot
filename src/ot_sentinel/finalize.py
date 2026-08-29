from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from scripts.build_public_summary import build_summary
from scripts.export_navigator import build_layer, validate_layer
from scripts.generate_report import build_report

from .handoff import (
    HANDOFF_SCHEMA_VERSION,
    atomic_write_bytes,
    canonical_jsonl,
    import_sanitized_jsonl,
    require_private_output,
    require_valid_preflight,
)
from .privacy import sanitize_event
from .publication import validate_public_records, validate_public_stix_bundle
from .stix_export import export_events

MANIFEST_SCHEMA_VERSION = "ot-sentinel-processing-manifest-1.0"


def _tool_version() -> str:
    try:
        return version("ot-sentinel")
    except PackageNotFoundError:
        return "0.2.0"


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checkpoint(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def _relative_artifact(run_directory: Path, path: Path) -> dict[str, str]:
    return {
        "path": path.relative_to(run_directory).as_posix(),
        "sha256": _hash(path),
    }


def _verify_existing_manifest(run_directory: Path, input_sha256: str) -> dict[str, Any] | None:
    manifest_path = run_directory / "processing-manifest.json"
    if not manifest_path.exists():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("existing processing manifest is unreadable") from exc
    if manifest.get("input", {}).get("sha256") != input_sha256:
        raise ValueError("existing processing manifest does not match the input")
    for artifact in manifest.get("outputs", {}).values():
        if not isinstance(artifact, dict):
            raise TypeError("existing processing manifest has an invalid output entry")
        relative = artifact.get("path")
        expected = artifact.get("sha256")
        path = run_directory / str(relative)
        if not path.is_file() or _hash(path) != expected:
            raise ValueError("existing processing output failed checksum verification")
    manifest["rerun_status"] = "already_complete_and_verified"
    return manifest


def finalize_collection(
    input_path: str | Path,
    workspace: str | Path,
    *,
    repository_root: str | Path,
    fingerprint_secret: str,
    privacy_salt: str,
    dry_run: bool = False,
    approve_public_candidates: bool = False,
) -> dict[str, Any]:
    """Build an offline, private, reproducible handoff without publishing anything."""
    report, source_records = require_valid_preflight(input_path)
    if len(fingerprint_secret) < 32 or len(privacy_salt) < 32:
        raise ValueError("OT_FINGERPRINT_SECRET and OT_PRIVACY_SALT must be at least 32 characters")
    root = Path(repository_root).resolve()
    private_workspace = require_private_output(workspace, repository_root=root)

    if report.sanitized_input is True:
        sanitized_records = validate_public_records(source_records)
    else:
        sanitized_records = validate_public_records(
            [sanitize_event(record, privacy_salt) for record in source_records]
        )
    sanitized_bytes = canonical_jsonl(sanitized_records)
    run_suffix = "reviewed-candidates" if approve_public_candidates else "private-only"
    run_directory = private_workspace / f"{report.sha256[:16]}-{run_suffix}"
    run_plan = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "dry_run": dry_run,
        "input": {
            "sha256": report.sha256,
            "record_count": report.total_records,
            "classification": report.data_classification,
            "sanitized_on_input": report.sanitized_input,
        },
        "approval": {
            "public_candidate_creation": approve_public_candidates,
            "publication": False,
        },
        "planned_stages": [
            "integrity_preflight",
            "sanitized_candidate",
            "privacy_validation",
            "privacy_reduced_sqlite_import",
            "wazuh_ready_output",
            "private_weekly_report",
            "private_attack_navigator_layer",
            *(
                ["aggregate_streamlit_candidate", "public_profile_stix_candidate"]
                if approve_public_candidates
                else []
            ),
            "processing_manifest",
        ],
        "publication_performed": False,
    }
    if dry_run:
        return run_plan

    existing = _verify_existing_manifest(run_directory, report.sha256)
    if existing is not None:
        return existing

    sanitized_path = run_directory / "sanitized" / "events.sanitized.jsonl"
    database_path = run_directory / "analysis" / "observations.sqlite3"
    wazuh_path = run_directory / "wazuh" / "events.jsonl"
    report_path = run_directory / "reports" / "weekly-private.md"
    navigator_path = run_directory / "exports" / "attack-navigator-private.json"
    summary_path = run_directory / "public-candidate" / "streamlit-summary.json"
    stix_path = run_directory / "public-candidate" / "events.stix.json"

    atomic_write_bytes(sanitized_path, sanitized_bytes)
    import_result = import_sanitized_jsonl(
        sanitized_path,
        database_path,
        repository_root=root,
        fingerprint_secret=fingerprint_secret,
        privacy_salt=privacy_salt,
    )
    atomic_write_bytes(wazuh_path, sanitized_bytes)

    latest = datetime.fromisoformat(str(report.latest_timestamp))
    as_of = latest.astimezone(UTC) + timedelta(seconds=1)
    report_text, _ = build_report(database_path, as_of=as_of, days=90)
    atomic_write_bytes(report_path, (report_text + "\n").encode())

    layer = build_layer(database_path)
    layer_errors = validate_layer(layer)
    if layer_errors:
        raise ValueError("ATT&CK Navigator candidate failed validation")
    atomic_write_bytes(
        navigator_path,
        (json.dumps(layer, indent=2, sort_keys=True) + "\n").encode(),
    )

    if approve_public_candidates:
        summary = build_summary(sanitized_path)
        atomic_write_bytes(
            summary_path,
            (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode(),
        )
        bundle = export_events(sanitized_records, profile="public")
        validate_public_stix_bundle(bundle)
        atomic_write_bytes(
            stix_path,
            (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode(),
        )

    _checkpoint(database_path)
    outputs = {
        "sanitized_candidate": _relative_artifact(run_directory, sanitized_path),
        "analysis_database": _relative_artifact(run_directory, database_path),
        "wazuh_ready_jsonl": _relative_artifact(run_directory, wazuh_path),
        "private_weekly_report": _relative_artifact(run_directory, report_path),
        "private_attack_navigator": _relative_artifact(run_directory, navigator_path),
    }
    if approve_public_candidates:
        outputs["aggregate_streamlit_candidate"] = _relative_artifact(
            run_directory, summary_path
        )
        outputs["public_profile_stix_candidate"] = _relative_artifact(
            run_directory, stix_path
        )

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tool": {"name": "ot-sentinel", "version": _tool_version()},
        "event_schema": HANDOFF_SCHEMA_VERSION,
        "data_classification": (
            "synthetic_demo"
            if report.data_classification == "synthetic"
            else "sanitized_observed_private"
        ),
        "input": {
            "sha256": report.sha256,
            "file_size_bytes": report.file_size_bytes,
            "record_count": report.total_records,
            "earliest_timestamp": report.earliest_timestamp,
            "latest_timestamp": report.latest_timestamp,
            "protocols": report.protocols,
            "event_types": report.event_types,
        },
        "stages_completed": run_plan["planned_stages"],
        "validation": {
            "integrity_preflight": True,
            "privacy_gate": True,
            "sqlite_transaction": True,
            "navigator": True,
            "stix": approve_public_candidates,
        },
        "import": import_result,
        "outputs": outputs,
        "approval": {
            "public_candidate_creation": approve_public_candidates,
            "publication": False,
            "manual_review_still_required": True,
        },
        "automatic_upload": False,
        "automatic_dashboard_replacement": False,
    }
    atomic_write_bytes(
        run_directory / "processing-manifest.json",
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
    )
    return manifest
