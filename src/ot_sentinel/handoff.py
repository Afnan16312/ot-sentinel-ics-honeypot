from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .publication import PublicationValidationError, load_public_jsonl
from .storage import SQLiteObservationStore

MAX_JSONL_RECORD_BYTES = 64 * 1024
HANDOFF_SCHEMA_VERSION = "ot-sentinel-handoff-1.0"
SUPPORTED_PROTOCOLS = {"modbus", "s7", "iec104"}
SUPPORTED_EVENT_TYPES = {
    "connection",
    "protocol_request",
    "session_error",
    "known_exploit_probe",
}
REQUIRED_FIELDS = {
    "event_id",
    "session_id",
    "sensor_id",
    "observed_at",
    "protocol",
    "event_type",
    "decoded",
    "techniques",
    "tags",
    "severity",
    "is_demo",
}
ALLOWED_FIELDS = REQUIRED_FIELDS | {
    "source_ip",
    "source_id",
    "source_network",
    "source_port",
    "destination_port",
    "byte_count",
    "raw_payload_hex",
    "source_country",
    "source_country_code",
    "source_latitude",
    "source_longitude",
    "source_asn",
    "sanitized",
    "transport_authenticated",
    "configuration_version",
    "data_notice",
}


@dataclass(frozen=True)
class PreflightReport:
    schema_version: str
    sha256: str
    file_size_bytes: int
    total_records: int
    valid_records: int
    invalid_records: int
    duplicate_event_ids: int
    earliest_timestamp: str | None
    latest_timestamp: str | None
    protocols: dict[str, int]
    event_types: dict[str, int]
    data_classification: str
    sanitized_input: bool | None
    incomplete_or_malformed: bool
    error_codes: dict[str, int]
    safe_errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.incomplete_or_malformed and self.invalid_records == 0

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["valid"] = self.valid
        return result


class PreflightValidationError(ValueError):
    """Fail-closed preflight result that never includes event field values."""

    def __init__(self, report: PreflightReport) -> None:
        self.report = report
        super().__init__("historical event preflight failed; review the safe report")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _record_errors(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_FIELDS - set(record))
    if missing:
        errors.append("missing_required_fields")
    if set(record) - ALLOWED_FIELDS:
        errors.append("unexpected_top_level_fields")
    for key in ("event_id", "session_id", "sensor_id", "severity"):
        if not isinstance(record.get(key), str) or not str(record.get(key)).strip():
            errors.append(f"invalid_{key}")
    if record.get("protocol") not in SUPPORTED_PROTOCOLS:
        errors.append("unsupported_protocol")
    if record.get("event_type") not in SUPPORTED_EVENT_TYPES:
        errors.append("unsupported_event_type")
    if _safe_timestamp(record.get("observed_at")) is None:
        errors.append("invalid_timestamp")
    if not isinstance(record.get("is_demo"), bool):
        errors.append("invalid_classification")
    if not isinstance(record.get("decoded"), dict):
        errors.append("invalid_decoded_object")
    if not isinstance(record.get("techniques"), list):
        errors.append("invalid_techniques_list")
    if not isinstance(record.get("tags"), list):
        errors.append("invalid_tags_list")

    sanitized = record.get("sanitized")
    if sanitized is not None and sanitized is not True:
        errors.append("invalid_sanitized_flag")
    if sanitized is True:
        if not isinstance(record.get("source_id"), str) or not record["source_id"].strip():
            errors.append("missing_sanitized_source_id")
        if "source_ip" in record or "raw_payload_hex" in record:
            errors.append("private_fields_in_sanitized_record")
    elif not isinstance(record.get("source_ip"), str) or not record["source_ip"].strip():
        errors.append("missing_private_source_ip")

    raw_payload = record.get("raw_payload_hex")
    if raw_payload is not None and (
        not isinstance(raw_payload, str)
        or (
            len(raw_payload) > 1024
            or bool(raw_payload)
            and (
                len(raw_payload) % 2 != 0
                or any(
                    character not in "0123456789abcdefABCDEF"
                    for character in raw_payload
                )
            )
        )
    ):
        errors.append("invalid_raw_payload")
    return sorted(set(errors))


def inspect_jsonl(path: str | Path) -> tuple[PreflightReport, list[dict[str, Any]]]:
    """Inspect a JSONL evidence file while returning only privacy-safe diagnostics."""
    source = Path(path)
    size = source.stat().st_size
    digest = _sha256(source)
    records: list[dict[str, Any]] = []
    classifications: set[bool] = set()
    sanitized_flags: set[bool] = set()
    event_ids: set[str] = set()
    duplicate_count = 0
    protocols: Counter[str] = Counter()
    event_types: Counter[str] = Counter()
    timestamps: list[datetime] = []
    error_codes: Counter[str] = Counter()
    safe_errors: list[str] = []
    invalid_records = 0
    total_records = 0

    with source.open("rb") as handle:
        raw_lines = handle.readlines()
    incomplete = bool(raw_lines and not raw_lines[-1].endswith(b"\n"))
    if incomplete:
        safe_errors.append("file does not end with a complete newline-terminated record")

    for line_number, raw_line in enumerate(raw_lines, start=1):
        if not raw_line.strip():
            continue
        total_records += 1
        line_errors: list[str] = []
        if incomplete and line_number == len(raw_lines):
            line_errors.append("incomplete_final_line")
        if len(raw_line) > MAX_JSONL_RECORD_BYTES:
            line_errors.append("oversized_record")
            value: object = None
        else:
            try:
                value = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                value = None
                line_errors.append("malformed_json")
        if value is not None and not isinstance(value, dict):
            line_errors.append("record_not_object")
        if isinstance(value, dict):
            line_errors.extend(_record_errors(value))
            event_id = value.get("event_id")
            if isinstance(event_id, str) and event_id:
                if event_id in event_ids:
                    duplicate_count += 1
                    line_errors.append("duplicate_event_id")
                else:
                    event_ids.add(event_id)
            classification = value.get("is_demo")
            if isinstance(classification, bool):
                classifications.add(classification)
            sanitized_flags.add(value.get("sanitized") is True)
            timestamp = _safe_timestamp(value.get("observed_at"))
            if timestamp is not None:
                timestamps.append(timestamp)
            protocol = value.get("protocol")
            if isinstance(protocol, str):
                protocols[protocol] += 1
            event_type = value.get("event_type")
            if isinstance(event_type, str):
                event_types[event_type] += 1
        line_errors = sorted(set(line_errors))
        if line_errors:
            invalid_records += 1
            for code in line_errors:
                error_codes[code] += 1
            safe_errors.append(
                f"record {line_number} failed: {', '.join(line_errors)}"
            )
        elif isinstance(value, dict):
            records.append(value)

    if not total_records:
        error_codes["empty_file"] += 1
        safe_errors.append("file contains no event records")
    if len(classifications) > 1:
        error_codes["mixed_classification"] += 1
        safe_errors.append("synthetic and observed records are mixed")
    if len(sanitized_flags) > 1:
        error_codes["mixed_privacy_state"] += 1
        safe_errors.append("raw and sanitized records are mixed")

    if classifications == {True}:
        classification = "synthetic"
    elif classifications == {False}:
        classification = "observed"
    elif len(classifications) > 1:
        classification = "mixed"
    else:
        classification = "unknown"
    sanitized_input = next(iter(sanitized_flags)) if len(sanitized_flags) == 1 else None
    report = PreflightReport(
        schema_version=HANDOFF_SCHEMA_VERSION,
        sha256=digest,
        file_size_bytes=size,
        total_records=total_records,
        valid_records=total_records - invalid_records,
        invalid_records=invalid_records,
        duplicate_event_ids=duplicate_count,
        earliest_timestamp=(
            min(timestamps).isoformat(timespec="milliseconds") if timestamps else None
        ),
        latest_timestamp=(
            max(timestamps).isoformat(timespec="milliseconds") if timestamps else None
        ),
        protocols=dict(sorted(protocols.items())),
        event_types=dict(sorted(event_types.items())),
        data_classification=classification,
        sanitized_input=sanitized_input,
        incomplete_or_malformed=bool(error_codes),
        error_codes=dict(sorted(error_codes.items())),
        safe_errors=tuple(safe_errors[:100]),
    )
    return report, records


def require_valid_preflight(path: str | Path) -> tuple[PreflightReport, list[dict[str, Any]]]:
    report, records = inspect_jsonl(path)
    if not report.valid:
        raise PreflightValidationError(report)
    return report, records


def require_private_output(path: str | Path, *, repository_root: str | Path) -> Path:
    """Refuse a repository output unless Git confirms that it is ignored."""
    target = Path(path).resolve()
    root = Path(repository_root).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return target
    result = subprocess.run(
        ["git", "check-ignore", "--quiet", str(target)],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ValueError("output path is inside the repository but is not ignored by Git")
    return target


def atomic_write_bytes(path: Path, content: bytes) -> str:
    """Write once atomically; identical reruns are safe and collisions fail closed."""
    digest = hashlib.sha256(content).hexdigest()
    if path.exists():
        if _sha256(path) == digest:
            return digest
        raise FileExistsError("output collision: an existing artifact has different content")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return digest


def canonical_jsonl(records: list[dict[str, Any]]) -> bytes:
    return b"".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        for record in records
    )


def import_sanitized_jsonl(
    input_path: str | Path,
    database_path: str | Path,
    *,
    repository_root: str | Path,
    fingerprint_secret: str,
    privacy_salt: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    report, _ = require_valid_preflight(input_path)
    try:
        records = load_public_jsonl(input_path)
    except PublicationValidationError as exc:
        raise ValueError("sanitized input failed the privacy gate") from exc
    target = require_private_output(database_path, repository_root=repository_root)
    if len(fingerprint_secret) < 32 or len(privacy_salt) < 32:
        raise ValueError("analysis secrets must each contain at least 32 characters")
    result: dict[str, Any] = {
        "data_classification": report.data_classification,
        "input_sha256": report.sha256,
        "records_accepted": len(records),
        "records_imported": 0,
        "records_skipped": 0,
        "dry_run": dry_run,
    }
    if dry_run:
        return result
    store = SQLiteObservationStore(
        target,
        fingerprint_secret=fingerprint_secret,
        privacy_salt=privacy_salt,
    )
    imported, skipped = store.import_sanitized(records, input_digest=report.sha256)
    result["records_imported"] = imported
    result["records_skipped"] = skipped
    return result
