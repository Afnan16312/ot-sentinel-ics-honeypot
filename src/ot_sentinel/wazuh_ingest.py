from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from .handoff import (
    HANDOFF_SCHEMA_VERSION,
    atomic_write_bytes,
    canonical_jsonl,
    require_private_output,
    require_valid_preflight,
)
from .publication import PublicationValidationError, load_public_jsonl


def stage_wazuh_dataset(
    input_path: str | Path,
    staging_directory: str | Path,
    *,
    repository_root: str | Path,
    approved: bool,
) -> dict[str, Any]:
    """Atomically stage only privacy-validated events for local Wazuh collection."""
    if not approved:
        raise ValueError("explicit local-ingestion approval is required")
    report, _ = require_valid_preflight(input_path)
    try:
        records = load_public_jsonl(input_path)
    except PublicationValidationError as exc:
        raise ValueError("Wazuh input failed the privacy gate") from exc
    staging = require_private_output(staging_directory, repository_root=repository_root)
    staging.mkdir(parents=True, exist_ok=True)
    filename = "events.jsonl"
    target = staging / filename
    ledger = staging / "staging.sqlite3"
    content = canonical_jsonl(records)
    artifact_hash = hashlib.sha256(content).hexdigest()
    already_staged = _append_once(
        target,
        ledger,
        input_digest=report.sha256,
        content=content,
        content_digest=artifact_hash,
    )
    metadata = {
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "data_classification": report.data_classification,
        "input_sha256": report.sha256,
        "staged_sha256": artifact_hash,
        "record_count": len(records),
        "sanitized": True,
        "local_ingestion_approved": True,
        "published": False,
        "staged_file": filename,
    }
    _write_manifest(staging / f"manifest-{report.sha256[:16]}.json", metadata)
    return {**metadata, "already_staged": already_staged}


def _write_manifest(path: Path, metadata: dict[str, Any]) -> None:
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("existing Wazuh staging manifest is unreadable") from exc
        if isinstance(existing, dict):
            existing.pop("already_staged", None)
        if existing != metadata:
            raise ValueError("existing Wazuh staging manifest conflicts with this import")
        return
    atomic_write_bytes(
        path,
        (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode(),
    )


def _connect_ledger(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=5.0, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS staged_imports (
            input_digest TEXT PRIMARY KEY,
            content_digest TEXT NOT NULL,
            start_offset INTEGER NOT NULL,
            byte_count INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending', 'committed')),
            created_at_epoch INTEGER NOT NULL
        )
        """
    )
    return connection


def _append_once(
    target: Path,
    ledger: Path,
    *,
    input_digest: str,
    content: bytes,
    content_digest: str,
) -> bool:
    """Two-phase, restart-safe append to the one file watched by Wazuh."""
    target.touch(exist_ok=True)
    with _connect_ledger(ledger) as connection:
        connection.execute("BEGIN IMMEDIATE")
        other_pending = connection.execute(
            """
            SELECT 1 FROM staged_imports
            WHERE status = 'pending' AND input_digest <> ? LIMIT 1
            """,
            (input_digest,),
        ).fetchone()
        if other_pending is not None:
            connection.execute("ROLLBACK")
            raise RuntimeError(
                "a different interrupted Wazuh import must be retried before new staging"
            )
        row = connection.execute(
            "SELECT * FROM staged_imports WHERE input_digest = ?", (input_digest,)
        ).fetchone()
        if row is not None and row["status"] == "committed":
            if row["content_digest"] != content_digest:
                connection.execute("ROLLBACK")
                raise RuntimeError("Wazuh staging digest conflicts with its import ledger")
            connection.execute("COMMIT")
            return True
        if row is not None and row["content_digest"] != content_digest:
            connection.execute("ROLLBACK")
            raise RuntimeError("Wazuh staging digest conflicts with its pending import")
        if row is None:
            start_offset = target.stat().st_size
            connection.execute(
                """
                INSERT INTO staged_imports(
                    input_digest, content_digest, start_offset, byte_count, status,
                    created_at_epoch
                ) VALUES (?, ?, ?, ?, 'pending', ?)
                """,
                (
                    input_digest,
                    content_digest,
                    start_offset,
                    len(content),
                    int(time.time()),
                ),
            )
        connection.execute("COMMIT")

    with _connect_ledger(ledger) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM staged_imports WHERE input_digest = ?", (input_digest,)
        ).fetchone()
        if row is None:
            connection.execute("ROLLBACK")
            raise RuntimeError("Wazuh staging ledger lost a pending import")
        start = int(row["start_offset"])
        expected_end = start + int(row["byte_count"])
        with target.open("r+b") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size < start:
                connection.execute("ROLLBACK")
                raise RuntimeError("Wazuh staging file is shorter than its import ledger")
            if size >= expected_end:
                handle.seek(start)
                existing = handle.read(int(row["byte_count"]))
                existing_digest = hashlib.sha256(existing).hexdigest()
                if existing_digest != row["content_digest"]:
                    connection.execute("ROLLBACK")
                    raise RuntimeError("Wazuh staging recovery found conflicting content")
            else:
                handle.truncate(start)
                handle.seek(start)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        connection.execute(
            "UPDATE staged_imports SET status = 'committed' WHERE input_digest = ?",
            (input_digest,),
        )
        connection.execute("COMMIT")
    return False
