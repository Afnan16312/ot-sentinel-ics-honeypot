from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contracts import validate_analysis
from .privacy import pseudonymize_ip
from .triage import TriageAssessment, assess_event

REPLAY_TTL_SECONDS = 900
DEDUP_WINDOW_SECONDS = 30 * 60


@dataclass(frozen=True)
class StoredObservation:
    """Private-index result used for alerting and analyst prioritization."""

    observation_id: int
    assessment: TriageAssessment
    repeat_source_count: int
    novel_payload: bool


def _require_secret(value: str, label: str) -> bytes:
    if len(value) < 32:
        raise ValueError(f"{label} must contain at least 32 characters")
    return value.encode()


def _epoch(value: str | datetime | None) -> int:
    if value is None:
        return int(time.time())
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp())


def observation_fingerprint(secret: bytes, source_ip: str, protocol: str, payload: bytes) -> str:
    material = source_ip.encode() + b"\0" + protocol.encode() + b"\0" + payload
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def sanitized_observation_fingerprint(
    secret: bytes, source_id: str, protocol: str, event_type: str, decoded: object
) -> str:
    material = json.dumps(
        [source_id, protocol, event_type, decoded],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


class MemoryReplayStore:
    """Thread-safe replay reservations for tests and explicit ephemeral use."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def reserve(self, replay_key: str, *, now: int, ttl: int = REPLAY_TTL_SECONDS) -> bool:
        with self._lock:
            self._seen = {
                key: expires_at for key, expires_at in self._seen.items() if expires_at > now
            }
            if replay_key in self._seen:
                return False
            self._seen[replay_key] = now + ttl
            return True

    def release(self, replay_key: str) -> None:
        with self._lock:
            self._seen.pop(replay_key, None)


class SQLiteReplayStore:
    """Durable replay reservations shared safely across collector threads and restarts."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_keys (
                    sensor_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    expires_at_epoch INTEGER NOT NULL,
                    PRIMARY KEY(sensor_id, event_id)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_replay_expiry ON replay_keys(expires_at_epoch)"
            )

    def reserve(self, replay_key: str, *, now: int, ttl: int = REPLAY_TTL_SECONDS) -> bool:
        sensor_id, separator, event_id = replay_key.partition(":")
        if not separator or not sensor_id or not event_id:
            raise ValueError("replay key must contain sensor_id:event_id")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute("DELETE FROM replay_keys WHERE expires_at_epoch <= ?", (now,))
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO replay_keys(sensor_id, event_id, expires_at_epoch)
                    VALUES (?, ?, ?)
                    """,
                    (sensor_id, event_id, now + ttl),
                )
                accepted = cursor.rowcount == 1
                connection.execute("COMMIT")
                return accepted
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def release(self, replay_key: str) -> None:
        sensor_id, separator, event_id = replay_key.partition(":")
        if not separator or not sensor_id or not event_id:
            raise ValueError("replay key must contain sensor_id:event_id")
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM replay_keys WHERE sensor_id = ? AND event_id = ?",
                (sensor_id, event_id),
            )


class SQLiteObservationStore:
    """Privacy-reduced SQLite index for deduplicated analysis and local exports."""

    def __init__(
        self,
        path: Path,
        *,
        fingerprint_secret: str,
        privacy_salt: str,
        dedup_window_seconds: int = DEDUP_WINDOW_SECONDS,
    ) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fingerprint_secret = _require_secret(
            fingerprint_secret, "fingerprint secret"
        )
        _require_secret(privacy_salt, "privacy salt")
        self._privacy_salt = privacy_salt
        self.dedup_window_seconds = max(60, min(dedup_window_seconds, 24 * 60 * 60))
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    first_seen_epoch INTEGER NOT NULL,
                    last_seen_epoch INTEGER NOT NULL,
                    repeat_count INTEGER NOT NULL DEFAULT 1 CHECK(repeat_count >= 1),
                    severity TEXT NOT NULL,
                    is_demo INTEGER NOT NULL CHECK(is_demo IN (0, 1)),
                    decoded_json TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    threat_score INTEGER NOT NULL DEFAULT 0 CHECK(threat_score BETWEEN 0 AND 100),
                    threat_priority TEXT NOT NULL DEFAULT 'informational',
                    threat_factors_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_observation_fingerprint_time
                    ON observations(fingerprint, last_seen_epoch DESC);
                CREATE INDEX IF NOT EXISTS idx_observation_window
                    ON observations(last_seen_epoch, protocol);
                CREATE INDEX IF NOT EXISTS idx_observation_source
                    ON observations(source_id, last_seen_epoch DESC);
                CREATE TABLE IF NOT EXISTS observation_techniques (
                    observation_id INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
                    technique_id TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    PRIMARY KEY(observation_id, technique_id, confidence)
                );
                CREATE TABLE IF NOT EXISTS imported_events (
                    event_id TEXT PRIMARY KEY,
                    input_digest TEXT NOT NULL,
                    event_digest TEXT NOT NULL,
                    imported_at_epoch INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    analysis_run_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    versions_json TEXT NOT NULL,
                    started_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS analysis_results (
                    analysis_id TEXT PRIMARY KEY,
                    analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(analysis_run_id),
                    event_id TEXT NOT NULL,
                    input_digest TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_analysis_results_event
                    ON analysis_results(event_id, created_at DESC);
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(observations)")}
            migrations = {
                "threat_score": "ALTER TABLE observations ADD COLUMN threat_score INTEGER NOT NULL DEFAULT 0",
                "threat_priority": "ALTER TABLE observations ADD COLUMN threat_priority TEXT NOT NULL DEFAULT 'informational'",
                "threat_factors_json": "ALTER TABLE observations ADD COLUMN threat_factors_json TEXT NOT NULL DEFAULT '[]'",
            }
            for name, statement in migrations.items():
                if name not in columns:
                    connection.execute(statement)

    @staticmethod
    def _insert_observation(
        connection: sqlite3.Connection,
        event: Mapping[str, Any],
        *,
        fingerprint: str,
        source_id: str,
        observed_epoch: int,
        cutoff: int,
        assessment: TriageAssessment,
    ) -> int:
        existing = connection.execute(
            """
            SELECT id FROM observations
            WHERE fingerprint = ? AND last_seen_epoch BETWEEN ? AND ?
            ORDER BY last_seen_epoch DESC LIMIT 1
            """,
            (fingerprint, cutoff, observed_epoch),
        ).fetchone()
        if existing is not None:
            observation_id = int(existing["id"])
            connection.execute(
                """
                UPDATE observations
                SET last_seen_epoch = ?, repeat_count = repeat_count + 1,
                    threat_score = ?, threat_priority = ?, threat_factors_json = ?
                WHERE id = ?
                """,
                (
                    observed_epoch,
                    assessment.score,
                    assessment.priority,
                    json.dumps(assessment.to_dict()["factors"], separators=(",", ":")),
                    observation_id,
                ),
            )
            return observation_id
        cursor = connection.execute(
            """
            INSERT INTO observations(
                fingerprint, source_id, protocol, event_type, session_id,
                first_seen_epoch, last_seen_epoch, repeat_count, severity,
                is_demo, decoded_json, tags_json, threat_score, threat_priority, threat_factors_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint,
                source_id,
                str(event.get("protocol", "unknown")),
                str(event.get("event_type", "unknown")),
                str(event.get("session_id", "")),
                observed_epoch,
                observed_epoch,
                str(event.get("severity", "info")),
                1 if event.get("is_demo") is True else 0,
                json.dumps(event.get("decoded", {}), separators=(",", ":")),
                json.dumps(event.get("tags", []), separators=(",", ":")),
                assessment.score,
                assessment.priority,
                json.dumps(assessment.to_dict()["factors"], separators=(",", ":")),
            ),
        )
        observation_id = int(cursor.lastrowid)
        for technique in event.get("techniques", []):
            if not isinstance(technique, Mapping):
                continue
            technique_id = str(technique.get("technique_id", "")).strip()
            confidence = str(technique.get("confidence", "low")).lower()
            if technique_id:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO observation_techniques(
                        observation_id, technique_id, confidence
                    ) VALUES (?, ?, ?)
                    """,
                    (observation_id, technique_id, confidence),
                )
        return observation_id

    def record(self, event: Mapping[str, Any], *, payload: bytes, now: int | None = None) -> int:
        """Store an event and return its private observation identifier for compatibility."""
        return self.record_with_assessment(event, payload=payload, now=now).observation_id

    def record_with_assessment(
        self, event: Mapping[str, Any], *, payload: bytes, now: int | None = None
    ) -> StoredObservation:
        source_ip = str(event.get("source_ip", "")).strip()
        protocol = str(event.get("protocol", "")).strip()
        if not source_ip or not protocol:
            raise ValueError("observation requires source_ip and protocol")
        if len(payload) > 512:
            raise ValueError("observation payload exceeds 512 bytes")
        observed_epoch = now if now is not None else _epoch(str(event.get("observed_at", "")))
        fingerprint = observation_fingerprint(
            self._fingerprint_secret, source_ip, protocol, payload
        )
        source_id = pseudonymize_ip(source_ip, self._privacy_salt)
        cutoff = observed_epoch - self.dedup_window_seconds

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                repeat_source_count = int(
                    connection.execute(
                        "SELECT COALESCE(SUM(repeat_count), 0) FROM observations WHERE source_id = ?",
                        (source_id,),
                    ).fetchone()[0]
                ) + 1
                novel_payload = (
                    connection.execute(
                        "SELECT 1 FROM observations WHERE fingerprint = ? LIMIT 1", (fingerprint,)
                    ).fetchone()
                    is None
                )
                assessment = assess_event(
                    event, repeat_count=repeat_source_count, is_novel_payload=novel_payload
                )
                observation_id = self._insert_observation(
                    connection,
                    event,
                    fingerprint=fingerprint,
                    source_id=source_id,
                    observed_epoch=observed_epoch,
                    cutoff=cutoff,
                    assessment=assessment,
                )
                connection.execute("COMMIT")
                return StoredObservation(
                    observation_id, assessment, repeat_source_count, novel_payload
                )
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def import_sanitized(
        self, records: list[Mapping[str, Any]], *, input_digest: str
    ) -> tuple[int, int]:
        """Atomically import validated sanitized records with restart-safe idempotence."""
        imported = 0
        skipped = 0
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for event in records:
                    if event.get("sanitized") is not True or "source_ip" in event:
                        raise ValueError("historical import requires sanitized records")
                    event_id = str(event.get("event_id", "")).strip()
                    source_id = str(event.get("source_id", "")).strip()
                    protocol = str(event.get("protocol", "")).strip()
                    if not event_id or not source_id or not protocol:
                        raise ValueError("historical import record is missing required identity")
                    event_digest = hashlib.sha256(
                        json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                    cursor = connection.execute(
                        """
                        INSERT OR IGNORE INTO imported_events(
                            event_id, input_digest, event_digest, imported_at_epoch
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (event_id, input_digest, event_digest, int(time.time())),
                    )
                    if cursor.rowcount != 1:
                        existing = connection.execute(
                            "SELECT event_digest FROM imported_events WHERE event_id = ?",
                            (event_id,),
                        ).fetchone()
                        if existing is None or existing["event_digest"] != event_digest:
                            raise ValueError(
                                "event ID conflicts with an existing historical import"
                            )
                        skipped += 1
                        continue
                    observed_epoch = _epoch(str(event.get("observed_at", "")))
                    fingerprint = sanitized_observation_fingerprint(
                        self._fingerprint_secret,
                        source_id,
                        protocol,
                        str(event.get("event_type", "unknown")),
                        event.get("decoded", {}),
                    )
                    repeat_source_count = int(
                        connection.execute(
                            "SELECT COALESCE(SUM(repeat_count), 0) FROM observations WHERE source_id = ?",
                            (source_id,),
                        ).fetchone()[0]
                    ) + 1
                    novel_payload = (
                        connection.execute(
                            "SELECT 1 FROM observations WHERE fingerprint = ? LIMIT 1", (fingerprint,)
                        ).fetchone()
                        is None
                    )
                    assessment = assess_event(
                        event,
                        repeat_count=repeat_source_count,
                        is_novel_payload=novel_payload,
                    )
                    self._insert_observation(
                        connection,
                        event,
                        fingerprint=fingerprint,
                        source_id=source_id,
                        observed_epoch=observed_epoch,
                        cutoff=observed_epoch - self.dedup_window_seconds,
                        assessment=assessment,
                    )
                    imported += 1
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        return imported, skipped

    def record_analysis(self, result: Mapping[str, Any]) -> None:
        """Persist a versioned interpretation separately from immutable observations."""
        validate_analysis(result)
        versions = json.dumps(result["versions"], sort_keys=True, separators=(",", ":"))
        serialized = json.dumps(dict(result), sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO analysis_runs(
                        analysis_run_id, schema_version, versions_json, started_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        result["analysis_run_id"],
                        result["schema_version"],
                        versions,
                        result["executed_at"],
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO analysis_results(
                        analysis_id, analysis_run_id, event_id, input_digest, result_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result["analysis_id"],
                        result["analysis_run_id"],
                        result["event_id"],
                        result["input_digest"],
                        serialized,
                        result["executed_at"],
                    ),
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def analysis_results(self) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return list(connection.execute("SELECT * FROM analysis_results ORDER BY created_at, analysis_id"))

    def observations(self) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return list(connection.execute("SELECT * FROM observations ORDER BY id"))
