from __future__ import annotations

import json
from pathlib import Path

from ot_sentinel.storage import SQLiteObservationStore

ROOT = Path(__file__).resolve().parents[1]


def build_demo_database(path: Path) -> None:
    if path.exists():
        path.unlink()
    store = SQLiteObservationStore(
        path,
        fingerprint_secret="synthetic-fingerprint-secret-32-characters",
        privacy_salt="synthetic-private-salt-at-least-32-chars",
    )
    source_addresses: dict[str, str] = {}
    with (ROOT / "data" / "demo_events.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            event = json.loads(line)
            source_id = str(event["source_id"])
            if source_id not in source_addresses:
                source_addresses[source_id] = f"192.0.2.{len(source_addresses) + 1}"
            event["source_ip"] = source_addresses[source_id]
            # The public fixture has no payload. A unique bounded synthetic token preserves counts.
            payload = f"synthetic:{event['event_id']}".encode()
            store.record(event, payload=payload)


if __name__ == "__main__":
    build_demo_database(ROOT / "tmp" / "phase2-demo.sqlite3")
    print("Created synthetic Phase 2 database under tmp/")
