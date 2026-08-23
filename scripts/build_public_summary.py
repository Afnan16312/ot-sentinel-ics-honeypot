from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from scripts.validate_public_data import validate
except ModuleNotFoundError:  # Direct execution adds scripts/, not the repository root, to sys.path.
    from validate_public_data import validate


def _sorted_counts(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def build_summary(path: Path) -> dict[str, Any]:
    """Build aggregate-only statistics from an already sanitized JSONL file."""
    _, errors = validate(path)
    if errors:
        raise ValueError("Input failed public-data validation: " + "; ".join(errors[:10]))

    with path.open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]

    demo_flags = {record.get("is_demo") is True for record in records}
    if len(demo_flags) != 1:
        raise ValueError("Synthetic and observed records must not be mixed in one summary")

    observed_dates = sorted(
        str(record.get("observed_at", ""))[:10]
        for record in records
        if record.get("observed_at")
    )
    technique_ids = [
        str(technique.get("technique_id", "unknown"))
        for record in records
        for technique in record.get("techniques", [])
        if isinstance(technique, dict)
    ]

    is_demo = next(iter(demo_flags))
    return {
        "schema_version": "ot-sentinel-public-summary-1.0",
        "data_classification": "synthetic_demo" if is_demo else "sanitized_observations",
        "data_notice": (
            "Synthetic demonstration statistics; not observed attacker activity."
            if is_demo
            else "Aggregate statistics from a separately reviewed sanitized dataset."
        ),
        "observation_window": {
            "first_date": observed_dates[0] if observed_dates else None,
            "last_date": observed_dates[-1] if observed_dates else None,
        },
        "totals": {
            "events": len(records),
            "sessions": len(
                {record["session_id"] for record in records if record.get("session_id")}
            ),
            "pseudonymous_sources": len(
                {record["source_id"] for record in records if record.get("source_id")}
            ),
        },
        "protocols": _sorted_counts(
            [str(record.get("protocol", "unknown")) for record in records]
        ),
        "event_types": _sorted_counts(
            [str(record.get("event_type", "unknown")) for record in records]
        ),
        "severities": _sorted_counts(
            [str(record.get("severity", "unknown")) for record in records]
        ),
        "techniques": _sorted_counts(technique_ids),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create aggregate-only statistics from a sanitized OT Sentinel JSONL file"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    summary = build_summary(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"Created aggregate public summary: {args.output}")


if __name__ == "__main__":
    main()
