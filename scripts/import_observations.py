from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ot_sentinel.handoff import import_sanitized_jsonl

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import validated sanitized JSONL into the private analysis index"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("database", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    fingerprint_secret = os.getenv("OT_FINGERPRINT_SECRET", "")
    privacy_salt = os.getenv("OT_PRIVACY_SALT", "")
    try:
        result = import_sanitized_jsonl(
            args.input,
            args.database,
            repository_root=ROOT,
            fingerprint_secret=fingerprint_secret,
            privacy_salt=privacy_salt,
            dry_run=args.dry_run,
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Historical import failed safely: {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
