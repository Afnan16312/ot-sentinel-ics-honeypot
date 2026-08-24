from __future__ import annotations

import argparse
from pathlib import Path

from ot_sentinel.publication import PublicationValidationError, load_public_jsonl


def validate(path: Path) -> tuple[int, list[str]]:
    try:
        records = load_public_jsonl(path)
    except PublicationValidationError as exc:
        return 0, list(exc.errors)
    return len(records), []


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail when a public JSONL file contains raw fields")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    count, errors = validate(args.path)
    if errors:
        raise SystemExit("Public-data validation failed:\n- " + "\n- ".join(errors[:50]))
    print(f"Validated {count} sanitized public events: {args.path}")


if __name__ == "__main__":
    main()
