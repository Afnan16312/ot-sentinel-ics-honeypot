from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path

FORBIDDEN_FIELDS = {
    "source_ip",
    "raw_payload_hex",
    "password",
    "credential",
    "token",
    "username",
}


def walk(value, path: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            current = f"{path}.{key}" if path else key
            yield current, key, child
            yield from walk(child, current)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def validate(path: Path) -> tuple[int, list[str]]:
    errors: list[str] = []
    count = 0
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            count += 1
            record = json.loads(line)
            if not record.get("sanitized"):
                errors.append(f"line {line_number}: sanitized flag is not true")
            for field_path, key, value in walk(record):
                if key.lower() in FORBIDDEN_FIELDS:
                    errors.append(f"line {line_number}: forbidden field {field_path}")
                if isinstance(value, str) and key.lower().endswith("ip"):
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        pass
                    else:
                        errors.append(f"line {line_number}: literal IP found in {field_path}")
    if count == 0:
        errors.append("dataset is empty")
    return count, errors


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

