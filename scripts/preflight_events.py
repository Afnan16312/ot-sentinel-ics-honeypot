from __future__ import annotations

import argparse
import json
from pathlib import Path

from ot_sentinel.handoff import inspect_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Privacy-safe integrity preflight for OT Sentinel historical JSONL"
    )
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    report, _ = inspect_jsonl(args.input)
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    if not report.valid:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
