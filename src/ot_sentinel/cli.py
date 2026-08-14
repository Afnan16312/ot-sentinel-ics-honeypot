from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .normalizer import normalize_conpot
from .privacy import sanitize_event
from .sensor import main as sensor_main


def _normalize(args: argparse.Namespace) -> None:
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with Path(args.input).open(encoding="utf-8") as source, destination.open(
        "w", encoding="utf-8"
    ) as target:
        for line in source:
            if line.strip():
                event = normalize_conpot(json.loads(line), args.sensor_id)
                target.write(json.dumps(event.to_dict()) + "\n")


def _sanitize(args: argparse.Namespace) -> None:
    salt = os.getenv("OT_PRIVACY_SALT")
    if not salt:
        raise SystemExit("Set OT_PRIVACY_SALT to a private random value before sanitizing.")
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with Path(args.input).open(encoding="utf-8") as source, destination.open(
        "w", encoding="utf-8"
    ) as target:
        for line in source:
            if line.strip():
                target.write(json.dumps(sanitize_event(json.loads(line), salt)) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(prog="ot-sentinel")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("sensor", help="Run the low-interaction sensor")
    normalize = subparsers.add_parser("normalize", help="Normalize Conpot JSONL")
    normalize.add_argument("input")
    normalize.add_argument("output")
    normalize.add_argument("--sensor-id", default="conpot-01")
    sanitize = subparsers.add_parser("sanitize", help="Remove publication-sensitive fields")
    sanitize.add_argument("input")
    sanitize.add_argument("output")
    args, remaining = parser.parse_known_args()
    if args.command == "sensor":
        import sys

        sys.argv = [sys.argv[0], *remaining]
        sensor_main()
    elif args.command == "normalize":
        _normalize(args)
    else:
        _sanitize(args)


if __name__ == "__main__":
    main()
