from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .collector import main as collector_main
from .evaluation import evaluate_mapper, load_labeled_jsonl
from .normalizer import normalize_conpot
from .privacy import sanitize_event
from .profiles import load_profile
from .sensor import main as sensor_main
from .stix_export import export_events, load_jsonl


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


def _export_stix(args: argparse.Namespace) -> None:
    salt = os.getenv(args.salt_env) if args.profile == "public" else None
    try:
        bundle = export_events(load_jsonl(args.input), profile=args.profile, salt=salt)
    except (AssertionError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")


def _evaluate_mapper(args: argparse.Namespace) -> None:
    result = evaluate_mapper(load_labeled_jsonl(args.fixtures))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))


def _validate_profile(args: argparse.Namespace) -> None:
    profile = load_profile(args.profile)
    print(
        json.dumps(
            {
                "valid": True,
                "profile_id": profile.profile_id,
                "sector": profile.sector,
                "registers": len(profile.holding_registers),
                "writable_ranges": len(profile.writable_ranges),
            },
            indent=2,
            sort_keys=True,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="ot-sentinel")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("sensor", help="Run the low-interaction sensor")
    subparsers.add_parser("collector", help="Run the authenticated central collector")
    normalize = subparsers.add_parser("normalize", help="Normalize Conpot JSONL")
    normalize.add_argument("input")
    normalize.add_argument("output")
    normalize.add_argument("--sensor-id", default="conpot-01")
    sanitize = subparsers.add_parser("sanitize", help="Remove publication-sensitive fields")
    sanitize.add_argument("input")
    sanitize.add_argument("output")
    export_stix = subparsers.add_parser("export-stix", help="Export JSONL events as STIX 2.1")
    export_stix.add_argument("input")
    export_stix.add_argument("output")
    export_stix.add_argument("--profile", choices=("public", "private"), default="public")
    export_stix.add_argument(
        "--salt-env",
        default="OT_PRIVACY_SALT",
        help="Environment variable holding the public-profile pseudonymization salt",
    )
    evaluate = subparsers.add_parser(
        "evaluate-mapper", help="Evaluate ATT&CK mappings against labeled fixtures"
    )
    evaluate.add_argument(
        "--fixtures",
        default="tests/fixtures/evaluation/mapper_cases.jsonl",
    )
    profile = subparsers.add_parser("validate-profile", help="Validate a safe OT profile")
    profile.add_argument("profile")
    args, remaining = parser.parse_known_args()
    if args.command == "sensor":
        import sys

        sys.argv = [sys.argv[0], *remaining]
        sensor_main()
    elif args.command == "collector":
        import sys

        sys.argv = [sys.argv[0], *remaining]
        collector_main()
    elif args.command == "normalize":
        _normalize(args)
    elif args.command == "sanitize":
        _sanitize(args)
    elif args.command == "export-stix":
        _export_stix(args)
    elif args.command == "evaluate-mapper":
        _evaluate_mapper(args)
    else:
        _validate_profile(args)


if __name__ == "__main__":
    main()
