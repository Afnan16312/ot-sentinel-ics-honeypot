from __future__ import annotations

import argparse
import json
from pathlib import Path

from ot_sentinel.wazuh_ingest import stage_wazuh_dataset

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stage approved sanitized OT Sentinel events for local Wazuh"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--staging-directory",
        type=Path,
        default=ROOT / "tests" / "soc" / "staging",
    )
    parser.add_argument("--approve-local-ingestion", action="store_true")
    args = parser.parse_args()
    try:
        result = stage_wazuh_dataset(
            args.input,
            args.staging_directory,
            repository_root=ROOT,
            approved=args.approve_local_ingestion,
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Wazuh staging failed safely: {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
