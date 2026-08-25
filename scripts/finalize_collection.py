from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ot_sentinel.finalize import finalize_collection


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare a private post-collection analysis handoff without publishing"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--workspace",
        type=Path,
        default=ROOT / "data" / "private" / "handoff",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--approve-public-candidates", action="store_true")
    args = parser.parse_args()
    try:
        result = finalize_collection(
            args.input,
            args.workspace,
            repository_root=ROOT,
            fingerprint_secret=os.getenv("OT_FINGERPRINT_SECRET", ""),
            privacy_salt=os.getenv("OT_PRIVACY_SALT", ""),
            dry_run=args.dry_run,
            approve_public_candidates=args.approve_public_candidates,
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Final processing stopped safely: {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
