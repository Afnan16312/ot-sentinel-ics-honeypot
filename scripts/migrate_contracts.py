from __future__ import annotations

import argparse
import json
from pathlib import Path

from ot_sentinel.contract_migrations import migrate_record


def _write_jsonl(path: Path, records: list[dict]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        "\n".join(json.dumps(item, sort_keys=True) for item in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    temporary.replace(path)


def migrate(
    input_path: Path,
    observations_output: Path | None,
    analyses_output: Path | None,
    *,
    dry_run: bool,
) -> dict[str, int]:
    observations: list[dict] = []
    analyses: list[dict] = []
    for line in input_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            observation, analysis = migrate_record(json.loads(line))
            if observation:
                observations.append(observation)
            if analysis:
                analyses.append(analysis)
    result = {"observations": len(observations), "analyses": len(analyses)}
    if dry_run:
        return result
    if observations_output is None or analyses_output is None:
        raise ValueError("both outputs are required unless --dry-run is used")
    for output_path, records in ((observations_output, observations), (analyses_output, analyses)):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        _write_jsonl(output_path, records)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Adapt mixed OT Sentinel JSONL into separate v1 observation and analysis JSONL files"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("observations_output", type=Path, nargs="?")
    parser.add_argument("analyses_output", type=Path, nargs="?")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            migrate(
                args.input,
                args.observations_output,
                args.analyses_output,
                dry_run=args.dry_run,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
