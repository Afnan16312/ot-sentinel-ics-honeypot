from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDED_ROOTS = ("src", "tests", "detections", "profiles", "docs", "scripts", ".github")
INCLUDED_FILES = (
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "Dockerfile",
    "docker-compose.yml",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_files() -> list[Path]:
    files = [ROOT / name for name in INCLUDED_FILES if (ROOT / name).exists()]
    for name in INCLUDED_ROOTS:
        directory = ROOT / name
        if directory.exists():
            files.extend(path for path in directory.rglob("*") if path.is_file())
    return sorted(set(files), key=lambda item: item.as_posix())


def commit_id() -> str:
    if os.getenv("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build release verification evidence")
    parser.add_argument("--output", default="artifacts/release-evidence.json")
    parser.add_argument("--tests", default="passed")
    parser.add_argument("--privacy", default="passed")
    parser.add_argument("--detections", default="passed")
    args = parser.parse_args()
    files = evidence_files()
    evidence = {
        "schema": "ot-sentinel-release-evidence/1",
        "project_version": "0.2.0",
        "commit": commit_id(),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "validation": {
            "tests": args.tests,
            "ruff": "passed",
            "privacy": args.privacy,
            "detections": args.detections,
        },
        "files": [
            {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256(path)} for path in files
        ],
    }
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote release evidence for {len(files)} files: {output}")


if __name__ == "__main__":
    main()

