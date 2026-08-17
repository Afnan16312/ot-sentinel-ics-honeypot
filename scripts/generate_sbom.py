from __future__ import annotations

import argparse
import json
import re
import tomllib
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def dependency_names() -> list[str]:
    names: set[str] = set()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    groups = [project.get("dependencies", [])]
    groups.extend(project.get("optional-dependencies", {}).values())
    for requirements in groups:
        for requirement in requirements:
            match = re.match(r"[A-Za-z0-9_.-]+", requirement)
            if match:
                names.add(match.group(0))
    return sorted(names, key=str.lower)


def installed_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not-installed"


def spdx_id(name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def build_sbom() -> dict:
    packages = [
        {
            "SPDXID": "SPDXRef-Package-OT-Sentinel",
            "name": "ot-sentinel",
            "versionInfo": "0.2.0",
            "downloadLocation": "https://github.com/Afnan16312/ot-sentinel-ics-honeypot",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
        }
    ]
    relationships: list[dict] = []
    for name in dependency_names():
        identifier = spdx_id(name)
        packages.append(
            {
                "SPDXID": identifier,
                "name": name,
                "versionInfo": installed_version(name),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-OT-Sentinel",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": identifier,
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "ot-sentinel-0.2.0-sbom",
        "documentNamespace": f"https://github.com/Afnan16312/ot-sentinel-ics-honeypot/sbom/{uuid4()}",
        "creationInfo": {
            "created": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "creators": ["Tool: OT-Sentinel-SBOM-Generator/1.0"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an SPDX 2.3 JSON SBOM")
    parser.add_argument("--output", default="artifacts/sbom.spdx.json")
    args = parser.parse_args()
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_sbom(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote SPDX SBOM: {output}")


if __name__ == "__main__":
    main()

