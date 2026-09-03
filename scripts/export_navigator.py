from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from ot_sentinel.mapper import CATALOG

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.3.2"
ATTACK_VERSION = "18"
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
FORBIDDEN_KEYS = {"source_id", "session_id", "source_ip", "raw_payload_hex", "payload"}


def _contains_ip_literal(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_ip_literal(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_ip_literal(item) for item in value)
    if not isinstance(value, str):
        return False
    for token in re.split(r"[^0-9A-Fa-f:.]+", value):
        if not token:
            continue
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        return True
    return False


def validate_layer(layer: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if layer.get("name") is None:
        errors.append("name is required")
    if layer.get("domain") != "ics-attack":
        errors.append("domain must be ics-attack")
    versions = layer.get("versions", {})
    if versions.get("layer") != LAYER_VERSION:
        errors.append("versions.layer must be 4.5")
    try:
        navigator_parts = tuple(int(item) for item in versions.get("navigator", "0").split("."))
    except ValueError:
        navigator_parts = (0,)
    if navigator_parts < (4, 9, 0):
        errors.append("versions.navigator must be at least 4.9.0")
    techniques = layer.get("techniques")
    if not isinstance(techniques, list):
        errors.append("techniques must be a list")
        techniques = []
    for index, technique in enumerate(techniques):
        technique_id = str(technique.get("techniqueID", ""))
        if not TECHNIQUE_PATTERN.fullmatch(technique_id) or technique_id not in CATALOG:
            errors.append(f"techniques[{index}] has an unsupported techniqueID")
        score = technique.get("score")
        if not isinstance(score, int) or score < 0:
            errors.append(f"techniques[{index}].score must be a non-negative integer")
        if not isinstance(technique.get("comment"), str):
            errors.append(f"techniques[{index}].comment must be a string")
    serialized = json.dumps(layer, sort_keys=True)
    if any(f'"{key}"' in serialized for key in FORBIDDEN_KEYS):
        errors.append("layer contains a forbidden identifier or payload key")
    if _contains_ip_literal(layer):
        errors.append("layer contains an IP address literal")
    return errors


def build_layer(database: Path) -> dict[str, Any]:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT t.technique_id, t.confidence, SUM(o.repeat_count) AS observations
            FROM observation_techniques AS t
            JOIN observations AS o ON o.id = t.observation_id
            GROUP BY t.technique_id, t.confidence
            ORDER BY t.technique_id, t.confidence
            """
        ).fetchall()

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        technique_id = str(row["technique_id"])
        if not TECHNIQUE_PATTERN.fullmatch(technique_id) or technique_id not in CATALOG:
            raise ValueError(f"unsupported ATT&CK for ICS technique: {technique_id!r}")
        item = grouped.setdefault(technique_id, {"score": 0, "confidence": {}})
        count = int(row["observations"])
        item["score"] += count
        item["confidence"][str(row["confidence"])] = count

    techniques = []
    for technique_id in sorted(grouped):
        item = grouped[technique_id]
        confidence = ", ".join(
            f"{name}={count}" for name, count in sorted(item["confidence"].items())
        )
        techniques.append(
            {
                "techniqueID": technique_id,
                "score": item["score"],
                "comment": f"{item['score']} observations; confidence: {confidence}",
                "enabled": True,
            }
        )
    maximum = max((item["score"] for item in techniques), default=1)
    layer = {
        "name": "OT Sentinel — ATT&CK for ICS observation frequency",
        "description": (
            "Evidence-qualified OT Sentinel technique hypotheses. Scores are observation "
            "frequencies, not proof of compromise or attacker intent."
        ),
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "ics-attack",
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "aggregateFunction": "sum",
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#e8f1f7", "#6f9fc4", "#1c4966"],
            "minValue": 0,
            "maxValue": maximum,
        },
        "legendItems": [
            {"label": "Higher score = more observations", "color": "#1c4966"}
        ],
        "metadata": [
            {"name": "data handling", "value": "aggregate counts only"},
            {"name": "mapping", "value": "evidence-qualified hypotheses"},
        ],
    }
    errors = validate_layer(layer)
    if errors:
        raise ValueError("Navigator validation failed: " + "; ".join(errors))
    return layer


def main() -> None:
    parser = argparse.ArgumentParser(description="Export an ATT&CK Navigator ICS layer")
    parser.add_argument("database", type=Path)
    parser.add_argument(
        "output",
        type=Path,
        nargs="?",
        default=Path("exports/private/ot-sentinel-layer.json"),
    )
    args = parser.parse_args()
    layer = build_layer(args.database)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    print(f"Created ATT&CK Navigator layer: {args.output}")


if __name__ == "__main__":
    main()
