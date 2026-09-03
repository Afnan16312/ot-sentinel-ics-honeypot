from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from scripts.validate_detections import (
    load_sigma_rules,
    load_suricata_rules,
    load_wazuh_rules,
    sigma_matches,
    suricata_matches,
    wazuh_matches,
)


@dataclass(frozen=True)
class DetectionPrediction:
    engine: str
    rule_id: str
    title: str
    severity: str
    technique: str
    protocol: str
    evidence_reason: str
    event_id: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class NativeValidationEvidence:
    """Privacy-safe summary of the last recorded native synthetic validation."""

    status: str
    validated_on: str
    wazuh_version: str
    suricata_version: str


@dataclass(frozen=True)
class DetectionCoverageRow:
    """One observed behavior's safe, actionable detection-engineering status."""

    protocol: str
    operation: str
    observed_events: int
    mapped_techniques: str
    rule_engines: str
    fixture_coverage: str
    status: str
    next_action: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


@lru_cache(maxsize=4)
def load_native_validation_evidence(path_text: str) -> NativeValidationEvidence | None:
    """Read the committed validation record without implying current engine health."""

    path = Path(path_text)
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    status = re.search(r"Status:\s+\*\*(.+?)\*\*", text)
    date = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", status.group(1) if status else "")
    wazuh = re.search(r"Wazuh manager, indexer and dashboard images pinned to `([^`]+)`", text)
    suricata = re.search(r"Suricata image pinned to `([^`]+)`", text)
    if not (status and date and wazuh and suricata):
        return None
    return NativeValidationEvidence(
        status="passed synthetic fixtures" if "passed" in status.group(1).lower() else "recorded",
        validated_on=date.group(1),
        wazuh_version=wazuh.group(1),
        suricata_version=suricata.group(1),
    )


def _wazuh_severity(level: int) -> str:
    if level >= 12:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def _preview_event(event: Mapping[str, Any]) -> dict[str, Any]:
    decoded = event.get("decoded")
    decoded = dict(decoded) if isinstance(decoded, Mapping) else {}
    preview = {
        "sensor_id": str(event.get("sensor_id", "sanitized-sensor")),
        "event_type": str(event.get("event_type", "")),
        "protocol": str(event.get("protocol", "")),
        "decoded": decoded,
    }
    if preview["protocol"] == "modbus":
        operation = str(decoded.get("operation", ""))
        function = int(decoded.get("function_code", 0) or 0)
        preview["modbus"] = {
            "unit": int(decoded.get("unit_id", 1) or 1),
            "function": function,
            "function_class": "unassigned" if function > 64 else "assigned",
            "access": "write" if operation.startswith("write_") else "read",
        }
    return preview


def _evidence_reason(event: Mapping[str, Any]) -> str:
    decoded = event.get("decoded")
    operation = decoded.get("operation", "unknown") if isinstance(decoded, Mapping) else "unknown"
    return (
        f"Offline rule conditions matched event_type={event.get('event_type', 'unknown')}, "
        f"protocol={event.get('protocol', 'unknown')}, operation={operation}."
    )


@lru_cache(maxsize=4)
def _load_rules(root_text: str):
    root = Path(root_text)
    detections = root / "detections"
    sigma, errors = load_sigma_rules(detections / "sigma")
    wazuh, more = load_wazuh_rules(detections / "wazuh" / "ot_sentinel_rules.xml")
    errors.extend(more)
    suricata, more = load_suricata_rules(
        detections / "suricata" / "ot_sentinel_modbus.rules"
    )
    errors.extend(more)
    if errors:
        raise ValueError("Detection pack is invalid: " + "; ".join(errors[:5]))
    return sigma, wazuh, suricata


def preview_detections(
    events: Iterable[Mapping[str, Any]], *, root: Path
) -> list[DetectionPrediction]:
    """Predict rule matches offline; this is not authoritative native-engine output."""
    sigma_rules, wazuh_rules, suricata_rules = _load_rules(str(root.resolve()))
    predictions: list[DetectionPrediction] = []
    wazuh_by_id = {rule.rule_id: rule for rule in wazuh_rules}

    for original in events:
        event = _preview_event(original)
        protocol = str(event.get("protocol", "unknown"))
        event_id = str(original.get("event_id", "sanitized-event"))
        reason = _evidence_reason(event)
        for rule in sigma_rules:
            if sigma_matches(rule, event):
                predictions.append(
                    DetectionPrediction(
                        "Sigma",
                        rule.rule_id,
                        rule.title,
                        rule.level,
                        ", ".join(rule.techniques) or "not mapped",
                        protocol,
                        reason,
                        event_id,
                    )
                )
        for rule_id in sorted(wazuh_matches(wazuh_rules, event)):
            rule = wazuh_by_id[rule_id]
            predictions.append(
                DetectionPrediction(
                    "Wazuh",
                    str(rule.rule_id),
                    rule.description,
                    _wazuh_severity(rule.level),
                    ", ".join(rule.techniques) or "not mapped",
                    protocol,
                    reason,
                    event_id,
                )
            )
        for rule in suricata_rules:
            if suricata_matches(rule, event):
                predictions.append(
                    DetectionPrediction(
                        "Suricata",
                        str(rule.sid),
                        rule.title,
                        rule.severity,
                        ", ".join(rule.techniques) or "not mapped",
                        protocol,
                        reason,
                        event_id,
                    )
                )
    return sorted(
        predictions,
        key=lambda item: (item.engine, item.rule_id, item.protocol, item.event_id),
    )


def _fixture_behaviors(root: Path) -> set[tuple[str, str]]:
    """Read only synthetic fixture metadata; fixture payloads are never returned."""

    fixture_path = root / "detections" / "fixtures" / "events.jsonl"
    if not fixture_path.exists():
        return set()
    behaviors: set[tuple[str, str]] = set()
    for line in fixture_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        event = item.get("event")
        decoded = event.get("decoded") if isinstance(event, Mapping) else None
        if isinstance(event, Mapping) and isinstance(decoded, Mapping):
            behaviors.add(
                (str(event.get("protocol", "unknown")), str(decoded.get("operation", "unknown")))
            )
    return behaviors


def detection_coverage_backlog(
    events: Iterable[Mapping[str, Any]], *, root: Path
) -> list[DetectionCoverageRow]:
    """Summarize observed behavior coverage without claiming native engine equivalence."""

    records = [dict(event) for event in events]
    predictions = preview_detections(records, root=root)
    engines_by_event: dict[str, set[str]] = {}
    for prediction in predictions:
        engines_by_event.setdefault(prediction.event_id, set()).add(prediction.engine)
    fixture_behaviors = _fixture_behaviors(root)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in records:
        decoded = event.get("decoded")
        decoded = decoded if isinstance(decoded, Mapping) else {}
        behavior = (str(event.get("protocol", "unknown")), str(decoded.get("operation", "unknown")))
        grouped.setdefault(behavior, []).append(event)

    rows: list[DetectionCoverageRow] = []
    for (protocol, operation), behavior_events in sorted(grouped.items()):
        technique_ids = sorted(
            {
                str(item.get("technique_id"))
                for event in behavior_events
                for item in event.get("techniques", []) or []
                if isinstance(item, Mapping) and item.get("technique_id")
            }
        )
        engines = sorted(
            {
                engine
                for event in behavior_events
                for engine in engines_by_event.get(str(event.get("event_id", "")), set())
            }
        )
        fixture_covered = (protocol, operation) in fixture_behaviors
        if not technique_ids:
            status = "mapping review"
            next_action = "Review decoded evidence before proposing an ATT&CK mapping or detection rule."
        elif not engines:
            status = "rule opportunity"
            next_action = "Review this mapped behavior for a rule and add positive and nearest-negative fixtures."
        elif not fixture_covered:
            status = "fixture follow-up"
            next_action = "Add a controlled positive and nearest-negative fixture before treating this rule path as covered."
        else:
            status = "covered in pack"
            next_action = "Re-run the documented validation after changing this rule, fixture, or engine version."
        rows.append(
            DetectionCoverageRow(
                protocol=protocol,
                operation=operation,
                observed_events=len(behavior_events),
                mapped_techniques=", ".join(technique_ids) or "not mapped",
                rule_engines=", ".join(engines) or "none",
                fixture_coverage="synthetic fixture present" if fixture_covered else "no matching fixture",
                status=status,
                next_action=next_action,
            )
        )
    return rows
