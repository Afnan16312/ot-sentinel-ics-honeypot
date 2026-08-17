from __future__ import annotations

import argparse
import json
import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SIGMA_REQUIRED_KEYS = {
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
}


@dataclass(frozen=True)
class SigmaRule:
    name: str
    rule_id: str
    selection: dict[str, Any]


@dataclass(frozen=True)
class WazuhRule:
    rule_id: int
    level: int
    parent_id: int | None
    fields: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class SuricataRule:
    sid: int
    expression: str


def _scalar(value: str) -> Any:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def _top_level_keys(text: str) -> set[str]:
    return {
        match.group(1)
        for line in text.splitlines()
        if (match := re.match(r"^([A-Za-z][A-Za-z0-9_-]*):(?:\s|$)", line))
    }


def load_sigma_rules(directory: Path) -> tuple[list[SigmaRule], list[str]]:
    rules: list[SigmaRule] = []
    errors: list[str] = []
    seen_ids: set[str] = set()

    for path in sorted(directory.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        missing = SIGMA_REQUIRED_KEYS - _top_level_keys(text)
        if missing:
            errors.append(f"{path}: missing Sigma keys {sorted(missing)}")

        id_match = re.search(r"^id:\s*(\S+)\s*$", text, re.MULTILINE)
        if not id_match:
            errors.append(f"{path}: missing rule UUID")
            continue
        rule_id = id_match.group(1)
        try:
            uuid.UUID(rule_id)
        except ValueError:
            errors.append(f"{path}: invalid rule UUID {rule_id!r}")
        if rule_id in seen_ids:
            errors.append(f"{path}: duplicate Sigma UUID {rule_id}")
        seen_ids.add(rule_id)

        if "product: ot_sentinel" not in text or "service: sensor" not in text:
            errors.append(f"{path}: logsource must identify the OT Sentinel sensor")

        selection: dict[str, Any] = {}
        in_detection = False
        in_selection = False
        active_field: str | None = None
        condition = ""
        for line in text.splitlines():
            if line == "detection:":
                in_detection = True
                continue
            if in_detection and line and not line.startswith(" "):
                break
            if not in_detection or not line.strip() or line.lstrip().startswith("#"):
                continue
            selection_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if selection_match:
                in_selection = selection_match.group(1) == "selection"
                active_field = None
                continue
            condition_match = re.match(r"^  condition:\s*(.+?)\s*$", line)
            if condition_match:
                condition = condition_match.group(1)
                in_selection = False
                continue
            if not in_selection:
                continue
            field_match = re.match(r"^    ([A-Za-z0-9_.|]+):(?:\s*(.*))?$", line)
            if field_match:
                active_field = field_match.group(1)
                raw_value = (field_match.group(2) or "").strip()
                selection[active_field] = _scalar(raw_value) if raw_value else []
                continue
            item_match = re.match(r"^      -\s+(.+?)\s*$", line)
            if item_match and active_field:
                selection[active_field].append(_scalar(item_match.group(1)))

        if condition != "selection":
            errors.append(f"{path}: offline validator supports condition: selection")
        if not selection:
            errors.append(f"{path}: detection selection is empty")
        rules.append(SigmaRule(path.stem, rule_id, selection))

    if not rules:
        errors.append(f"{directory}: no Sigma rules found")
    return rules, errors


def _field_value(event: dict[str, Any], dotted_path: str) -> tuple[bool, Any]:
    current: Any = event
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def sigma_matches(rule: SigmaRule, event: dict[str, Any]) -> bool:
    for raw_field, expected in rule.selection.items():
        field, separator, modifier = raw_field.partition("|")
        exists, actual = _field_value(event, field)
        if separator:
            if modifier != "exists" or exists is not bool(expected):
                return False
        elif not exists:
            return False
        elif isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def load_wazuh_rules(path: Path) -> tuple[list[WazuhRule], list[str]]:
    errors: list[str] = []
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        return [], [f"{path}: invalid XML: {exc}"]

    rules: list[WazuhRule] = []
    ids: set[int] = set()
    for element in root.findall("rule"):
        try:
            rule_id = int(element.attrib["id"])
            level = int(element.attrib["level"])
        except (KeyError, ValueError):
            errors.append(f"{path}: every Wazuh rule needs numeric id and level attributes")
            continue
        if not 100000 <= rule_id <= 120000:
            errors.append(f"{path}: Wazuh custom rule id {rule_id} is outside 100000-120000")
        if rule_id in ids:
            errors.append(f"{path}: duplicate Wazuh rule id {rule_id}")
        ids.add(rule_id)
        parent_text = element.findtext("if_sid")
        parent_id = int(parent_text) if parent_text else None
        fields: list[tuple[str, str]] = []
        for field in element.findall("field"):
            name = field.attrib.get("name", "")
            pattern = field.text or ""
            if not name or not pattern:
                errors.append(f"{path}: Wazuh rule {rule_id} has an incomplete field")
            fields.append((name, pattern))
        if element.find("description") is None:
            errors.append(f"{path}: Wazuh rule {rule_id} needs a description")
        rules.append(WazuhRule(rule_id, level, parent_id, tuple(fields)))

    for rule in rules:
        if rule.parent_id is not None and rule.parent_id not in ids:
            errors.append(f"{path}: Wazuh rule {rule.rule_id} has unknown parent {rule.parent_id}")
    return rules, errors


def wazuh_matches(rules: list[WazuhRule], event: dict[str, Any]) -> set[int]:
    by_id = {rule.rule_id: rule for rule in rules}
    memo: dict[int, bool] = {}

    def matches(rule: WazuhRule, visiting: set[int]) -> bool:
        if rule.rule_id in memo:
            return memo[rule.rule_id]
        if rule.rule_id in visiting:
            return False
        parent_ok = True
        if rule.parent_id is not None:
            parent_ok = matches(by_id[rule.parent_id], visiting | {rule.rule_id})
        fields_ok = True
        for field, pattern in rule.fields:
            exists, actual = _field_value(event, field)
            if not exists or re.search(pattern, str(actual)) is None:
                fields_ok = False
                break
        memo[rule.rule_id] = parent_ok and fields_ok
        return memo[rule.rule_id]

    return {rule.rule_id for rule in rules if rule.level > 0 and matches(rule, set())}


def load_suricata_rules(path: Path) -> tuple[list[SuricataRule], list[str]]:
    errors: list[str] = []
    rules: list[SuricataRule] = []
    sids: set[int] = set()
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        prefix = f"{path}: line {line_number}"
        required = (
            "alert tcp ",
            "flow:established,to_server;",
            "app-layer-protocol:modbus;",
            "modbus:",
            "msg:",
            "sid:",
            "rev:",
        )
        for item in required:
            if item not in line:
                errors.append(f"{prefix}: missing {item!r}")
        sid_match = re.search(r"\bsid:\s*(\d+)\s*;", line)
        expression_match = re.search(r"\bmodbus:\s*([^;]+);", line)
        if not sid_match or not expression_match:
            continue
        sid = int(sid_match.group(1))
        if sid in sids:
            errors.append(f"{prefix}: duplicate Suricata sid {sid}")
        sids.add(sid)
        rules.append(SuricataRule(sid, expression_match.group(1).strip()))
    if not rules:
        errors.append(f"{path}: no active Suricata rules found")
    return rules, errors


def suricata_matches(rule: SuricataRule, event: dict[str, Any]) -> bool:
    if event.get("protocol") != "modbus":
        return False
    modbus = event.get("modbus")
    if not isinstance(modbus, dict):
        return False
    for clause in (part.strip() for part in rule.expression.split(",")):
        key, _, value = clause.partition(" ")
        value = value.strip()
        if key == "unit" and modbus.get("unit") != int(value):
            return False
        if key == "access" and modbus.get("access") != value:
            return False
        if key == "function":
            actual = modbus.get("function") if value.isdigit() else modbus.get("function_class")
            expected: Any = int(value) if value.isdigit() else value
            if actual != expected:
                return False
        if key not in {"unit", "access", "function"}:
            return False
    return True


def load_fixtures(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    fixtures: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_cases: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                fixture = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{path}: line {line_number}: invalid JSON: {exc}")
                continue
            case_id = fixture.get("case_id")
            if not isinstance(case_id, str) or not case_id:
                errors.append(f"{path}: line {line_number}: case_id is required")
            elif case_id in seen_cases:
                errors.append(f"{path}: duplicate case_id {case_id}")
            seen_cases.add(case_id)
            if not isinstance(fixture.get("event"), dict):
                errors.append(f"{path}: {case_id}: event must be an object")
            expected = fixture.get("expected")
            if not isinstance(expected, dict) or set(expected) != {"sigma", "wazuh", "suricata"}:
                errors.append(f"{path}: {case_id}: expected must name all three rule formats")
            fixtures.append(fixture)
    if not fixtures:
        errors.append(f"{path}: fixture set is empty")
    return fixtures, errors


def validate_pack(root: Path = ROOT) -> tuple[dict[str, int], list[str]]:
    detections = root / "detections"
    sigma_rules, errors = load_sigma_rules(detections / "sigma")
    wazuh_rules, more_errors = load_wazuh_rules(detections / "wazuh" / "ot_sentinel_rules.xml")
    errors.extend(more_errors)
    suricata_rules, more_errors = load_suricata_rules(
        detections / "suricata" / "ot_sentinel_modbus.rules"
    )
    errors.extend(more_errors)
    fixtures, more_errors = load_fixtures(detections / "fixtures" / "events.jsonl")
    errors.extend(more_errors)

    sigma_names = {rule.name for rule in sigma_rules}
    wazuh_alert_ids = {rule.rule_id for rule in wazuh_rules if rule.level > 0}
    suricata_sids = {rule.sid for rule in suricata_rules}
    covered_sigma: set[str] = set()
    covered_wazuh: set[int] = set()
    covered_suricata: set[int] = set()
    negative_cases = 0

    for fixture in fixtures:
        case_id = fixture.get("case_id", "unknown")
        event = fixture.get("event", {})
        expected = fixture.get("expected", {})
        if not isinstance(event, dict) or not isinstance(expected, dict):
            continue
        expected_sigma = set(expected.get("sigma", []))
        expected_wazuh = set(expected.get("wazuh", []))
        expected_suricata = set(expected.get("suricata", []))
        actual_sigma = {rule.name for rule in sigma_rules if sigma_matches(rule, event)}
        actual_wazuh = wazuh_matches(wazuh_rules, event)
        actual_suricata = {
            rule.sid for rule in suricata_rules if suricata_matches(rule, event)
        }
        for format_name, expected_set, actual_set in (
            ("Sigma", expected_sigma, actual_sigma),
            ("Wazuh", expected_wazuh, actual_wazuh),
            ("Suricata", expected_suricata, actual_suricata),
        ):
            if actual_set != expected_set:
                errors.append(
                    f"fixture {case_id}: {format_name} expected {sorted(expected_set)!r}, "
                    f"got {sorted(actual_set)!r}"
                )
        covered_sigma.update(expected_sigma)
        covered_wazuh.update(expected_wazuh)
        covered_suricata.update(expected_suricata)
        if not expected_sigma and not expected_wazuh and not expected_suricata:
            negative_cases += 1

    for label, existing, covered in (
        ("Sigma", sigma_names, covered_sigma),
        ("Wazuh", wazuh_alert_ids, covered_wazuh),
        ("Suricata", suricata_sids, covered_suricata),
    ):
        unknown = covered - existing
        missing = existing - covered
        if unknown:
            errors.append(f"fixtures reference unknown {label} rules: {sorted(unknown)!r}")
        if missing:
            errors.append(f"{label} rules lack a positive fixture: {sorted(missing)!r}")
    if negative_cases < 2:
        errors.append("fixture set must contain at least two all-negative cases")

    summary = {
        "sigma_rules": len(sigma_rules),
        "wazuh_alert_rules": len(wazuh_alert_ids),
        "suricata_rules": len(suricata_rules),
        "fixtures": len(fixtures),
        "negative_cases": negative_cases,
    }
    return summary, errors


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate OT Sentinel detection syntax, identifiers and fixture behavior"
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    args = parser.parse_args()
    summary, errors = validate_pack(args.root.resolve())
    if errors:
        raise SystemExit("Detection validation failed:\n- " + "\n- ".join(errors))
    print(
        "Detection pack validated: "
        f"{summary['sigma_rules']} Sigma, "
        f"{summary['suricata_rules']} Suricata, "
        f"{summary['wazuh_alert_rules']} Wazuh alert rules; "
        f"{summary['fixtures']} fixtures ({summary['negative_cases']} all-negative)."
    )


if __name__ == "__main__":
    main()
