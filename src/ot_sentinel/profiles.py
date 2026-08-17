from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProfileValidationError(ValueError):
    """Raised when a decoy profile contains unsafe or invalid content."""


_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
_ALLOWED_TOP_LEVEL = {
    "schema_version",
    "profile_id",
    "display_name",
    "fictional",
    "sector",
    "description",
    "device",
    "modbus",
    "s7",
    "iec104",
}
_FORBIDDEN_KEYS = {
    "command",
    "exec",
    "executable",
    "hook",
    "module",
    "plugin",
    "script",
    "shell",
    "subprocess",
    "url",
}


def _reject_active_content(value: Any, path: str = "profile") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in _FORBIDDEN_KEYS:
                raise ProfileValidationError(f"active content key is not allowed: {path}.{key}")
            _reject_active_content(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_active_content(child, f"{path}[{index}]")


def _bounded_text(value: Any, field: str, maximum: int = 160) -> str:
    text = str(value).strip()
    if not text or len(text) > maximum or any(ord(character) < 32 for character in text):
        raise ProfileValidationError(f"{field} must be printable and 1-{maximum} characters")
    return text


def _register_map(raw: Any) -> dict[int, int]:
    if not isinstance(raw, dict) or len(raw) > 512:
        raise ProfileValidationError("modbus.holding_registers must be an object with <=512 entries")
    result: dict[int, int] = {}
    for address, value in raw.items():
        try:
            numeric_address = int(address)
            numeric_value = int(value)
        except (TypeError, ValueError) as exc:
            raise ProfileValidationError("Modbus register addresses and values must be integers") from exc
        if not 0 <= numeric_address <= 65535 or not 0 <= numeric_value <= 65535:
            raise ProfileValidationError("Modbus register addresses and values must fit uint16")
        result[numeric_address] = numeric_value
    return result


def _writable_ranges(raw: Any) -> tuple[tuple[int, int], ...]:
    if not isinstance(raw, list) or len(raw) > 32:
        raise ProfileValidationError("modbus.writable_ranges must be a list with <=32 ranges")
    ranges: list[tuple[int, int]] = []
    for item in raw:
        if not isinstance(item, list) or len(item) != 2:
            raise ProfileValidationError("each writable range must contain [start, end]")
        start, end = int(item[0]), int(item[1])
        if not 0 <= start <= end <= 65535:
            raise ProfileValidationError("invalid writable Modbus range")
        ranges.append((start, end))
    return tuple(ranges)


@dataclass(frozen=True)
class ProfileDefinition:
    profile_id: str
    display_name: str
    sector: str
    description: str
    device: dict[str, str]
    holding_registers: dict[int, int]
    writable_ranges: tuple[tuple[int, int], ...]
    s7: dict[str, Any]
    iec104: dict[str, Any]


def load_profile(path: str | Path) -> ProfileDefinition:
    """Load the project's safe JSON-subset-of-YAML profile format.

    JSON is valid YAML 1.2. Restricting profiles to this subset keeps the sensor
    dependency-free and prevents YAML object constructors or executable tags.
    """
    profile_path = Path(path)
    if profile_path.stat().st_size > 64 * 1024:
        raise ProfileValidationError("profile exceeds the 64 KiB limit")
    try:
        raw = json.loads(profile_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProfileValidationError("profile must use the safe JSON subset of YAML") from exc
    if not isinstance(raw, dict):
        raise ProfileValidationError("profile root must be an object")
    unknown = set(raw) - _ALLOWED_TOP_LEVEL
    if unknown:
        raise ProfileValidationError(f"unknown profile keys: {', '.join(sorted(unknown))}")
    _reject_active_content(raw)
    if raw.get("schema_version") != 1:
        raise ProfileValidationError("schema_version must be 1")
    if raw.get("fictional") is not True:
        raise ProfileValidationError("profiles must be explicitly marked fictional")
    profile_id = str(raw.get("profile_id", ""))
    if not _PROFILE_ID.fullmatch(profile_id):
        raise ProfileValidationError("profile_id must be a lowercase, hyphenated identifier")

    device_raw = raw.get("device", {})
    if not isinstance(device_raw, dict) or len(device_raw) > 16:
        raise ProfileValidationError("device must be a small object")
    device = {str(key): _bounded_text(value, f"device.{key}") for key, value in device_raw.items()}
    modbus = raw.get("modbus", {})
    if not isinstance(modbus, dict):
        raise ProfileValidationError("modbus must be an object")

    return ProfileDefinition(
        profile_id=profile_id,
        display_name=_bounded_text(raw.get("display_name"), "display_name"),
        sector=_bounded_text(raw.get("sector"), "sector", 40),
        description=_bounded_text(raw.get("description"), "description", 300),
        device=device,
        holding_registers=_register_map(modbus.get("holding_registers", {})),
        writable_ranges=_writable_ranges(modbus.get("writable_ranges", [])),
        s7=deepcopy(raw.get("s7", {})),
        iec104=deepcopy(raw.get("iec104", {})),
    )


class ProfileRuntime:
    """In-memory-only simulated process state for one sensor process."""

    def __init__(self, definition: ProfileDefinition) -> None:
        self.definition = definition
        self._initial_registers = deepcopy(definition.holding_registers)
        self._registers = deepcopy(definition.holding_registers)
        self.command_count = 0

    def reset(self) -> None:
        self._registers = deepcopy(self._initial_registers)
        self.command_count = 0

    def _is_writable(self, address: int) -> bool:
        return any(start <= address <= end for start, end in self.definition.writable_ranges)

    def enrich(self, protocol: str, decoded: dict[str, Any]) -> None:
        decoded["profile_id"] = self.definition.profile_id
        decoded["profile_sector"] = self.definition.sector
        if protocol == "modbus":
            self._apply_modbus(decoded)
        elif protocol == "s7" and decoded.get("valid"):
            decoded["simulated_device"] = deepcopy(self.definition.device)
        elif protocol == "iec104" and decoded.get("valid"):
            decoded["common_address"] = int(self.definition.iec104.get("common_address", 1))
            if decoded.get("operation") in {"single_command", "setpoint_command"}:
                self.command_count += 1
                decoded["simulated_command_recorded"] = True
                decoded["simulated_command_count"] = self.command_count

    def _apply_modbus(self, decoded: dict[str, Any]) -> None:
        function_code = int(decoded.get("function_code", -1))
        address = int(decoded.get("address", 0))
        if function_code in {3, 4}:
            quantity = min(max(int(decoded.get("value_or_quantity", 1)), 1), 16)
            decoded["simulated_values"] = [
                self._registers.get(address + offset, 0) for offset in range(quantity)
            ]
            return
        writes: list[tuple[int, int]] = []
        if function_code == 6:
            writes = [(address, int(decoded.get("value_or_quantity", 0)))]
        elif function_code == 16:
            writes = [
                (address + offset, int(value))
                for offset, value in enumerate(decoded.get("write_values", []))
            ]
        if not writes:
            return
        applied: list[dict[str, int]] = []
        rejected: list[int] = []
        for target, value in writes:
            if self._is_writable(target):
                previous = self._registers.get(target, 0)
                self._registers[target] = value
                applied.append({"address": target, "previous": previous, "value": value})
            else:
                rejected.append(target)
        self.command_count += 1
        decoded["simulated_write_applied"] = bool(applied)
        decoded["simulated_changes"] = applied
        decoded["simulated_rejected_addresses"] = rejected
        decoded["simulated_command_count"] = self.command_count

