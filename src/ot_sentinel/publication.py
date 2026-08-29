from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

MIN_PSEUDONYM_SALT_LENGTH = 32

_PRIVATE_FIELD_NAMES = {
    "source_ip",
    "raw_payload_hex",
    "payload",
    "payload_bin",
}
_CREDENTIAL_TERMS = {
    "api_key",
    "access_key",
    "auth_header",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "password",
    "passwd",
    "private_key",
    "secret",
    "token",
    "username",
}
_ADDRESS_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]+(?:/[0-9]{1,3})?")


class PublicationValidationError(ValueError):
    """Raised when an artifact is unsafe for public display or download."""

    def __init__(self, errors: Iterable[str]) -> None:
        self.errors = tuple(errors)
        message = "; ".join(self.errors[:10]) or "public artifact validation failed"
        super().__init__(message)


def credential_like_key(key: object) -> bool:
    """Return whether a field name could hold authentication material."""
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
    parts = set(normalized.split("_"))
    if normalized in _CREDENTIAL_TERMS:
        return True
    return bool(parts & {"credential", "password", "passwd", "secret", "token", "username"})


def private_field_key(key: object) -> bool:
    normalized = str(key).lower()
    return normalized in _PRIVATE_FIELD_NAMES or credential_like_key(normalized)


def strip_credential_fields(value: Any) -> Any:
    """Recursively remove credential-like dictionary keys without mutating input."""
    if isinstance(value, Mapping):
        return {
            str(key): strip_credential_fields(child)
            for key, child in value.items()
            if not credential_like_key(key)
        }
    if isinstance(value, list):
        return [strip_credential_fields(child) for child in value]
    if isinstance(value, tuple):
        return [strip_credential_fields(child) for child in value]
    return value


def contains_address_literal(value: object) -> bool:
    """Detect an IPv4/IPv6 address or network prefix, including inside labels."""
    if not isinstance(value, str):
        return False
    for candidate in _ADDRESS_CANDIDATE.findall(value):
        candidate = candidate.strip(".:")
        if not candidate or ("." not in candidate and ":" not in candidate):
            continue
        try:
            if "/" in candidate:
                ipaddress.ip_network(candidate, strict=False)
            else:
                ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


def walk(value: Any, path: str = "") -> Iterable[tuple[str, object, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            current = f"{path}.{key}" if path else str(key)
            yield current, key, child
            yield from walk(child, current)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def validate_public_records(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Validate a complete public dataset and return independent record dictionaries."""
    materialized = [dict(record) for record in records]
    errors: list[str] = []
    classifications: set[bool] = set()
    if not materialized:
        errors.append("dataset is empty")

    for index, record in enumerate(materialized, start=1):
        label = f"record {index}"
        if record.get("sanitized") is not True:
            errors.append(f"{label}: sanitized flag is not true")
        if not isinstance(record.get("is_demo"), bool):
            errors.append(f"{label}: is_demo must be a boolean classification")
        else:
            classifications.add(record["is_demo"])
        source_id = record.get("source_id")
        if not isinstance(source_id, str) or not source_id.strip():
            errors.append(f"{label}: source_id is required")
        elif contains_address_literal(source_id):
            errors.append(f"{label}: source_id contains an address literal")

        for field_path, key, value in walk(record):
            normalized_key = str(key).lower()
            if private_field_key(normalized_key):
                errors.append(f"{label}: forbidden field {field_path}")
            if contains_address_literal(value):
                errors.append(f"{label}: address or network prefix found in {field_path}")

    if len(classifications) > 1:
        errors.append("synthetic and observed classifications must not be mixed")
    if errors:
        raise PublicationValidationError(errors)
    return materialized


def load_public_jsonl(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    records: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    with source.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                parse_errors.append(f"line {line_number}: malformed JSON")
                continue
            if not isinstance(value, dict):
                parse_errors.append(f"line {line_number}: record must be a JSON object")
                continue
            records.append(value)
    if parse_errors:
        raise PublicationValidationError(parse_errors)
    return validate_public_records(records)


def validate_public_stix_bundle(bundle: Mapping[str, Any]) -> None:
    """Second, independent privacy gate for a generated public STIX bundle."""
    errors: list[str] = []
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        errors.append("STIX artifact must be a Bundle with an objects list")
    for field_path, key, value in walk(bundle):
        normalized_key = str(key).lower()
        if private_field_key(normalized_key):
            errors.append(f"forbidden STIX field {field_path}")
        if contains_address_literal(value):
            errors.append(f"address or network prefix found in STIX field {field_path}")
    serialized = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    if not serialized:
        errors.append("STIX artifact is empty")
    if errors:
        raise PublicationValidationError(errors)
