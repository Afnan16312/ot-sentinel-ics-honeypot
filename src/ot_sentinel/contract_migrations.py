from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .contracts import ANALYSIS_SCHEMA_VERSION, OBSERVATION_SCHEMA_VERSION, legacy_to_contracts


def migrate_record(record: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return v1 contracts while preserving already-versioned records unchanged."""
    schema = record.get("schema_version")
    if schema == OBSERVATION_SCHEMA_VERSION:
        return dict(record), None
    if schema == ANALYSIS_SCHEMA_VERSION:
        return {}, dict(record)
    return legacy_to_contracts(record)
