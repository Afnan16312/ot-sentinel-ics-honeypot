from __future__ import annotations

import json
from pathlib import Path

from openapi_spec_validator import validate

CONTRACT = Path(__file__).resolve().parents[1] / "docs" / "api" / "collector.openapi.json"


def test_collector_contract_passes_external_openapi_31_validator():
    specification = json.loads(CONTRACT.read_text(encoding="utf-8"))
    validate(specification)
