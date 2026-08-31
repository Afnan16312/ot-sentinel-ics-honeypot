from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from .contracts import (
    ANALYSIS_SCHEMA_VERSION,
    canonical_digest,
    observation_from_event,
    utc_now,
    validate_analysis,
)
from .model import Event
from .triage import TriageAssessment


def analysis_from_event(
    event: Event | Mapping[str, Any],
    assessment: TriageAssessment | Mapping[str, Any],
    *,
    analysis_run_id: str,
) -> dict[str, Any]:
    """Create a versioned interpretation that can be regenerated from one observation."""
    raw = event.to_dict() if isinstance(event, Event) else dict(event)
    observation = observation_from_event(raw)
    triage = assessment.to_dict() if isinstance(assessment, TriageAssessment) else dict(assessment)
    result = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "analysis_id": str(uuid4()),
        "analysis_run_id": analysis_run_id,
        "event_id": observation["event_id"],
        "input_digest": canonical_digest(observation),
        "executed_at": utc_now(),
        "versions": {"mapper": "v1", "triage": "v1", "rule_catalog": "not-run"},
        "attack_hypotheses": raw.get("techniques", []),
        "severity": raw.get("severity", "info"),
        "triage": triage,
        "detection_results": [],
        "evidence_completeness": triage.get("evidence_completeness", {}),
    }
    validate_analysis(result)
    return result
