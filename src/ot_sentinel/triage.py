"""Deterministic, evidence-based triage for OT Sentinel events.

The score ranks recorded decoy interactions for analyst review. It does not
infer attacker identity, motive, attribution, or successful compromise.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

CONTROL_OPERATIONS = {
    "write_single",
    "write_multiple",
    "single_command",
    "setpoint_command",
}
PROGRAM_OPERATIONS = {"program_download"}
READ_OPERATIONS = {
    "read_coils",
    "read_discrete_inputs",
    "read_holding_registers",
    "read_input_registers",
}
PROBE_OPERATIONS = {"device_probe", "connection_setup", "interrogation"}


@dataclass(frozen=True)
class TriageFactor:
    """One observable contribution to a triage score."""

    code: str
    points: int
    explanation: str


@dataclass(frozen=True)
class TriageAssessment:
    """A review priority derived only from evidence stored in an event."""

    score: int
    priority: str
    factors: tuple[TriageFactor, ...]
    analyst_note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def assess_event(
    event: Mapping[str, Any], *, repeat_count: int = 1, is_novel_payload: bool = False
) -> TriageAssessment:
    """Assign a reproducible review score in the inclusive range 0..100.

    Points are additive and capped at 100. Repeat evidence is a count of prior
    pseudonymous-source observations; novelty means this payload fingerprint has
    not appeared in the private index. Geography and identity are ignored.
    """

    decoded = event.get("decoded") or {}
    if not isinstance(decoded, Mapping):
        decoded = {}
    operation = str(decoded.get("operation", "")).lower()
    event_type = str(event.get("event_type", "")).lower()
    factors: list[TriageFactor] = []

    if operation in CONTROL_OPERATIONS:
        factors.append(
            TriageFactor(
                "control_command",
                40,
                "The request carried an operation that can change simulated controller state.",
            )
        )
    elif operation in PROGRAM_OPERATIONS:
        factors.append(
            TriageFactor(
                "program_transfer",
                45,
                "The request used a controller program-transfer operation.",
            )
        )
    else:
        if operation in READ_OPERATIONS or _is_modbus_read(decoded):
            factors.append(
                TriageFactor(
                    "process_read",
                    15,
                    "The request read simulated process or I/O state.",
                )
            )
        if operation in PROBE_OPERATIONS:
            factors.append(
                TriageFactor(
                    "protocol_probe",
                    10,
                    "The source sent a protocol-aware discovery request.",
                )
            )

    if event_type == "known_exploit_probe" and decoded.get("signature"):
        factors.append(
            TriageFactor(
                "exploit_signature",
                35,
                "The captured payload matched a configured exploit signature.",
            )
        )

    highest_confidence = _highest_confidence(event.get("techniques"))
    confidence_points = {"low": 5, "medium": 10, "high": 20}.get(highest_confidence, 0)
    if confidence_points:
        factors.append(
            TriageFactor(
                "mapped_evidence",
                confidence_points,
                f"The strongest evidence-qualified ATT&CK mapping has {highest_confidence} confidence.",
            )
        )

    if repeat_count > 1:
        repeat_points = 15 if repeat_count >= 5 else 10
        factors.append(
            TriageFactor(
                "repeat_source",
                repeat_points,
                f"This pseudonymous source has {repeat_count:,} observations in the private index.",
            )
        )
    if is_novel_payload:
        factors.append(
            TriageFactor(
                "novel_payload",
                5,
                "This payload fingerprint has not previously appeared in the private index.",
            )
        )

    score = min(100, sum(factor.points for factor in factors))
    priority = priority_for_score(score)
    return TriageAssessment(
        score=score,
        priority=priority,
        factors=tuple(factors),
        analyst_note=_analyst_note(priority),
    )


def priority_for_score(score: int) -> str:
    """Convert a score to a stable review queue without implying intent."""

    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")
    if score >= 75:
        return "urgent review"
    if score >= 50:
        return "high review"
    if score >= 25:
        return "elevated review"
    if score > 0:
        return "routine review"
    return "informational"


def factor_summary(assessment: TriageAssessment) -> str:
    """Return a concise, human-readable explanation for tables and exports."""

    if not assessment.factors:
        return "No scored protocol evidence."
    return "; ".join(f"{factor.code} (+{factor.points})" for factor in assessment.factors)


def next_step_for_priority(priority: str) -> str:
    """Give a bounded human review step without implying automated response."""

    steps = {
        "urgent review": "Review the session timeline, ATT&CK rationale, and detection coverage promptly.",
        "high review": "Review the session timeline and validate the recorded evidence before escalation.",
        "elevated review": "Compare this evidence with related sessions and check the mapped ATT&CK rationale.",
        "routine review": "Retain this evidence for routine correlation and look for repeated activity.",
        "informational": "Keep this record as context; no scored protocol behavior requires a response.",
    }
    return steps.get(priority, "Review the recorded evidence before deciding on any next action.")


def _is_modbus_read(decoded: Mapping[str, Any]) -> bool:
    try:
        return int(decoded.get("function_code", -1)) in {1, 2, 3, 4}
    except (TypeError, ValueError):
        return False


def _highest_confidence(techniques: Any) -> str:
    if not isinstance(techniques, Sequence) or isinstance(techniques, (str, bytes)):
        return ""
    weights = {"low": 1, "medium": 2, "high": 3}
    best = ""
    for technique in techniques:
        if isinstance(technique, Mapping):
            confidence = str(technique.get("confidence", "")).lower()
        else:
            confidence = str(getattr(technique, "confidence", "")).lower()
        if weights.get(confidence, 0) > weights.get(best, 0):
            best = confidence
    return best


def _analyst_note(priority: str) -> str:
    notes = {
        "urgent review": "Review promptly and validate the recorded protocol evidence.",
        "high review": "Prioritize this evidence for analyst review.",
        "elevated review": "Review after higher-scored interactions.",
        "routine review": "Retain for routine analysis and correlation.",
        "informational": "Retain as context; no scored behavior was observed.",
    }
    return notes[priority]
