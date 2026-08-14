from __future__ import annotations

from collections.abc import Iterable

from .model import TechniqueMatch

CATALOG: dict[str, tuple[str, str]] = {
    "T0846.001": ("Remote System Discovery: Port Scan", "Discovery"),
    "T0877": ("I/O Image", "Collection"),
    "T1692.001": ("Unauthorized Message: Command Message", "Impair Process Control"),
    "T0836": ("Modify Parameter", "Impair Process Control"),
    "T0806": ("Brute Force I/O", "Impair Process Control"),
    "T0843": ("Program Download", "Lateral Movement"),
    "T0866": ("Exploitation of Remote Services", "Initial Access"),
}


def _match(technique_id: str, confidence: str, rationale: str) -> TechniqueMatch:
    name, tactic = CATALOG[technique_id]
    return TechniqueMatch(technique_id, name, tactic, confidence, rationale)


def map_event(protocol: str, event_type: str, decoded: dict) -> list[TechniqueMatch]:
    """Return evidence-qualified ATT&CK hypotheses for a decoded request.

    A TCP connection alone is deliberately not mapped. ATT&CK describes adversary
    behavior, so the mapper requires protocol-level evidence and records confidence.
    """
    if event_type not in {"protocol_request", "known_exploit_probe"}:
        return []

    matches: list[TechniqueMatch] = []
    operation = str(decoded.get("operation", "")).lower()

    if operation in {"device_probe", "connection_setup", "interrogation"}:
        matches.append(
            _match(
                "T0846.001",
                "medium",
                "The source issued a protocol-aware request commonly used to enumerate an ICS service.",
            )
        )

    if protocol == "modbus" and decoded.get("function_code") in {1, 2, 3, 4}:
        matches.append(
            _match(
                "T0877",
                "low",
                "A Modbus read may collect process or I/O state; intent cannot be proven from one request.",
            )
        )

    if operation in {"write_single", "write_multiple", "single_command", "setpoint_command"}:
        matches.extend(
            [
                _match(
                    "T1692.001",
                    "high",
                    "An unauthenticated command message attempted to change decoy controller state.",
                ),
                _match(
                    "T0836",
                    "medium",
                    "The command carried a value intended to alter a simulated process parameter.",
                ),
            ]
        )

    if operation == "program_download":
        matches.append(
            _match("T0843", "high", "The request used a controller program-transfer operation.")
        )

    if event_type == "known_exploit_probe" and decoded.get("signature"):
        matches.append(
            _match(
                "T0866",
                "high",
                "The payload matched a documented exploit signature, not merely an open-port probe.",
            )
        )

    return _deduplicate(matches)


def _deduplicate(matches: Iterable[TechniqueMatch]) -> list[TechniqueMatch]:
    seen: set[str] = set()
    result: list[TechniqueMatch] = []
    for match in matches:
        if match.technique_id not in seen:
            result.append(match)
            seen.add(match.technique_id)
    return result

