from __future__ import annotations

import argparse
import json
import os
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_WARNING = 1
EXIT_CRITICAL = 2


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    message: str


@dataclass(frozen=True)
class HealthResult:
    status: str
    exit_code: int
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "ot-sentinel-health-check/1",
            "status": self.status,
            "exit_code": self.exit_code,
            "findings": [asdict(finding) for finding in self.findings],
        }


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _age_seconds(value: object, now: datetime) -> float | None:
    parsed = _timestamp(value)
    if parsed is None:
        return None
    return max(0.0, (now - parsed).total_seconds())


def evaluate_health(
    snapshot: dict[str, Any],
    *,
    now: datetime,
    process_running: bool = True,
    disk_free_percent: float = 100.0,
    collector_storage_ready: bool | None = None,
    expect_traffic: bool = False,
    generated_max_age: int = 120,
    event_max_age: int = 900,
    disk_warning_percent: float = 10.0,
    disk_critical_percent: float = 5.0,
) -> HealthResult:
    """Evaluate a local health snapshot without copying its telemetry into output."""
    findings: list[Finding] = []

    if not process_running or snapshot.get("status") != "ok":
        findings.append(Finding("process", "critical", "Sensor process is not healthy."))

    generated_age = _age_seconds(snapshot.get("generated_at"), now)
    if generated_age is None:
        findings.append(Finding("snapshot_freshness", "critical", "Health timestamp is invalid."))
    elif generated_age > generated_max_age:
        findings.append(Finding("snapshot_freshness", "critical", "Health snapshot is stale."))

    if expect_traffic:
        event_age = _age_seconds(snapshot.get("last_event_at"), now)
        if event_age is None:
            findings.append(Finding("event_freshness", "warning", "No recent event is reported."))
        elif event_age > event_max_age:
            findings.append(Finding("event_freshness", "warning", "Last event is stale."))

    if disk_free_percent < disk_critical_percent:
        findings.append(Finding("disk", "critical", "Available disk space is critically low."))
    elif disk_free_percent < disk_warning_percent:
        findings.append(Finding("disk", "warning", "Available disk space is below threshold."))

    queue_drop_fields = ("alert_queue_drops", "collector_queue_drops", "spool_queue_drops")
    if any(int(snapshot.get(field, 0) or 0) > 0 for field in queue_drop_fields):
        findings.append(Finding("queue_drops", "warning", "One or more bounded queues dropped work."))
    if int(snapshot.get("delivery_failures", 0) or 0) > 0:
        findings.append(Finding("delivery", "warning", "One or more deliveries failed."))
    if int(snapshot.get("rejected_sessions", 0) or 0) > 0:
        findings.append(
            Finding("session_capacity", "warning", "One or more sessions exceeded sensor capacity.")
        )

    if collector_storage_ready is None:
        value = snapshot.get("collector_storage_ready")
        collector_storage_ready = value if isinstance(value, bool) else None
    if collector_storage_ready is False:
        findings.append(
            Finding("collector_storage", "critical", "Collector storage is not writable.")
        )
    elif collector_storage_ready is None:
        findings.append(
            Finding("collector_storage", "warning", "Collector storage readiness is not reported.")
        )

    severities = {finding.severity for finding in findings}
    if "critical" in severities:
        return HealthResult("critical", EXIT_CRITICAL, tuple(findings))
    if "warning" in severities:
        return HealthResult("warning", EXIT_WARNING, tuple(findings))
    return HealthResult("ok", EXIT_OK, ())


def process_running(pid: int | None) -> bool:
    if pid is None:
        return True
    try:
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False
    return True


def storage_ready(path: Path | None) -> bool | None:
    if path is None:
        return None
    target = path if path.is_dir() else path.parent
    return target.is_dir() and os.access(target, os.W_OK)


def render_text(result: HealthResult) -> str:
    lines = [f"OT Sentinel health: {result.status.upper()}"]
    if not result.findings:
        lines.append("All configured local readiness checks passed.")
    else:
        lines.extend(
            f"- {finding.severity.upper()} {finding.check}: {finding.message}"
            for finding in result.findings
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check a local OT Sentinel health snapshot")
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--expect-traffic", action="store_true")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--collector-storage", type=Path)
    parser.add_argument("--generated-max-age", type=int, default=120)
    parser.add_argument("--event-max-age", type=int, default=900)
    parser.add_argument("--disk-warning-percent", type=float, default=10.0)
    parser.add_argument("--disk-critical-percent", type=float, default=5.0)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
        if not isinstance(snapshot, dict):
            raise TypeError("snapshot is not an object")
        disk = shutil.disk_usage(args.snapshot.parent)
        free_percent = disk.free / disk.total * 100 if disk.total else 0.0
        result = evaluate_health(
            snapshot,
            now=datetime.now(UTC),
            process_running=process_running(args.pid),
            disk_free_percent=free_percent,
            collector_storage_ready=storage_ready(args.collector_storage),
            expect_traffic=args.expect_traffic,
            generated_max_age=args.generated_max_age,
            event_max_age=args.event_max_age,
            disk_warning_percent=args.disk_warning_percent,
            disk_critical_percent=args.disk_critical_percent,
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        result = HealthResult(
            "critical",
            EXIT_CRITICAL,
            (Finding("snapshot", "critical", "Local health snapshot could not be read."),),
        )
    print(json.dumps(result.to_dict(), sort_keys=True) if args.as_json else render_text(result))
    raise SystemExit(result.exit_code)


if __name__ == "__main__":
    main()
