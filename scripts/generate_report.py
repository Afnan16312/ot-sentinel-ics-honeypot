from __future__ import annotations

import argparse
import sqlite3
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def build_report(database: Path, *, as_of: datetime, days: int = 7) -> tuple[str, bool]:
    as_of = as_of.astimezone(UTC)
    days = max(1, min(days, 90))
    start = as_of - timedelta(days=days)
    start_epoch = int(start.timestamp())
    end_epoch = int(as_of.timestamp())
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        observations = connection.execute(
            """
            SELECT * FROM observations
            WHERE last_seen_epoch >= ? AND last_seen_epoch < ?
            ORDER BY last_seen_epoch, id
            """,
            (start_epoch, end_epoch),
        ).fetchall()
        techniques = connection.execute(
            """
            SELECT t.technique_id, t.confidence, o.repeat_count
            FROM observation_techniques AS t
            JOIN observations AS o ON o.id = t.observation_id
            WHERE o.last_seen_epoch >= ? AND o.last_seen_epoch < ?
            ORDER BY t.technique_id, t.confidence
            """,
            (start_epoch, end_epoch),
        ).fetchall()

    classifications = {bool(row["is_demo"]) for row in observations}
    if len(classifications) > 1:
        raise ValueError("synthetic and observed records must not be mixed in one report")
    is_demo = next(iter(classifications), True)
    total_events = sum(int(row["repeat_count"]) for row in observations)
    sessions = {str(row["session_id"]) for row in observations if row["session_id"]}
    protocols: Counter[str] = Counter()
    source_sessions: dict[str, set[str]] = defaultdict(set)
    technique_counts: Counter[str] = Counter()
    confidence_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for row in observations:
        protocols[str(row["protocol"])] += int(row["repeat_count"])
        if row["session_id"]:
            source_sessions[str(row["source_id"])].add(str(row["session_id"]))
    for row in techniques:
        count = int(row["repeat_count"])
        technique_id = str(row["technique_id"])
        technique_counts[technique_id] += count
        confidence_counts[technique_id][str(row["confidence"])] += count

    notice = (
        "Synthetic demonstration statistics; not observed attacker activity."
        if is_demo
        else "Private sanitized observations; not approved for public release."
    )
    lines = [
        "# Weekly OT Threat Intelligence Brief",
        "",
        f"> **Data notice:** {notice}",
        "",
        "## Reporting window",
        "",
        f"{start.isoformat(timespec='seconds')} to {as_of.isoformat(timespec='seconds')} (UTC)",
        "",
        "## Summary",
        "",
        f"- Total sessions represented: **{len(sessions)}**",
        f"- Total events including repetitions: **{total_events}**",
        "- Source pseudonyms do not identify people or organizations.",
        "- ATT&CK mappings are evidence-qualified hypotheses, not proof of intent or compromise.",
        "",
        "## Protocol breakdown",
        "",
        "| Protocol | Events |",
        "|---|---:|",
    ]
    for protocol in ("modbus", "s7", "iec104"):
        lines.append(f"| {protocol} | {protocols[protocol]} |")
    lines.extend(
        [
            "",
            "## Top ATT&CK for ICS techniques",
            "",
            "| Technique | Observations | Confidence distribution |",
            "|---|---:|---|",
        ]
    )
    for technique_id, count in sorted(
        technique_counts.items(), key=lambda item: (-item[1], item[0])
    )[:5]:
        confidence = ", ".join(
            f"{name}: {value}"
            for name, value in sorted(confidence_counts[technique_id].items())
        )
        lines.append(f"| {technique_id} | {count} | {confidence} |")
    if not technique_counts:
        lines.append("| None | 0 | No mapped techniques in this window |")
    lines.extend(
        [
            "",
            "## Top private pseudonymous sources",
            "",
            "| Salted pseudonym | Sessions |",
            "|---|---:|",
        ]
    )
    ranked_sources = sorted(
        ((source_id, len(values)) for source_id, values in source_sessions.items()),
        key=lambda item: (-item[1], item[0]),
    )[:5]
    for source_id, count in ranked_sources:
        lines.append(f"| {source_id} | {count} |")
    if not ranked_sources:
        lines.append("| None | 0 |")
    lines.extend(
        [
            "",
            "## Methodology",
            "",
            (
                "Counts come from OT Sentinel's privacy-reduced SQLite analysis index. Repeated "
                "source/protocol/payload observations inside the deduplication window contribute "
                "through `repeat_count`. JSONL remains the authoritative private evidence."
            ),
            "",
            "## Limitations",
            "",
            (
                "A honeypot observes only traffic that reaches its exposed decoy. A network "
                "source is not an identity, geolocation is approximate, and protocol interaction "
                "is not proof of exploitation, attribution or physical impact."
            ),
            "",
        ]
    )
    return "\n".join(lines), is_demo


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a weekly OT intelligence brief")
    parser.add_argument("database", type=Path)
    parser.add_argument("--as-of", required=True, help="ISO-8601 exclusive report end time")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    as_of = _parse_time(args.as_of)
    report, is_demo = build_report(args.database, as_of=as_of, days=args.days)
    output = args.output
    if output is None:
        output = Path("reports/private") / f"weekly-{as_of.date().isoformat()}.md"
    if not is_demo and Path("reports/private") not in output.parents:
        raise SystemExit("Observed-data reports must remain under reports/private/.")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"Created weekly report: {output}")


if __name__ == "__main__":
    main()
