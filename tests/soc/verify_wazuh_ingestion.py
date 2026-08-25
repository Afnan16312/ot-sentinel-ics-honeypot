from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
LAB = Path(__file__).resolve().parent
COMPOSE = ["docker", "compose", "-f", str(LAB / "docker-compose.yml")]
POSITIVE_ID = "soc-persist-write-001"
NEGATIVE_IDS = {"soc-persist-connection-001", "soc-persist-read-001"}
CUSTOM_ALERT_RULES = {"110001", "110002", "110003", "110004"}


def _run(service: str, command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*COMPOSE, "exec", "-T", service, *command],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _manager_alerts() -> list[dict[str, Any]]:
    result = _run(
        "wazuh.manager",
        [
            "sh",
            "-c",
            (
                "test -f /var/ossec/logs/alerts/alerts.json && "
                "cat /var/ossec/logs/alerts/alerts.json"
            ),
        ],
    )
    if result.returncode != 0:
        return []
    alerts: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            alerts.append(value)
    return alerts


def _event_id(alert: dict[str, Any]) -> str:
    data = alert.get("data")
    return str(data.get("event_id", "")) if isinstance(data, dict) else ""


def _rule_id(alert: dict[str, Any]) -> str:
    rule = alert.get("rule")
    return str(rule.get("id", "")) if isinstance(rule, dict) else ""


def _indexer_hits() -> int:
    query = json.dumps(
        {
            "size": 0,
            "query": {"match": {"data.event_id": POSITIVE_ID}},
        },
        separators=(",", ":"),
    )
    result = _run(
        "wazuh.indexer",
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--cacert",
            "/usr/share/wazuh-indexer/config/certs/root-ca.pem",
            "--cert",
            "/usr/share/wazuh-indexer/config/certs/admin.pem",
            "--key",
            "/usr/share/wazuh-indexer/config/certs/admin-key.pem",
            "-H",
            "Content-Type: application/json",
            "https://wazuh.indexer:9200/wazuh-alerts-*/_search",
            "-d",
            query,
        ],
    )
    if result.returncode != 0:
        return 0
    try:
        payload = json.loads(result.stdout)
        total = payload["hits"]["total"]
        return int(total["value"] if isinstance(total, dict) else total)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return 0


def verify(*, timeout_seconds: int = 120) -> None:
    deadline = time.monotonic() + timeout_seconds
    manager_verified = False
    indexer_verified = False
    while time.monotonic() < deadline:
        alerts = _manager_alerts()
        positive = [
            alert
            for alert in alerts
            if _event_id(alert) == POSITIVE_ID and _rule_id(alert) == "110001"
        ]
        negative_custom = [
            alert
            for alert in alerts
            if _event_id(alert) in NEGATIVE_IDS and _rule_id(alert) in CUSTOM_ALERT_RULES
        ]
        manager_verified = bool(positive) and not negative_custom
        indexer_verified = _indexer_hits() > 0
        if manager_verified and indexer_verified:
            return
        time.sleep(3)
    raise AssertionError(
        "persistent Wazuh validation timed out "
        f"(manager={manager_verified}, indexer={indexer_verified})"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify persistent and searchable synthetic OT Sentinel Wazuh alerts"
    )
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    verify(timeout_seconds=max(10, min(args.timeout, 300)))
    print(
        "Persistent Wazuh validation passed: rule 110001 was stored and indexed only "
        "for the synthetic write fixture."
    )


if __name__ == "__main__":
    main()
