from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = Path(__file__).resolve().parent
COMPOSE = ["docker", "compose", "-f", str(LAB / "docker-compose.yml")]

POSITIVE = {
    "sensor_id": "synthetic-soc-lab",
    "event_type": "protocol_request",
    "protocol": "modbus",
    "decoded": {"operation": "write_single", "function_code": 6},
    "severity": "high",
    "is_demo": True,
    "sanitized": True,
}
NEGATIVES = [
    {
        "sensor_id": "synthetic-soc-lab",
        "event_type": "connection",
        "protocol": "modbus",
        "decoded": {},
        "severity": "info",
        "is_demo": True,
        "sanitized": True,
    },
    {
        "sensor_id": "synthetic-soc-lab",
        "event_type": "protocol_request",
        "protocol": "modbus",
        "decoded": {"operation": "device_probe", "function_code": 3},
        "severity": "medium",
        "is_demo": True,
        "sanitized": True,
    },
]


def run_logtest(
    event: dict,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    command = [
        *COMPOSE,
        "exec",
        "-T",
        "wazuh.manager",
        "/var/ossec/bin/wazuh-logtest",
    ]
    result = runner(
        command,
        cwd=ROOT,
        input=json.dumps(event) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"wazuh-logtest failed:\n{output}")
    return output


def verify_outputs(positive: str, negatives: list[str]) -> None:
    if "110001" not in positive:
        raise AssertionError("Wazuh rule 110001 did not fire for synthetic Modbus write")
    for output in negatives:
        if "110001" in output:
            raise AssertionError("Wazuh rule 110001 fired for a harmless negative fixture")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run native Wazuh OT Sentinel rule tests")
    parser.parse_args()
    positive = run_logtest(POSITIVE)
    negative_outputs = [run_logtest(event) for event in NEGATIVES]
    verify_outputs(positive, negative_outputs)
    print("Wazuh native validation passed: rule 110001 fired only for the write fixture.")


if __name__ == "__main__":
    main()
