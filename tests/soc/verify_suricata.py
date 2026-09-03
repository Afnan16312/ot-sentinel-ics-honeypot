from __future__ import annotations

import json
from pathlib import Path


def verify(path: Path) -> None:
    alerts = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record.get("event_type") == "alert":
                alerts.append(record)
    matching = [
        record
        for record in alerts
        if int(record.get("alert", {}).get("signature_id", 0)) == 4200501
    ]
    if len(matching) != 1:
        raise AssertionError(f"expected one SID 4200501 write alert, found {len(matching)}")
    if int(matching[0].get("src_port", 0)) != 41000:
        raise AssertionError("write alert did not correspond to the synthetic write flow")
    if any(int(record.get("src_port", 0)) == 42000 for record in alerts):
        raise AssertionError("harmless Modbus read flow generated an alert")


if __name__ == "__main__":
    verify(Path(__file__).resolve().parent / "output" / "eve.json")
    print("Suricata native validation passed: write alerted and read remained quiet.")
