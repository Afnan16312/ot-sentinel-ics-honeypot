# Offline SOC Integration Plan

OT Sentinel already includes tested Wazuh and Suricata rules. This plan keeps integration work separate from the live Oracle sensor until a controlled maintenance window is approved.

## Phase 1: safe offline verification

1. Run `python scripts/validate_detections.py`.
2. Review the positive and negative synthetic fixtures in `detections/fixtures/events.jsonl`.
3. Confirm that connection-only activity does not create an attack alert.
4. In a disposable Wazuh lab, copy `detections/wazuh/ot_sentinel_rules.xml` into the manager's custom rules directory.
5. Test only synthetic fixture lines with `wazuh-logtest`.
6. In a disposable Suricata lab, load `detections/suricata/ot_sentinel_modbus.rules` and run `suricata -T` before packet testing.
7. Record false positives and rule changes with matching regression fixtures.

## Phase 2: controlled future integration

Do not start this phase during active collection without a change window and rollback approval.

1. Choose Wazuh log ingestion or Suricata network inspection; they solve different problems.
2. Back up private evidence and configuration.
3. Define resource limits, retention, redaction and destination access.
4. Test the exact configuration on a cloned or disposable environment.
5. Start in alert-only mode with no automatic blocking.
6. Monitor resource use, event loss and false-positive volume.
7. Roll back immediately if collection, storage or isolation controls degrade.

Detailed rule behavior and tool-specific commands remain in [Detection Engineering](DETECTION_ENGINEERING.md). No SOC agent, rule or service is deployed by this document.
