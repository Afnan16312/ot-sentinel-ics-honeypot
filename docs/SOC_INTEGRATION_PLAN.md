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

The repository now provides this disposable harness under `tests/soc/`, including pinned Wazuh 4.14.7 and Suricata 8.0.4 definitions, a synthetic injector, deterministic write/read PCAP and verification scripts. It requires at least 4 CPU, 8 GB RAM, 50 GB free disk and a recent Docker Compose implementation. All host mappings are loopback-only, and Suricata runs offline without IPS/blocking behavior.

Static harness tests and native Wazuh/Suricata execution passed locally on 2026-08-25. The evidence remains intentionally separate from offline matching: `wazuh-logtest`, `suricata -T` and deterministic `eve.json` verification are recorded in [tests/soc/NATIVE_VALIDATION.md](../tests/soc/NATIVE_VALIDATION.md). Re-run the disposable lab after rule or engine changes; never run this stack on Oracle.

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
