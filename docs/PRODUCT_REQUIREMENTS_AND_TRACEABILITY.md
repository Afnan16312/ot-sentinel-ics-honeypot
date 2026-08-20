# Product Requirements and Traceability (PRT)

This document states the product requirements for OT Sentinel v0.2.0 plus the current deployment update and traces each requirement to implementation and verification evidence.

## 1. Product definition

OT Sentinel is a low-interaction OT/ICS honeypot and analysis pipeline. It safely simulates selected industrial protocol behavior, records bounded evidence, maps supported behavior to MITRE ATT&CK for ICS, protects publication-sensitive fields and produces useful dashboard, detection and threat-intelligence outputs.

## 2. Intended users

- A learner demonstrating OT/ICS security engineering.
- A security analyst studying sanitized honeypot telemetry.
- A detection engineer adapting example rules for a SIEM or IDS.
- A researcher preparing an authorized, privacy-reviewed collection study.

## 3. Goals

1. Demonstrate industrial-protocol awareness rather than generic port logging.
2. Keep untrusted interaction low risk and disconnected from physical equipment.
3. Separate observed evidence from analytical inference.
4. Make public outputs reproducible and privacy reviewed.
5. Turn telemetry into portable intelligence and detection content.
6. Make the complete synthetic demonstration runnable without paid services.

## 4. Non-goals

- Full vendor PLC or HMI emulation.
- Connection to production OT, safety systems or physical processes.
- Attacker attribution, retaliation or identity discovery.
- Proof of NESA compliance or certification.
- Claiming synthetic records as live UAE threat intelligence.
- Replacing a production SIEM, message broker, secret manager or incident-response platform.

## 5. Functional requirements

| ID | Requirement | Status | Implementation evidence | Verification evidence |
|---|---|---|---|---|
| FR-01 | Listen for Modbus/TCP requests on a configurable port | Shipped | `sensor.py`, `protocols.py` | `test_protocols.py`, `test_sensor_integration.py` |
| FR-02 | Listen for S7/ISO-on-TCP requests on a configurable port | Shipped | `sensor.py`, `protocols.py` | `test_protocols.py` |
| FR-03 | Listen for IEC-104 requests on a configurable port | Shipped | `sensor.py`, `protocols.py` | `test_protocols.py` |
| FR-04 | Produce structured JSON events for connections, protocol requests and bounded errors | Shipped | `model.py`, `sensor.py` | integration and protocol tests |
| FR-05 | Normalize compatible Conpot JSONL into the project event model | Shipped | `normalizer.py`, `cli.py` | CLI normalization smoke check and implementation review |
| FR-06 | Map only supported protocol evidence to ATT&CK for ICS with confidence and rationale | Shipped | `mapper.py` | `test_mapper.py`, labeled evaluation fixtures |
| FR-07 | Avoid labeling a connection-only event as exploitation | Shipped | `mapper.py` | negative mapper and detection fixtures |
| FR-08 | Sanitize publication data by pseudonymizing addresses and removing raw payloads and credential-like fields | Shipped | `privacy.py`, `validate_public_data.py` | `test_privacy.py`, public-data validation |
| FR-09 | Display sanitized activity, techniques, sessions, limitations and triage results | Shipped | `app.py` | dashboard import and HTTP health smoke tests; dataset validation |
| FR-10 | Calculate a deterministic, explainable evidence-based review priority | Shipped | `triage.py` | `test_triage.py` |
| FR-11 | Evaluate ATT&CK mapper agreement against labeled regression cases | Shipped | `evaluation.py`, evaluation fixtures | `test_evaluation.py`, CLI output |
| FR-12 | Export events using public and private STIX 2.1 profiles | Shipped | `stix_export.py`, `cli.py` | `test_stix_export.py`, OASIS validator subtests |
| FR-13 | Supply portable detection examples for Sigma, Suricata and Wazuh | Shipped | `detections/` | `validate_detections.py`, `test_detections.py` |
| FR-14 | Load fictional, stateful device profiles without executable hooks | Shipped | `profiles.py`, `profiles/` | `test_profiles.py` |
| FR-15 | Apply permitted Modbus writes only to in-memory fictional registers | Shipped | `ProfileRuntime`, `protocols.py` | single/multiple write, reset and rejection tests |
| FR-16 | Record sensor health counters and queue state atomically | Shipped | `HealthTracker` in `operations.py` | `test_operations.py` and sensor smoke test |
| FR-17 | Optionally send deduplicated, redacted alerts for high-severity and high-confidence events only | Shipped | `AlertPolicy`, `WebhookAlerter` | `test_operations.py` |
| FR-18 | Optionally forward events to a central collector using per-sensor HMAC authentication | Shipped | `transport.py`, `collector.py` | `test_transport.py` |
| FR-19 | Reject remote replay, stale timestamps, identity mismatch, invalid signatures and oversized bodies | Shipped | `CollectorVerifier`, HTTP handler | `test_transport.py` |
| FR-20 | Generate an SPDX 2.3 SBOM and SHA-256 release evidence | Shipped | `generate_sbom.py`, `build_release_evidence.py` | `test_supply_chain.py`, release workflow |
| FR-21 | Provide a repeatable 420-event synthetic dataset and report | Shipped | `generate_demo_data.py`, `build_report.py`, `data/`, `output/pdf/` | reproducibility check in CI |
| FR-22 | Provide local, Docker, systemd, Oracle and Azure deployment assets | Shipped and Oracle-verified | `Dockerfile`, Compose and `infra/` | container build/scan; Oracle inbound, outbound, restart, health and rotation checks |
| FR-23 | Preserve inbound public OT ports while blocking container-initiated Internet connections | Shipped and Oracle-verified | `infra/oracle/ot-sentinel-firewall`, Oracle Compose override | public port tests and outbound `TimeoutError` verification |
| FR-24 | Record live deployment evidence without publishing identifiers or raw telemetry | Shipped | `docs/LIVE_DEPLOYMENT_RECORD.md` | manual privacy review and repository secret/data checks |

## 6. Non-functional requirements

| ID | Requirement | Design response | Verification |
|---|---|---|---|
| NFR-01 Safety | No received content may execute or reach real equipment | Low-interaction parsers, fixed response functions, no shell/plugin hooks | protocol, profile and integration tests |
| NFR-02 Bounded input | A client cannot send unbounded session data | Configurable limit with 4 KiB hard cap and timeouts | sensor implementation and tests |
| NFR-03 Privacy | Public output must exclude raw IPs and payloads | Allowlisted sanitizer and STIX public gate | privacy tests and validator script |
| NFR-04 Explainability | Every strong mapping or score must expose its evidence | rationale, confidence and score factors | mapper, triage tests and dashboard |
| NFR-05 Availability | Notification or collector failure must not stop local sensing | bounded background queues and retries | operations and transport tests |
| NFR-06 Authentication | Remote collection must authenticate sensor and body | HMAC-SHA256 over timestamp and exact body | tamper, stale and replay tests |
| NFR-07 Encryption | Remote delivery must use HTTPS outside loopback tests | URL validation and TLS-required collector startup | transport tests and operations guide |
| NFR-08 Reproducibility | Demo results and analysis must be repeatable | seeded data, deterministic scoring and STIX IDs | CI data diff and unit tests |
| NFR-09 Supply chain | Known dependency and container risks must be detected | pip-audit, Dependabot, CodeQL and Trivy | successful GitHub workflows |
| NFR-10 Cost | Local development and demonstration must require no paid service | Python, Streamlit and local JSONL architecture | local launcher and deployment guide |
| NFR-11 Portability | Core sensor must have no required third-party runtime dependency | Python standard-library sensor and collector | package metadata and container build |
| NFR-12 Honesty | Synthetic, inferred and observed information must remain distinguishable | `is_demo`, STIX labels and repeated notices | dataset validation, dashboard and documentation |

## 7. Acceptance evidence for v0.2.0

- 54 automated tests pass, including two public/private STIX validator subtests.
- Four Sigma, four Suricata and four Wazuh alert rules pass ten positive/negative fixtures.
- All three fictional profiles pass schema and safety validation.
- The dashboard and sensor each pass local process smoke tests.
- GitHub CI, CodeQL and Trivy complete successfully.
- The tagged workflow produces an SPDX SBOM and release checksum artifact.
- The public repository contains no raw live collection log.

## 8. Requirements not yet satisfied

| ID | Future requirement | Why it is not marked complete | Completion evidence required |
|---|---|---|---|
| FUT-01 | Complete the active two-to-four-week public collection | The isolated sensor began collecting on 2026-08-19, but the window and shutdown record are incomplete | final collection window, daily health/cost evidence and shutdown record |
| FUT-02 | Publish a UAE-region observed-data report | There is no live reviewed dataset yet | privacy-reviewed observations and a report separating fact from inference |
| FUT-03 | Validate rules inside operational Sigma, Suricata and Wazuh engines | Those engine binaries are not installed in the local workspace | successful destination-engine validation logs |
| FUT-04 | Host a permanent public dashboard | The current dashboard is a local application | approved hosting, cost and privacy decision plus deployment health evidence |
| FUT-05 | Complete independent analyst labeling | The current 12-case mapper fixture is a regression set, not a field benchmark | larger independently reviewed corpus and revised metrics |

## 9. Change control

A future change should update this document when it adds, removes or materially changes a requirement. A requirement should move to **Shipped** only after code and verification evidence are committed together.
