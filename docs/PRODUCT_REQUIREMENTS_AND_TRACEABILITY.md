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
| FR-18 | Optionally forward events to a central collector using per-sensor HMAC authentication | Shipped | `transport.py`, `collector.py`, OpenAPI contract | transport and collector black-box tests |
| FR-19 | Reject remote replay, stale/future timestamps, identity mismatch, invalid signatures, malformed framing and oversized bodies | Shipped | `CollectorVerifier`, HTTP handler | transport and collector black-box tests |
| FR-20 | Generate an SPDX 2.3 SBOM and SHA-256 release evidence | Shipped | `generate_sbom.py`, `build_release_evidence.py` | `test_supply_chain.py`, release workflow |
| FR-21 | Provide a repeatable 420-event synthetic dataset and report | Shipped | `generate_demo_data.py`, `build_report.py`, `data/`, `output/pdf/` | reproducibility check in CI |
| FR-22 | Provide local, Docker, systemd, Oracle and Azure deployment assets | Shipped and Oracle-verified | `Dockerfile`, Compose and `infra/` | container build/scan; Oracle inbound, outbound, restart, health and rotation checks |
| FR-23 | Preserve inbound public OT ports while blocking container-initiated Internet connections | Shipped and Oracle-verified | `infra/oracle/ot-sentinel-firewall`, Oracle Compose override | public port tests and outbound `TimeoutError` verification |
| FR-24 | Record live deployment evidence without publishing identifiers or raw telemetry | Shipped | `docs/LIVE_DEPLOYMENT_RECORD.md` | manual privacy review and repository secret/data checks |
| FR-25 | Fail safely on concurrent requests, body timeout and private-storage errors | Shipped | collector replay/store locks, bounded HTTP read, safe retry release | `test_collector_blackbox.py` |
| FR-26 | Document the collector API, threat model, framework decision and production hardening boundary | Shipped as documentation | OpenAPI 3.1 and collector assurance documents | contract tests and documentation review |
| FR-27 | Produce aggregate public statistics without source IDs, session IDs, addresses, payloads or individual rows | Shipped for synthetic/reviewed sanitized input | `build_public_summary.py`, `demo_summary.json` | public-summary tests, privacy validator and CI reproducibility gate |
| FR-28 | Reject collector replay after restart and atomically accept only one concurrent copy | Shipped locally | `SQLiteReplayStore`, collector verifier | storage and collector concurrency/restart tests |
| FR-29 | Deduplicate repeated observations using a private keyed fingerprint while retaining JSONL | Shipped locally | `SQLiteObservationStore`, `JsonlWriter` | repeat, expiry, concurrency, failure and database-privacy tests |
| FR-30 | Export Navigator Layer 4.5 scores from summed repeat counts | Shipped for synthetic/private local input | `export_navigator.py` | Navigator structure, order, score and privacy tests |
| FR-31 | Generate reproducible seven-day intelligence briefs without automatic observed publication | Shipped for synthetic/private local input | `generate_report.py` | empty, provenance, tie, repeat and privacy tests |
| FR-32 | Validate public records before Streamlit normalization and public STIX download | Shipped | `publication.py`, `app.py`, `stix_export.py` | end-to-end publication and STIX tests |
| FR-33 | Enforce a non-configurable 512-byte maximum received sensor payload | Shipped locally | `LowInteractionSensor` | sensor integration limit test |
| FR-34 | Monitor local readiness with privacy-safe warning and critical results | Shipped locally | `check_health.py` | health monitor tests |
| FR-35 | Explain predicted Sigma, Wazuh and Suricata matches without presenting them as native alerts | Shipped | `detection_preview.py`, `app.py` | positive and negative preview tests |
| FR-36 | Persist pending authenticated deliveries without storing transport secrets | Shipped as optional local feature | `SQLiteDeliverySpool`, `RemoteCollectorSink` | restart, retry, corruption, bounds, drain and secret-exclusion tests |
| FR-37 | Validate the collector specification with an external OpenAPI 3.1 implementation | Shipped in development/CI | pinned validator and contract | external validation test and CI command |
| FR-38 | Provide a loopback-only native Wazuh/Suricata validation path | Shipped and natively validated | `tests/soc/` | `suricata -T`, deterministic PCAP verifier, `wazuh-logtest` injector and native evidence record |
| FR-39 | Provide an exact privacy-reviewed walkthrough procedure | Checklist shipped; recording pending | `RECORDING_CHECKLIST.md` | checklist test and required human review |
| FR-40 | Fail closed before historical JSONL analysis without displaying private values | Shipped locally | `handoff.py`, `preflight_events.py` | malformed, incomplete, oversized, duplicate, schema, classification and privacy-safe error tests |
| FR-41 | Import sanitized historical observations transactionally and idempotently | Shipped locally | `SQLiteObservationStore.import_sanitized`, `import_observations.py` | restart, rerun, rollback, secret, output and database privacy tests |
| FR-42 | Persist and index sanitized historical OT Sentinel alerts in loopback-only Wazuh | Shipped and natively validated | `wazuh_ingest.py`, fixed localfile mount, Wazuh verifier | write positive, connection/read negatives, index search and post-restart validation |
| FR-43 | Produce a deterministic private final handoff and checksum manifest without automatic publication | Shipped locally | `finalize.py`, `finalize_collection.py`, handoff runbook | dry-run, classification, approval, collision, idempotence, output and manifest-safety tests |

## 6. Non-functional requirements

| ID | Requirement | Design response | Verification |
|---|---|---|---|
| NFR-01 Safety | No received content may execute or reach real equipment | Low-interaction parsers, fixed response functions, no shell/plugin hooks | protocol, profile and integration tests |
| NFR-02 Bounded input | A client cannot send unbounded session data | Configurable value with an absolute 512-byte hard cap and timeouts | sensor implementation and tests |
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
| NFR-13 Evidence integrity | Original historical JSONL must remain unchanged and every generated artifact must be checksum-verifiable | read-only input, SHA-256 preflight, transactional/atomic outputs and manifest | handoff pipeline tests and synthetic end-to-end run |
| NFR-14 Human publication control | Processing must never imply that candidate creation equals publication approval | explicit candidate flag, private output directories, publication false in manifest | approval-gate and manifest tests |

## 7. Acceptance evidence for v0.2.0

- 175 automated tests and ten subtests pass, including public/private STIX, collector-contract standards validation and local Graphify privacy configuration.
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
| FUT-04 | Host a permanent public dashboard | The current dashboard is a local application | approved hosting, cost and privacy decision plus deployment health evidence |
| FUT-05 | Complete independent analyst labeling | The current 12-case mapper fixture is a regression set, not a field benchmark | larger independently reviewed corpus and revised metrics |
| FUT-06 | Record and publish the reviewed 5–7 minute walkthrough | Exact checklist exists; no safe recording was produced automatically | reviewed native SOC evidence, green branch CI, frame-by-frame privacy review and approved URL |

## 9. Change control

A future change should update this document when it adds, removes or materially changes a requirement. A requirement should move to **Shipped** only after code and verification evidence are committed together.
