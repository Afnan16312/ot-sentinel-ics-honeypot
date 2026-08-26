# Changelog

## Unreleased

- Added privacy-scoped Ponytail and local code-only Graphify developer tooling; generated graphs and all telemetry/private runtime paths remain ignored.
- Added a fail-closed historical JSONL preflight, transactional idempotent privacy-reduced import, deterministic final handoff processor and privacy-safe checksum manifest.
- Added persistent sanitized-only local Wazuh ingestion with a restart-safe staging ledger, indexed positive/negative verification and post-manager-restart evidence; no Oracle integration was added.
- Added the beginner final-data-handoff runbook and ADR covering immutable input, human publication gates and the Suricata packet/JSON boundary.
- Added durable SQLite replay reservations, privacy-reduced scanner deduplication and an optional bounded delivery spool while retaining JSONL as authoritative evidence.
- Added deterministic ATT&CK Navigator Layer 4.5 and seven-day Markdown intelligence generators with synthetic committed examples and ignored private outputs.
- Added and natively validated a loopback-only disposable Wazuh 4.14.7/Suricata 8.0.4 lab: four Suricata rules load, SID 4200501 fires only for the synthetic write, and Wazuh rule 110001 stays quiet for connection/read negatives.
- Consolidated public validation into the package, removed strict-public network prefixes, recursively strips credential-like data and gives Streamlit and public STIX independent fail-closed gates.
- Enforced an absolute 512-byte sensor payload ceiling and a 32-character minimum private pseudonymization salt.
- Added a privacy-safe local health monitor, Streamlit Detection Preview and queue readiness metrics.
- Added pinned external OpenAPI 3.1 validation to development dependencies and CI; sensor runtime dependencies remain empty.
- Added the exact synthetic-only recording checklist; the reviewed video remains a human deliverable and no video link is claimed.
- Added synthetic black-box collector assurance tests for authentication, replay, malformed HTTP, concurrency, timeout, storage failure, privacy and shutdown.
- Added a machine-readable OpenAPI 3.1 collector contract, dedicated threat model, framework ADR and operational hardening guide.
- Added privacy-safe collector error handling, media/length enforcement and retry release after failed storage.
- Added branch-level CI, aggregate-only public-summary generation, stricter network-prefix validation and synthetic pipeline tests.
- Added offline SOC integration, monitoring, report-template and five-minute demonstration guides.
- Added the verified Oracle Cloud ARM64 deployment override, systemd unit, outbound firewall guard and log-rotation policy.
- Added a complete Oracle Cloud free-tier runbook and privacy-safe live deployment record.
- Recorded the Docker 29 internal-network port-publication problem, its bounded edge-network solution and validation evidence.
- Updated project requirements, architecture decisions, operations and honesty notices for the active private collection.

## 0.2.0 - 2026-08-17

- Added Sigma, Suricata and Wazuh detection packs with offline regression fixtures.
- Added privacy-separated STIX 2.1 exports.
- Added explainable event triage and ATT&CK mapper evaluation.
- Added safe stateful water, power and port profiles.
- Added health snapshots, selective redacted alerts and signed multi-sensor collection.
- Added SPDX SBOM and release checksum generation, dependency review, dependency and container audits, Ruff and CodeQL.
- Expanded the dashboard and operational documentation.

## 0.1.0

- Initial low-interaction sensor, privacy pipeline, dashboard, synthetic dataset, tests, report and deployment assets.
