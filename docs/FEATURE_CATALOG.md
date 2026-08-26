# Feature Catalog

This catalog explains what OT Sentinel ships, why each feature exists, how it works, where its evidence lives, and what it does **not** prove. It describes release `v0.2.0` plus the current deployment update.

## Collection and simulation

| ID | Feature | Why it shipped | How it works | Evidence | Boundary |
|---|---|---|---|---|---|
| F-01 | Three OT protocol listeners | A single generic port would not demonstrate protocol-aware OT telemetry. | The sensor accepts bounded TCP sessions for Modbus/TCP, Siemens S7comm, and IEC-104 and decodes selected request fields. | `src/ot_sentinel/protocols.py`, `src/ot_sentinel/sensor.py`, protocol and integration tests | It is a low-interaction simulator, not a complete PLC implementation. |
| F-02 | Safe decoy responses | A believable demo needs limited interaction without executing attacker content. | Known safe requests receive small protocol-shaped replies; malformed or unsupported input is logged and rejected. | `src/ot_sentinel/protocols.py`, `tests/test_protocols.py` | It never runs uploaded code, shell commands, or arbitrary payloads. |
| F-03 | Bounded sessions | Internet-facing parsers must limit resource use. | Connection timeouts, request-size limits, connection caps, and per-session request caps are enforced. | `src/ot_sentinel/sensor.py`, `tests/test_sensor_integration.py` | These controls reduce risk; they do not make an exposed service invulnerable. |
| F-04 | JSONL event recording | Analysts need inspectable, tool-neutral evidence. | Each decoded interaction becomes one structured JSON object with time, protocol, source, action, evidence, and mapping fields. | `src/ot_sentinel/model.py`, `src/ot_sentinel/sensor.py`, `docs/DATA_DICTIONARY.md` | Raw logs are private evidence and are not automatically safe to publish. |
| F-05 | Configurable site profiles | Fixed banners make a decoy easy to fingerprint and hard to demonstrate. | Validated JSON profiles describe water, power, and port scenarios with protocol identity and bounded in-memory state. | `profiles/`, `src/ot_sentinel/profiles.py`, `tests/test_profiles.py` | Profiles contain no scripts, executable hooks, real asset data, or persistence across restarts. |
| F-06 | Conpot log normalization | Existing Conpot output should enter the same analysis path. | A normalizer converts supported Conpot records to the project event schema. | `src/ot_sentinel/normalizer.py`, CLI import path | Normalization does not recreate evidence absent from the source record. |

## Analysis and validation

| ID | Feature | Why it shipped | How it works | Evidence | Boundary |
|---|---|---|---|---|---|
| F-07 | Evidence-aware ATT&CK for ICS mapping | Port scans alone should not become confident claims of attacker intent. | Protocol actions and decoded evidence are matched to a small reviewed technique set with confidence, rationale, and evidence text. | `src/ot_sentinel/mapper.py`, `tests/test_mapper.py` | A mapping is an analytical hypothesis, not proof of compromise, attribution, or intent. |
| F-08 | Explainable triage score | A chronological event list does not show what needs attention first. | Deterministic protocol-evidence factors produce a bounded score and label; each factor is displayed. | `src/ot_sentinel/triage.py`, `tests/test_triage.py`, `docs/TRIAGE_AND_EVALUATION.md` | Geography and identity are deliberately excluded; the score is not a risk prediction. |
| F-09 | Mapper regression benchmark | Mapping changes need a repeatable accuracy check. | Human-labeled JSONL cases are compared with mapper output and reported as TP, FP, FN, TN, precision, recall, F1, and exact agreement. | `src/ot_sentinel/evaluation.py`, `tests/fixtures/evaluation/`, `tests/test_evaluation.py` | The small curated fixture set measures regression agreement, not real-world accuracy. |
| F-10 | Session correlation | Analysts need to group several messages from one bounded connection. | Events carry session and request identifiers used by the explorer. | Event schema and dashboard session explorer | A network session is not a person or organization identity. |

## Privacy and threat-intelligence exchange

| ID | Feature | Why it shipped | How it works | Evidence | Boundary |
|---|---|---|---|---|---|
| F-11 | Public/private data gate | Raw source IPs and payloads should not leak into public artifacts. | The sanitizer pseudonymizes network identifiers, strips unsafe fields, limits text, and marks provenance. | `src/ot_sentinel/privacy.py`, `tests/test_privacy.py`, `docs/ETHICS.md` | The operator must still review jurisdiction, consent, and publication policy. |
| F-12 | Public-artifact validator | Privacy controls need a machine-checkable release gate. | The validation command rejects forbidden or unmarked content before publication. | `scripts/validate_public_data.py`, CI workflow, privacy tests | Passing validates configured rules; it is not legal approval. |
| F-13 | STIX 2.1 export | Findings should be portable beyond this dashboard. | Sanitized observations and mapped techniques become deterministic STIX bundles with public and private export profiles. | `src/ot_sentinel/stix_export.py`, `tests/test_stix_export.py`, `docs/STIX_EXPORT.md` | Custom properties are project extensions; consumers may need profile-specific handling. |
| F-14 | Explicit provenance labels | Demonstration data must not be mistaken for captured attacks. | Events and reports distinguish `synthetic`, `simulated`, and authorized `live` origins. | Data model, report generator, public-data checks | The private study does not make its observations automatically publishable. |

## Defender content

| ID | Feature | Why it shipped | How it works | Evidence | Boundary |
|---|---|---|---|---|---|
| F-15 | Sigma detections | Normalized event behaviors should be usable in SIEM workflows. | Four rules cover Modbus write activity, IEC-104 control, S7 program download, and evidence-backed remote-service exploitation. | `detections/sigma/`, `docs/DETECTION_ENGINEERING.md` | Destination SIEM field mappings may need adaptation. |
| F-16 | Suricata detections | Network defenders need protocol-level companion coverage. | Four rules use native Modbus keywords and conservative signatures. | `detections/suricata/` | Authoritative `suricata -T` validation requires a Suricata installation. |
| F-17 | Wazuh detections | The normalized JSON stream should connect to a common open-source SOC platform. | A level-zero parent and four alert rules match selected behaviors. | `detections/wazuh/` | Wazuh decoder and MITRE database versions can change destination behavior. |
| F-18 | Offline detection validator | Contributors need useful checks without installing three security engines. | A standard-library validator checks pack structure and positive, negative, and all-negative fixtures. | `scripts/validate_detections.py`, `tests/test_detections.py` | Semantic checks do not replace engine-native validation. |

## Dashboard and reporting

| ID | Feature | Why it shipped | How it works | Evidence | Boundary |
|---|---|---|---|---|---|
| F-19 | Observatory | A demo needs an immediate operational summary. | Streamlit shows event volume, protocol mix, trends, geographic visualization, and recent activity. | `app.py` | Demo geography is synthetic and must not be read as observed attacker origin. |
| F-20 | ATT&CK layer | Technique mappings should be inspectable rather than hidden in logs. | The dashboard aggregates mapped techniques and exposes confidence and rationale. | `app.py`, mapper tests | Counts reflect the selected dataset and mapping rules only. |
| F-21 | Triage and validation | Review priority and mapping quality belong beside the visualization. | The page shows score factors, queue distribution, benchmark totals, and per-technique metrics. | `app.py`, evaluation/triage tests | Perfect fixture agreement is not a general performance claim. |
| F-22 | Session explorer | A reviewer needs to trace a finding back to the underlying messages. | Filters and session views connect summarized activity to individual normalized events. | `app.py` | It does not perform attribution or identity resolution. |
| F-23 | Methodology page | Viewers need the evidence boundary inside the application. | The dashboard explains architecture, ethics, provenance, and limitations. | `app.py` | The repository documentation remains the authoritative detail. |
| F-24 | Reproducible demonstration dataset | The project must be demonstrable before any authorized deployment. | A seeded generator creates 420 deterministic, explicitly synthetic events. | `scripts/generate_demo_data.py`, `data/demo_events.jsonl` | Synthetic data cannot support regional threat-intelligence conclusions. |
| F-25 | PDF report pipeline | The analysis should be convertible into a readable research artifact. | The report builder aggregates a validated dataset and labels its source status. | `scripts/build_report.py`, `output/pdf/` | A quarterly live report remains a future milestone pending authorized collection. |

## Operations, deployment, and supply chain

| ID | Feature | Why it shipped | How it works | Evidence | Boundary |
|---|---|---|---|---|---|
| F-26 | Windows one-command launcher | The Python launcher may not exist on a new Windows machine. | `run_dashboard.ps1` discovers `py`, `python`, or a standard Python 3.12 path, creates `.venv`, installs missing dependencies, and launches Streamlit. | `run_dashboard.ps1` | Python must still be installed; first setup needs package-download access. |
| F-27 | Health and operational metrics | A running process needs observable status. | The operations layer tracks bounded counters, health state, and safe status information. | `src/ot_sentinel/operations.py`, `tests/test_operations.py` | It is intentionally lightweight, not a replacement for a full observability platform. |
| F-28 | Bounded webhook alerts | Important events should be forwarded without blocking collection. | High-confidence/high-severity sanitized notices enter a capped queue with deduplication, retry, backoff, and drop metrics. | `src/ot_sentinel/operations.py`, operations tests | Delivery is best effort; JSONL remains the primary evidence record. |
| F-29 | Authenticated remote collector | Multiple sensors need a safer central-ingestion option. | TLS plus HMAC-signed envelopes, timestamps, size limits, replay rejection and privacy-safe storage errors protect the receiver interface. | collector/transport code, black-box and transport tests, OpenAPI contract | Key distribution, rate limiting, durable storage and certificate lifecycle remain operator responsibilities. |
| F-30 | Local, Docker, service, and cloud templates | The project should work free locally and support an isolated study. | Runbooks and configuration cover local execution, hardened Docker, systemd, verified Oracle deployment and optional Azure infrastructure. | `Dockerfile`, `docker-compose.yml`, `infra/`, `docs/DEPLOYMENT.md` | Cloud eligibility and price can change; cloud is not required for the portfolio demonstration. |
| F-31 | Automated quality and security gates | Published code should carry repeatable evidence. | CI runs tests and validation; CodeQL, dependency review, secret scanning, and container scanning cover common release risks. | `.github/workflows/`, `tests/` | Automated scanning reduces risk but cannot prove the absence of vulnerabilities. |
| F-32 | Reproducible release evidence | Users should be able to inspect what was shipped. | The release workflow produces an SBOM, checksums, validation outputs, and signed provenance for the container artifact path. | release workflow and GitHub release assets | Evidence applies to the exact released revision and workflow environment. |
| F-33 | Oracle host lifecycle and egress guard | The public sensor must survive restart without becoming an outbound foothold. | systemd restores a dedicated Docker edge bridge and `DOCKER-USER` egress policy before starting Compose; logrotate bounds local growth. | `infra/oracle/`, `docs/ORACLE_CLOUD_RUNBOOK.md`, deployment invariant tests | The firewall helper targets Docker's iptables backend and must be revalidated after upgrades. |
| F-34 | Privacy-safe deployment evidence | Recruiters and reviewers need proof of operation without seeing sensitive telemetry. | A dated record captures configuration, verification results and aggregate counts while excluding identifiers and payloads. | `docs/LIVE_DEPLOYMENT_RECORD.md` | Aggregate evidence is not a threat-intelligence conclusion or attacker attribution. |
| F-35 | Aggregate-only public summary | Dashboard and report preparation should not require publishing individual event rows. | A fail-closed builder validates a sanitized candidate and emits only dates and aggregate counts; CI reproduces the synthetic result. | `scripts/build_public_summary.py`, `data/demo_summary.json`, public-summary tests | Live publication still requires a separate human privacy and methodology review. |
| F-36 | Durable replay and observation deduplication | Restarts must not reopen the replay window or inflate scanner analysis rows. | Separate SQLite stores atomically reserve replay keys and aggregate keyed 30-minute fingerprints while retaining salted source IDs and confidence evidence. | `storage.py`, storage tests | Databases are private auxiliary state; JSONL remains authoritative. |
| F-37 | ATT&CK Navigator Layer 4.5 export | Analysts need a portable heat layer whose scores represent repeated observations. | The exporter sums `repeat_count`, validates ICS technique IDs and emits deterministic synthetic or ignored private layers. | `export_navigator.py`, Navigator tests and synthetic layer | Technique frequency is not proof of compromise or intent. |
| F-38 | Weekly intelligence brief generator | A collection window needs a reproducible review artifact before publication. | A seven-day SQLite query produces Markdown protocol, technique, confidence, session and pseudonym summaries. | `generate_report.py`, report tests and synthetic example | Observed reports remain ignored/private and require human approval. |
| F-39 | Disposable native SOC lab and evidence | Static checks cannot prove Wazuh/Suricata runtime behavior. | A pinned loopback-only Compose harness, synthetic injector and PCAP verifier run authoritative positive/negative checks. | `tests/soc/`, harness tests, `NATIVE_VALIDATION.md` | Validated for pinned Wazuh 4.14.7/Suricata 8.0.4 only; re-run after rule or engine changes. |
| F-40 | Shared end-to-end publication gate | Multiple validators can drift and expose different fields. | Scripts, Streamlit and public STIX share recursive field/address/provenance validation; STIX is checked again before download. | `publication.py`, privacy/publication/STIX tests | Passing the technical gate is not legal or methodology approval. |
| F-41 | Local readiness monitor | Operators need machine-readable stale, disk, queue, delivery and storage states. | A local snapshot checker emits redacted text/JSON and distinct warning/critical codes. | `check_health.py`, health-monitor tests and runbook | No monitoring service was installed on Oracle or any cloud resource. |
| F-42 | Detection Preview | Dashboard users need to understand defender-rule intent beside sanitized events. | Existing offline Sigma/Wazuh/Suricata matchers produce filterable rule, severity, technique and evidence explanations. | `detection_preview.py`, `app.py`, preview tests | Predictions are not native-engine alerts. |
| F-43 | Durable collector delivery spool | Temporary receiver outages and restarts should not discard pending forwards. | An optional row/byte-bounded SQLite spool persists events, signs only at transmission, retries with bounded backoff and reports age/depth. | `transport.py`, delivery-spool tests | Disabled by default and not deployed to the Oracle sensor. |
| F-44 | External OpenAPI 3.1 validation | JSON parsing and semantic assertions do not prove standards validity. | A pinned development-only validator runs in pytest and GitHub Actions. | `test_openapi_validation.py`, CI | The validator is not a sensor runtime dependency. |
| F-45 | Exact recording checklist | A safe public walkthrough needs repeatable timing and privacy review. | A 6:15 storyboard covers architecture, dashboard, Navigator, security tests, native SOC evidence and CI. | `RECORDING_CHECKLIST.md`, checklist test | Actual recording, review, upload and URL remain human actions. |
| F-46 | Historical evidence preflight | A damaged or mixed JSONL file must not silently enter analysis. | A bounded-record command reports checksums and aggregate diagnostics while rejecting malformed, incomplete, oversized, duplicate or unexpected records without printing values. | `handoff.py`, `preflight_events.py`, handoff tests | It validates the current event schema; an intentional schema change must update it. |
| F-47 | Transactional historical analysis import | Re-running or interrupting final processing must not inflate or partially write the analysis index. | A private import ledger and one SQLite transaction make sanitized event-ID ingestion idempotent and restart-safe. | `storage.py`, `import_observations.py`, handoff tests | The SQLite index is auxiliary private analysis; original JSONL remains authoritative. |
| F-48 | Persistent local Wazuh ingestion | Native rule tests alone do not prove alerts can be stored and searched. | A privacy-gated two-phase staging ledger appends validated JSON once to a read-only mounted file; manager and indexer verification confirms persistence. | `wazuh_ingest.py`, `tests/soc/`, native evidence | Local pinned lab only; it is never connected to Oracle and destination changes require revalidation. |
| F-49 | Deterministic final handoff processor | End-of-study steps are easy to run out of order or publish accidentally. | One command builds private sanitized, SQLite, Wazuh, report, Navigator and manifest outputs; public candidates require a separate flag and remain unpublished. | `finalize.py`, `finalize_collection.py`, `FINAL_DATA_HANDOFF.md` | Human shutdown, backup, legal/privacy review and any publication remain manual. |
| F-50 | Interactive geographic investigation workspace | A static world chart cannot support geographic comparison or source drill-down. | Four MapLibre modes add bounded flow paths, selectable source bubbles, density, UTC playback, time windows, camera controls, safe country focus, coverage auditing and allowlisted aggregate CSV export. | `dashboard_map.py`, `app.py`, dashboard tests, `INTERACTIVE_MAP_REDESIGN.md` | Coordinates are coarse, flow lines do not prove routes or attribution, and committed data remains synthetic. |
| F-51 | Map investigation and resilience pass | Analysts need a clear, reversible path from a map point to evidence, and the UI must remain useful on restricted networks. | Confidence, triage and control filters; custom UTC windows; previous-window comparison; repeat counts; accessible source selection; selected-source timeline and evidence badges; local review notes; detection coverage; aggregate view manifests; reversible country focus; and tile-free geographic fallback. | `app.py`, `dashboard_map.py`, `tests/test_dashboard_app.py`, `tests/test_dashboard_map.py`, `INTERACTIVE_MAP_REDESIGN.md` | Review notes are session-local; the fallback is an approximation for disconnected use; no feature makes attribution or intent claims. |

## Main commands

```powershell
# Easiest Windows dashboard launch
.\run_dashboard.ps1

# Run the low-interaction sensor with default safe ports
python -m ot_sentinel.sensor --profile profiles/water-treatment.yaml

# Create deterministic demo data
python scripts/generate_demo_data.py

# Validate defender content
python scripts/validate_detections.py

# Run the automated test suite
python -m pytest -q
```

See [PROJECT_WALKTHROUGH.md](PROJECT_WALKTHROUGH.md) for a presentation script and [DEPLOYMENT.md](DEPLOYMENT.md) for exact setup choices.
