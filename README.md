# OT Sentinel

**I built OT Sentinel as a safe, simulated industrial-system honeypot that records suspicious activity and turns it into an easy-to-read security dashboard.**

[![CI](https://github.com/Afnan16312/ot-sentinel-ics-honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/Afnan16312/ot-sentinel-ics-honeypot/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-6f9fc4.svg)](https://www.python.org/)
[![MITRE ATT&CK for ICS](https://img.shields.io/badge/MITRE-ATT%26CK%20for%20ICS-f4b860.svg)](https://attack.mitre.org/matrices/ics/)

> **Honest data notice:** The public dashboard uses clearly labeled, computer-generated demonstration data. A separate isolated Oracle Cloud sensor began a private live collection on 2026-08-19, but no unreviewed live record is published or presented as attacker activity. See the [privacy-safe deployment record](docs/LIVE_DEPLOYMENT_RECORD.md).

![OT Sentinel interactive geographic investigation workspace](docs/assets/dashboard.png)

## Project author

OT Sentinel is my OT/ICS security research project.

**Mir Afnan Ali** · [GitHub profile](https://github.com/Afnan16312) · [Project repository](https://github.com/Afnan16312/ot-sentinel-ics-honeypot)

## What I built

Factories, power plants and water facilities use industrial control systems (ICS) to operate equipment. Exposing a real control system to the internet would be unsafe, so I created OT Sentinel to provide harmless decoys that look like common industrial devices.

My system then:

1. Listens for traffic aimed at simulated Modbus, S7 and IEC-104 services.
2. Records what was attempted without controlling any real equipment.
3. Describes the behavior using MITRE ATT&CK for ICS, a well-known security framework.
4. Removes sensitive details before anything is made public.
5. Displays trends, locations, techniques and sessions in an interactive dashboard.
6. Exports portable STIX intelligence and tested Sigma, Suricata and Wazuh rules.
7. Prioritizes stronger events with an explainable risk score and review queue.
8. Keeps replay and pending delivery state across local restarts using optional bounded SQLite stores.
9. Generates a synthetic ATT&CK Navigator layer and weekly intelligence brief.
10. Prepares an immutable, checksum-led final handoff for private SQLite analysis and persistent local Wazuh ingestion.
11. Provides an interactive four-mode geographic investigation workspace with privacy-safe source drill-down and time playback.

## Why it matters

OT/ICS security protects services people depend on, including electricity, water, ports and manufacturing. I chose this project to develop practical skills in secure system design, industrial network protocols, threat analysis, privacy engineering, cloud deployment, automated testing and security reporting.

The repository includes the complete source code, a working dashboard, automated tests, deployment files, a verified Oracle Cloud runbook and a five-page [demonstration research report](output/pdf/ot-sentinel-demonstration-report.pdf).

I also documented how OT Sentinel compares with established honeypot projects and which practical security features should come next in the [competitive analysis and roadmap](docs/COMPETITIVE_ANALYSIS_AND_ROADMAP.md).

For the complete record of requirements, shipped features, engineering decisions, system design, and solved problems, start with the [engineering documentation](docs/ENGINEERING_DOCUMENTATION.md).

Development uses the optional, local-only [Ponytail and Graphify workflow](docs/DEVELOPER_ASSISTANTS.md); neither tool runs on the Oracle sensor.

## What is included in version 0.2

| Feature | Plain-language purpose |
|---|---|
| Stateful device profiles | Three fictional water, power and port scenarios respond consistently without controlling equipment |
| Detection rules | Ready-to-review examples for Sigma, Suricata and Wazuh |
| STIX 2.1 export | Moves sanitized findings into a standard threat-intelligence format |
| Triage and validation | Shows which sessions deserve attention and why, then measures mapper agreement against labeled examples |
| Health and alerts | Records sensor health and can send only redacted, high-confidence notifications |
| Multi-sensor collector | Accepts authenticated events from isolated sensors over encrypted transport |
| Release evidence | Produces an SPDX software bill of materials and SHA-256 file checksums |
| Isolated live deployment | Reproduces the Oracle ARM64 service, restart, firewall and log-retention controls without publishing private telemetry |

## Phase 2 enhancements on this feature branch

| Enhancement | Plain-language purpose |
|---|---|
| Durable replay protection | A resent collector event remains rejected after a local collector restart |
| Scanner deduplication | Repeated identical requests increment a count instead of creating misleading duplicate analysis rows |
| Navigator and weekly brief | Synthetic/private SQLite analysis becomes a heat layer and a reproducible seven-day Markdown summary |
| Shared publication safety gate | Streamlit, public summaries and public STIX reject raw addresses, prefixes, payloads, credentials and mixed provenance |
| Detection Preview | Shows which Sigma, Wazuh and Suricata rules would match, clearly labeled as an offline prediction |
| Local readiness monitor | Reports stale health, disk, queue, delivery and storage conditions without echoing telemetry |
| Durable delivery spool | Optionally preserves pending collector forwards across restarts without storing HMAC secrets |
| Standards validation | CI validates the collector contract with a pinned OpenAPI 3.1 implementation |
| Final data handoff | Safe preflight, transactional SQLite import, Wazuh staging and a checksum manifest prepare the completed study without automatic publication |
| Interactive threat map | Compares bounded flow paths, source bubbles, density and UTC playback, then opens a privacy-safe source investigation summary |

The disposable loopback-only Wazuh 4.14.7/Suricata 8.0.4 lab passed native positive and negative checks with synthetic fixtures; see the privacy-safe [native validation evidence](tests/soc/NATIVE_VALIDATION.md). The exact [recording checklist](docs/RECORDING_CHECKLIST.md) is ready, but no public video is claimed yet.

The [final data handoff runbook](docs/FINAL_DATA_HANDOFF.md) prepares the offline workflow for the end of the authorized collection. It does not connect Wazuh to Oracle, publish observed records or replace the synthetic dashboard.

## Current live-study status

The software is now operating on an isolated, Always Free-eligible Oracle Cloud VM in the UAE East (Dubai) region. The container survived the restart test, all three decoy ports responded, outbound container initiation was blocked, health remained `ok` overnight and log rotation was verified.

That deployment proves operation, not attacker identity or compromise. The first privacy-safe counts are recorded in [LIVE_DEPLOYMENT_RECORD.md](docs/LIVE_DEPLOYMENT_RECORD.md); raw JSONL remains private. The hosted Streamlit dashboard still displays only the deterministic synthetic dataset.

## Try the dashboard

You need Python 3.12 or newer.

On Windows, open PowerShell in the project folder and run the included launcher:

```powershell
.\run_dashboard.ps1
```

The launcher creates the local environment, installs anything missing and starts the dashboard. If Windows blocks local PowerShell scripts, use:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_dashboard.ps1
```

On Linux or macOS, run:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Streamlit opens the dashboard in your browser with the included demonstration data.

The observatory map supports zoom, pan, fullscreen, country focus, four analytical modes and a reviewed aggregate CSV export. The dashboard uses a Stitch-inspired light workstation layout with a fixed analysis rail, compact status header, filter chips and responsive KPI/map cards. Its design decisions, privacy contract, interaction model and QA evidence are documented in [Interactive Threat Map Redesign](docs/INTERACTIVE_MAP_REDESIGN.md).

## Run the honeypot locally

```bash
pip install -e .
python -m ot_sentinel.sensor --profile profiles/water-treatment.yaml
```

It listens on safe local test ports:

| Simulated service | Local port | Standard Docker/cloud port |
|---|---:|---:|
| Modbus/TCP | 1502 | 502 |
| Siemens S7 / ISO-on-TCP | 1102 | 102 |
| IEC-104 | 2404 | 2404 |

Docker users can run the complete sensor with:

```bash
docker compose up -d --build
docker compose logs -f
```

## How the pieces connect

```mermaid
flowchart LR
    A[Internet scanner] --> B[Safe industrial decoy]
    B --> C[Protocol evidence]
    C --> D[ATT&CK mapping and triage]
    D --> E[Detection and STIX outputs]
    D --> F[Privacy filter]
    F --> G[Public dashboard and report]
```

I designed the ATT&CK mapper to be intentionally cautious. A simple connection is not called an exploit. Stronger labels are added only when the recorded command provides supporting evidence, and every label includes a confidence level and explanation.

## My safety and ethics rules

- The honeypot never connects to a real PLC, HMI or industrial process.
- Responses are limited, simulated and designed not to become a general-purpose server.
- The project does not retaliate, identify people or make attribution claims.
- Raw IP addresses and payloads are excluded from the public repository.
- The verified Oracle design limits exposed ports, restricts SSH to the operator, blocks new container egress and preserves private logs locally.
- This is research tooling, not proof of NESA compliance or a production security control.

Read [ETHICS.md](docs/ETHICS.md) before any public deployment.

## Cost

I designed the project so it can be developed and demonstrated locally for free. GitHub, Docker, Python and Streamlit Community Cloud can be used without a project service fee. The current sensor uses an Oracle shape marked Always Free-eligible and stays inside the documented compute and storage allowance; eligibility, capacity and pricing can change, so Cost Analysis still needs daily review. The [deployment guide](docs/DEPLOYMENT.md) explains the cost boundary.

## Test the project

```bash
pip install -e .
python -m pytest -q -p no:cacheprovider
python -m ruff check .
python scripts/validate_detections.py
python scripts/validate_public_data.py data/demo_events.jsonl
python -m openapi_spec_validator docs/api/collector.openapi.json
```

The public-data check helps prevent accidental publication of raw IP addresses, raw payloads or unlabeled demonstration records.

The aggregate-only dashboard summary can also be reproduced without exposing individual rows:

```bash
python scripts/build_public_summary.py data/demo_events.jsonl data/demo_summary.json
```

Other useful commands:

```bash
ot-sentinel validate-profile profiles/water-treatment.yaml
ot-sentinel evaluate-mapper --fixtures tests/fixtures/evaluation/mapper_cases.jsonl
export OT_PRIVACY_SALT='replace-with-a-private-random-value'
ot-sentinel export-stix data/demo_events.jsonl artifacts/public-stix.json --profile public
```

## Repository guide

| Location | Purpose |
|---|---|
| `app.py` | Interactive Streamlit dashboard |
| `src/ot_sentinel/` | Honeypot, protocol parsers, ATT&CK mapper and privacy tools |
| `profiles/` | Validated fictional water, power and port device profiles |
| `detections/` | Sigma, Suricata and Wazuh detection content plus fixtures |
| `data/` | Clearly labeled synthetic demonstration events |
| `tests/` | Automated unit and integration tests |
| `infra/` | Docker, Oracle Cloud, Azure and Linux service deployment assets |
| `docs/` | Architecture, ethics, data and deployment explanations |
| `docs/ENGINEERING_DOCUMENTATION.md` | Index to requirements, features, decisions, system design and solved problems |
| `docs/PROJECT_WALKTHROUGH.md` | Simple step-by-step explanation and demonstration guide |
| `docs/OPERATIONS.md` | Health, alerting and authenticated collector instructions |
| `docs/ORACLE_CLOUD_RUNBOOK.md` | Exact verified Oracle deployment, isolation and recovery procedure |
| `docs/LIVE_DEPLOYMENT_RECORD.md` | Privacy-safe evidence that the live sensor is operating |
| `docs/DETECTION_ENGINEERING.md` | Detection logic, testing and deployment notes |
| `docs/SAFE_PUBLICATION_PIPELINE.md` | Aggregate-only synthetic pipeline and future publication gates |
| `docs/SOC_INTEGRATION_PLAN.md` | Safe offline Wazuh and Suricata integration phases |
| `docs/FINAL_DATA_HANDOFF.md` | Exact private preflight, analysis, Wazuh and final-review procedure |
| `docs/MONITORING_PLAN.md` | Future health, capacity and privacy-monitoring design |
| `docs/THREAT_INTELLIGENCE_REPORT_TEMPLATE.md` | Privacy-reviewed live-study report structure |
| `docs/DEMO_SCRIPT.md` | Simple five-minute explanation for project demonstrations |
| `docs/RECORDING_CHECKLIST.md` | Exact synthetic-only 5–7 minute recording and privacy-review procedure |
| `docs/INTERACTIVE_MAP_REDESIGN.md` | Map gap analysis, shipped interactions, privacy controls and QA matrix |
| `docs/PRODUCT_GAP_ANALYSIS.md` | Comprehensive user pain-point audit and prioritized map/product roadmap |
| `docs/USER_RESEARCH_AND_FEATURE_STRATEGY.md` | Detailed user personas, jobs, pain points, problem statements, minor/major feature backlog and validation plan |
| `docs/PHASE_2_ENGINEERING_RECORD.md` | Phase 2 decisions, features, tests, limitations and non-deployment record |
| `docs/HEALTH_MONITORING_RUNBOOK.md` | Local privacy-safe readiness checker instructions |
| `docs/STIX_EXPORT.md` | Public and private STIX export rules |
| `docs/COMPETITIVE_ANALYSIS_AND_ROADMAP.md` | Project comparison and zero-cost improvement plan |
| `output/pdf/` | Demonstration threat-intelligence report |

## Important limitations

IP location is approximate, a cloud region is only the sensor's location, and honeypot results depend on exposure time and realism. ATT&CK mappings are analyst hypotheses, not proof of compromise or attacker identity. These limitations are shown in the dashboard and report.

## License

The project code is available under the MIT License. MITRE ATT&CK is a registered trademark of The MITRE Corporation.
