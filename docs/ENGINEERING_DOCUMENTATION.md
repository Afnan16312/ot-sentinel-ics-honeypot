# OT Sentinel Engineering Documentation

This page is the starting point for understanding exactly what OT Sentinel is, why it was built, how it works, what decisions shaped it and what evidence proves each shipped capability.

## Release fact sheet

| Item | Current state |
|---|---|
| Release | `v0.2.0` |
| Author | Mir Afnan Ali |
| Purpose | Safe OT/ICS deception, evidence analysis and defender-ready outputs |
| Simulated protocols | Modbus/TCP, Siemens S7 over ISO-on-TCP and IEC-104 |
| Public demonstration data | 420 deterministic synthetic events |
| Dashboard views | Observatory, ATT&CK Layer, Detection Preview, Triage & Validation, Session Explorer and Methodology |
| Detection formats | Sigma, Suricata and Wazuh |
| Intelligence format | STIX 2.1 public and private profiles |
| Stateful scenarios | Fictional water treatment, power substation and port crane |
| Automated verification | 173 tests and 10 subtests, Ruff, dependency audit, OpenAPI/STIX/Navigator/public-data/detection validators, CodeQL and Trivy |
| Local demonstration cost | AED 0 |
| Private live study | Active since 2026-08-19 on an isolated Oracle Cloud UAE East sensor |
| Public live observations | None; public dashboard and report remain synthetic |

## Read the documents in this order

1. [Project Walkthrough](PROJECT_WALKTHROUGH.md) explains the project in simple language and includes a demonstration script.
2. [Product Requirements and Traceability](PRODUCT_REQUIREMENTS_AND_TRACEABILITY.md) states what the project must do and points to proof that each requirement is implemented.
3. [Feature Catalogue](FEATURE_CATALOG.md) lists every shipped feature, why it exists, where it is implemented and its honest limitation.
4. [System Design](SYSTEM_DESIGN.md) explains components, data flows, boundaries, failure behavior and deployment modes.
5. [Architecture Decisions](ARCHITECTURE_DECISIONS.md) records the important engineering choices and their consequences.
6. [Problem and Solution Record](PROBLEM_SOLUTION_RECORD.md) explains the concrete problems encountered and how each one was solved.

## Supporting specialist documents

| Document | Question it answers |
|---|---|
| [Architecture](ARCHITECTURE.md) | What are the main components and trust boundaries? |
| [Threat Model](THREAT_MODEL.md) | What can go wrong and how is risk reduced? |
| [Ethics](ETHICS.md) | What safety and publication rules govern the project? |
| [Data Dictionary](DATA_DICTIONARY.md) | What does each public event field mean? |
| [Detection Engineering](DETECTION_ENGINEERING.md) | How do the Sigma, Suricata and Wazuh rules work? |
| [STIX Export](STIX_EXPORT.md) | How are public and private intelligence bundles produced? |
| [Triage and Evaluation](TRIAGE_AND_EVALUATION.md) | How is review priority calculated and mapper agreement measured? |
| [Operations](OPERATIONS.md) | How are profiles, health, alerts and remote collection operated? |
| [Collector OpenAPI](api/collector.openapi.json) | What exact requests, headers, schemas, limits and responses does the collector support? |
| [Collector Threat Model](COLLECTOR_THREAT_MODEL.md) | Which collector assets, actors, threats, controls and residual risks exist? |
| [Collector Framework ADR](ADR_020_COLLECTOR_FRAMEWORK.md) | Why does the collector remain framework-free and when should that change? |
| [Collector Hardening](COLLECTOR_HARDENING.md) | What must a future production deployment add and verify? |
| [Phase 2 Engineering Record](PHASE_2_ENGINEERING_RECORD.md) | What was added locally, why, how it is tested and what was intentionally not deployed? |
| [Phase 2 Durable-State ADR](ADR_022_PHASE_2_DURABLE_STATE_AND_GATES.md) | Why are replay, deduplication and delivery separate SQLite stores, and why is publication centralized? |
| [Safe Publication Pipeline](SAFE_PUBLICATION_PIPELINE.md) | How are aggregate-only public statistics created without individual records? |
| [SOC Integration Plan](SOC_INTEGRATION_PLAN.md) | How can Wazuh and Suricata be tested without touching the live sensor? |
| [Native SOC Validation Evidence](../tests/soc/NATIVE_VALIDATION.md) | What authoritative pinned Wazuh/Suricata positive and negative results were observed locally? |
| [Final Data Handoff](FINAL_DATA_HANDOFF.md) | How is completed private evidence checked, sanitized, analyzed and staged for local Wazuh without automatic publication? |
| [Offline Handoff ADR](ADR_023_OFFLINE_HANDOFF_AND_WAZUH_STAGING.md) | Why are immutable input, digest-named runs and sanitized-only Wazuh staging required? |
| [Final Handoff Engineering Record](FINAL_HANDOFF_ENGINEERING_RECORD.md) | What was shipped, which problems were solved and what exact verification passed? |
| [Monitoring Plan](MONITORING_PLAN.md) | Which health and capacity signals should a future monitor use? |
| [Local Health Monitoring Runbook](HEALTH_MONITORING_RUNBOOK.md) | How are synthetic/local readiness snapshots checked without exposing telemetry? |
| [Threat-Intelligence Report Template](THREAT_INTELLIGENCE_REPORT_TEMPLATE.md) | What must a reviewed research report contain? |
| [Five-Minute Demonstration Script](DEMO_SCRIPT.md) | How can the project be explained accurately and simply? |
| [Recording Checklist](RECORDING_CHECKLIST.md) | What exact 5–7 minute synthetic walkthrough must a human record and review? |
| [Deployment](DEPLOYMENT.md) | How can the system be demonstrated for free or deployed with protected credit? |
| [Live Collection Runbook](LIVE_COLLECTION_RUNBOOK.md) | What must happen before a real Internet collection study? |
| [Oracle Cloud Runbook](ORACLE_CLOUD_RUNBOOK.md) | How is the verified free-tier sensor deployed and isolated? |
| [Live Deployment Record](LIVE_DEPLOYMENT_RECORD.md) | What privacy-safe evidence proves the current sensor is operating? |
| [Competitive Analysis and Roadmap](COMPETITIVE_ANALYSIS_AND_ROADMAP.md) | How does the project compare and what remains future work? |
| [Changelog](../CHANGELOG.md) | What changed between releases? |

## The most important honesty boundary

The software, tests, dashboard, detection content, STIX export and deployment assets are real and working. A private live sensor is operating, but the included public observations remain synthetic demonstration records. OT Sentinel does not claim that observed sources are attackers or that the two-to-four-week study and publication review are complete.

That future study requires written authorization, isolated public infrastructure, an agreed retention period and a privacy review. Collection governance is documented in the [Live Collection Runbook](LIVE_COLLECTION_RUNBOOK.md), and the prepared offline closeout is in the [Final Data Handoff Runbook](FINAL_DATA_HANDOFF.md).

## One-paragraph system summary

OT Sentinel accepts at most 512 bytes per bounded request on three industrial protocol listeners and returns limited simulated responses. It writes authoritative private JSONL, can build a privacy-reduced deduplicated SQLite index and can optionally persist pending authenticated deliveries in a bounded spool. Evidence-aware MITRE ATT&CK for ICS hypotheses feed Navigator, weekly-brief, triage, STIX and defender-rule outputs. One shared fail-closed publication gate protects scripts, Streamlit and public STIX. Detection Preview remains explicitly offline, while pinned Wazuh/Suricata native evidence is recorded separately.

## Evidence standard used in these documents

A feature is described as **shipped** only when its implementation exists in the repository and there is a test, validation script, dashboard view or successful GitHub workflow that exercises it. A design file without execution evidence is described as a deployment asset, not as proof of a completed live deployment.
