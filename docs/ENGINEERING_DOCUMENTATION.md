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
| Dashboard views | Observatory, ATT&CK Layer, Triage & Validation, Session Explorer and Methodology |
| Detection formats | Sigma, Suricata and Wazuh |
| Intelligence format | STIX 2.1 public and private profiles |
| Stateful scenarios | Fictional water treatment, power substation and port crane |
| Automated verification | 49 tests, two STIX validation subtests, Ruff, dependency audit, CodeQL and Trivy |
| Local demonstration cost | AED 0 |

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
| [Deployment](DEPLOYMENT.md) | How can the system be demonstrated for free or deployed with protected credit? |
| [Live Collection Runbook](LIVE_COLLECTION_RUNBOOK.md) | What must happen before a real Internet collection study? |
| [Competitive Analysis and Roadmap](COMPETITIVE_ANALYSIS_AND_ROADMAP.md) | How does the project compare and what remains future work? |
| [Changelog](../CHANGELOG.md) | What changed between releases? |

## The most important honesty boundary

The software, tests, dashboard, detection content, STIX export and deployment assets are real and working. The included public observations are synthetic demonstration records. OT Sentinel does not currently claim that it captured real UAE attackers or completed a two-to-four-week public study.

That future study requires written authorization, isolated public infrastructure, an agreed retention period and a privacy review. The exact process is documented in the [Live Collection Runbook](LIVE_COLLECTION_RUNBOOK.md).

## One-paragraph system summary

OT Sentinel accepts bounded network requests on three industrial protocol listeners and returns limited simulated responses. It converts each interaction into a structured event, applies evidence-aware MITRE ATT&CK for ICS hypotheses and calculates an explainable review priority. Private events can remain in JSONL, be sent to an authenticated collector or trigger a narrowly selected redacted alert. Before publication, source identifiers and payloads are removed or pseudonymized. Sanitized events can be viewed in Streamlit, exported as STIX 2.1 and converted into tested Sigma, Suricata and Wazuh detection content.

## Evidence standard used in these documents

A feature is described as **shipped** only when its implementation exists in the repository and there is a test, validation script, dashboard view or successful GitHub workflow that exercises it. A design file without execution evidence is described as a deployment asset, not as proof of a completed live deployment.
