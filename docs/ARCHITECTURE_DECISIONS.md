# Architecture Decision Record

This file records the major decisions behind OT Sentinel `v0.2.0`. Each decision is accepted unless marked otherwise. The goal is to preserve **why** the system looks this way, not merely describe the code.

## Decision summary

| ADR | Decision | Main reason |
|---|---|---|
| ADR-001 | Build a custom low-interaction sensor | Keep behavior auditable, bounded, and easy to run |
| ADR-002 | Keep the sensor core on the Python standard library | Minimize exposed dependencies and deployment friction |
| ADR-003 | Use separate Modbus, S7, and IEC-104 entry points | Preserve protocol context and operational separation |
| ADR-004 | Bound all untrusted input and interaction | Reduce denial-of-service and payload-execution risk |
| ADR-005 | Use append-only JSONL as primary evidence | Make records durable, inspectable, and portable |
| ADR-006 | Map ATT&CK techniques only from explicit evidence | Avoid overstating attacker intent |
| ADR-007 | Separate private evidence from public artifacts | Protect IP addresses, payloads, and sensitive context |
| ADR-008 | Ship synthetic data until live collection is authorized | Keep the project demonstrable without false claims |
| ADR-009 | Make triage deterministic and explainable | Ensure review priority can be audited |
| ADR-010 | Ship portable defender content | Let findings transfer to common SOC tools |
| ADR-011 | Offer public and private STIX profiles | Balance sharing with investigative fidelity |
| ADR-012 | Use declarative JSON site profiles | Add realism without executable configuration |
| ADR-013 | Make alerts bounded and secondary to local evidence | Protect collection when integrations fail |
| ADR-014 | Authenticate remote ingestion with TLS and HMAC | Add confidentiality, integrity, freshness, and replay defense |
| ADR-015 | Use Streamlit for the dashboard | Deliver a readable Python-native interface at zero service cost |
| ADR-016 | Do not require ELK or Wazuh to run the project | Preserve a free, low-resource default path |
| ADR-017 | Treat CI and release evidence as product features | Make security and reproducibility visible |
| ADR-018 | Keep public-cloud deployment optional | Avoid making paid infrastructure a prerequisite |

## ADR-001 — Custom low-interaction sensor

**Context.** Conpot is useful, but requiring its full runtime would add dependencies and make the security boundary harder to explain in a compact portfolio project.

**Decision.** Implement a small custom Python sensor, while retaining a Conpot normalizer for interoperability.

**Why.** The project can expose only reviewed behaviors, test its parsing directly, and run on an ordinary laptop.

**Consequences.** The simulator is easier to audit but less realistic than a high-interaction PLC. It must never be presented as a complete industrial controller.

**Evidence.** `src/ot_sentinel/sensor.py`, `src/ot_sentinel/protocols.py`, `src/ot_sentinel/normalizer.py`.

## ADR-002 — Standard-library sensor core

**Context.** Internet-facing code inherits risk and maintenance work from every runtime dependency.

**Decision.** Use Python's standard library for the sensor, parser, transport, and core analysis paths; keep dashboard libraries outside the exposed listener path.

**Why.** This reduces installation friction and supply-chain surface while keeping the code approachable.

**Consequences.** Some conveniences are implemented locally. Streamlit, pandas, and Plotly are still required for visualization.

**Evidence.** `pyproject.toml`, `requirements.txt`, module imports, supply-chain tests.

## ADR-003 — Separate protocol entry points

**Context.** Modbus/TCP, S7comm, and IEC-104 have different framing, evidence, and default ports.

**Decision.** Give each protocol its own configurable listener and decoder, then normalize outputs into one event model.

**Why.** Separation preserves protocol meaning while providing a common downstream pipeline.

**Consequences.** There are more ports and parser branches to test, but failures remain isolated and mappings retain protocol context.

**Evidence.** `src/ot_sentinel/protocols.py`, `src/ot_sentinel/sensor.py`, protocol tests.

## ADR-004 — Bounded interaction

**Context.** Any public listener receives malformed, oversized, slow, or intentionally hostile traffic.

**Decision.** Enforce timeouts, message and session limits, connection caps, and small allowlisted replies. Never execute payloads or emulate a shell.

**Why.** A honeypot must not become a convenient foothold or uncontrolled resource sink.

**Consequences.** Some real clients and attacker sequences will be truncated. Safety takes priority over maximum interaction depth.

**Evidence.** Sensor configuration, integration tests, [THREAT_MODEL.md](THREAT_MODEL.md).

## ADR-005 — Append-only JSONL evidence

**Context.** The project needs a storage format that works without a database and can later feed a SIEM.

**Decision.** Write one structured event per line as the authoritative local record.

**Why.** JSONL is inspectable, append-friendly, streamable, easy to test, and compatible with many ingestion tools.

**Consequences.** Large deployments will need rotation, retention, integrity controls, and perhaps a central store. The local file is not an analytics database.

**Evidence.** Event model, sensor writer, [DATA_DICTIONARY.md](DATA_DICTIONARY.md).

## ADR-006 — Evidence-aware ATT&CK mapping

**Context.** Treating every connection as exploitation creates misleading threat intelligence.

**Decision.** Map only decoded, defined behaviors; attach confidence, rationale, and evidence; allow an event to remain unmapped.

**Why.** Honest uncertainty is more useful than a visually impressive but unsupported technique count.

**Consequences.** Coverage is intentionally conservative. New mappings require evidence rules and regression cases.

**Evidence.** `src/ot_sentinel/mapper.py`, mapper tests, evaluation fixtures.

## ADR-007 — Public/private separation

**Context.** Source addresses, raw payloads, and operator notes can create privacy, legal, and operational risk.

**Decision.** Keep raw JSONL private. Publish only sanitized records that pass an automated public-data validation gate.

**Why.** Research transparency should not expose unnecessary identifiers or unsafe content.

**Consequences.** Public artifacts lose some investigative detail. Operators remain responsible for legal review and retention policy.

**Evidence.** `src/ot_sentinel/privacy.py`, `scripts/validate_public_data.py`, [ETHICS.md](ETHICS.md).

## ADR-008 — Synthetic-first demonstration

**Context.** A useful demo is needed before any public exposure has been safely authorized and operated.

**Decision.** Ship a deterministic synthetic dataset and label it prominently. Make live collection a separate operational phase.

**Why.** Anyone can evaluate the pipeline without cloud spend, exposed ports, or fabricated claims about attackers.

**Consequences.** The current repository cannot support conclusions about actual UAE attacker activity.

**Evidence.** `scripts/generate_demo_data.py`, `data/sample_events.jsonl`, [LIVE_COLLECTION_RUNBOOK.md](LIVE_COLLECTION_RUNBOOK.md).

## ADR-009 — Deterministic, explainable triage

**Context.** A hidden or identity-driven score would be difficult to defend and could encode irrelevant bias.

**Decision.** Score only protocol evidence using fixed factors and show every contribution. Exclude geography and claimed identity.

**Why.** Reviewers can reproduce the result and challenge the rule that produced it.

**Consequences.** The score is a queue-ordering heuristic, not a probability of compromise or a behavioral attribution model.

**Evidence.** `src/ot_sentinel/triage.py`, triage tests, [TRIAGE_AND_EVALUATION.md](TRIAGE_AND_EVALUATION.md).

## ADR-010 — Portable defender content

**Context.** A dashboard alone does not show how analysis becomes detection engineering.

**Decision.** Ship equivalent selected behaviors in Sigma, Suricata, and Wazuh formats with fixtures and an offline validator.

**Why.** The project can demonstrate the path from protocol evidence to an operational alert.

**Consequences.** Offline validation is intentionally not called engine certification. Destination environments must run their native validators.

**Evidence.** `detections/`, `scripts/validate_detections.py`, [DETECTION_ENGINEERING.md](DETECTION_ENGINEERING.md).

## ADR-011 — Dual STIX profiles

**Context.** Internal investigations and public sharing require different levels of detail.

**Decision.** Export deterministic STIX 2.1 bundles in a sanitized public profile and a richer private profile.

**Why.** Consumers get portable intelligence without forcing raw investigative data into public artifacts.

**Consequences.** Project-specific custom properties may require consumer mapping. Deterministic identifiers aid comparison but do not sign or authenticate a bundle.

**Evidence.** `src/ot_sentinel/stix_export.py`, STIX tests, [STIX_EXPORT.md](STIX_EXPORT.md).

## ADR-012 — Declarative JSON profiles

**Context.** Demonstrations need different simulated facilities, but dynamic plugins would expand the attack surface.

**Decision.** Store site identity and bounded initial values in validated JSON documents with no executable hooks.

**Why.** Profiles remain readable, reviewable, and safe to load.

**Consequences.** Complex process simulation is outside scope. Runtime changes remain in memory and reset at restart.

**Evidence.** `profiles/`, `src/ot_sentinel/profiles.py`, profile tests.

## ADR-013 — Bounded, non-authoritative alerts

**Context.** A slow or unavailable webhook must not stop the honeypot or cause unbounded memory growth.

**Decision.** Alert only selected high-confidence/high-severity events through a capped, deduplicated asynchronous queue. Treat local JSONL as authoritative.

**Why.** Collection remains stable during integration failure, and alert volume stays understandable.

**Consequences.** Alerts may be delayed or dropped after bounded retries; metrics must reveal this condition.

**Evidence.** `src/ot_sentinel/operations.py`, operations tests, [OPERATIONS.md](OPERATIONS.md).

## ADR-014 — TLS plus HMAC for remote collection

**Context.** Centralizing multiple sensors introduces interception, tampering, spoofing, and replay risks.

**Decision.** Require TLS transport and HMAC-signed envelopes with timestamps, body-size limits, and replay detection.

**Why.** TLS protects the channel while the envelope supplies application-level authenticity and freshness checks.

**Consequences.** Operators must manage certificates, shared secrets, clock synchronization, and rotation. Local-only mode remains simpler.

**Evidence.** `src/ot_sentinel/transport.py`, `src/ot_sentinel/collector.py`, transport tests.

## ADR-015 — Streamlit dashboard

**Context.** The project needs an interactive interface without building and hosting a separate frontend stack.

**Decision.** Use Streamlit with Plotly and pandas for local analysis and demonstration.

**Why.** It is Python-native, quick to audit, and free to run locally.

**Consequences.** It is not a multi-tenant SOC console. Internet publication requires additional authentication and hosting controls.

**Evidence.** `app.py`, `requirements.txt`, dashboard smoke checks.

## ADR-016 — No mandatory ELK/Wazuh runtime

**Context.** Requiring a full SIEM stack would consume more memory, setup time, and possibly hosting budget.

**Decision.** Keep JSONL plus Streamlit as the default stack and provide Wazuh content as an integration option.

**Why.** The complete demonstration remains accessible on a normal Windows computer at no service cost.

**Consequences.** Enterprise indexing, authentication, retention, and correlation require an optional external platform.

**Evidence.** Default launch path, detection pack, deployment documentation.

## ADR-017 — Security gates and release evidence

**Context.** Claims of secure engineering should be backed by repeatable checks rather than prose alone.

**Decision.** Run unit tests, linting, public-data checks, dependency review, CodeQL, secret detection, container scanning, SBOM generation, checksums, and release provenance where applicable.

**Why.** A reviewer can inspect both the software and the evidence produced for a release.

**Consequences.** CI adds maintenance and can fail when upstream tooling changes. Passing checks remain evidence, not a security guarantee.

**Evidence.** `.github/workflows/`, `tests/test_supply_chain.py`, release assets.

## ADR-018 — Optional public cloud

**Context.** Azure UAE regions are relevant to a future regional study, but cloud deployment can incur cost and increases operational responsibility.

**Decision.** Make local execution the default and keep Azure/systemd/container deployment as optional templates.

**Why.** Development, testing, reporting, and demonstration remain free; an operator can later add a deliberately budgeted collection host.

**Consequences.** There is no always-on public sensor or permanent hosted dashboard in the current release.

**Evidence.** `infra/`, [DEPLOYMENT.md](DEPLOYMENT.md), [LIVE_COLLECTION_RUNBOOK.md](LIVE_COLLECTION_RUNBOOK.md).

## How to change a decision

A future change should add a new ADR or mark the affected ADR as superseded. Record the new context, decision, security and privacy consequences, migration steps, and tests. Do not silently rewrite the original reason after implementation changes.
