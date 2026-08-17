# Problem and Solution Record

This record explains the important engineering and delivery problems encountered or anticipated in OT Sentinel, how they were solved, what proves the solution, and what risk remains. It covers release `v0.2.0` and the launch work that preceded it.

## Product and security problems

| ID | Problem and impact | Solution shipped | Proof | Remaining limitation |
|---|---|---|---|---|
| PS-001 | Connecting a portfolio project to real industrial equipment would create unacceptable safety risk. | Built an isolated, low-interaction software decoy with no physical control path or payload execution. | Protocol/sensor code, integration tests, threat model | Public exposure still requires hardening and monitoring. |
| PS-002 | Azure or another always-on cloud host can create cost before it produces useful evidence. | Made local Windows/Docker operation the complete default; kept cloud templates optional. | Windows launcher, Docker assets, deployment guide | A future regional collection study needs a deliberately budgeted host or free credit. |
| PS-003 | A generic TCP logger would not show meaningful ICS knowledge. | Added selected Modbus/TCP, S7comm, and IEC-104 decoding and safe responses. | Protocol code and tests | It remains a selected low-interaction subset, not full protocol conformance. |
| PS-004 | Untrusted clients can send oversized, slow, repeated, or malformed input. | Added bounded reads, timeouts, connection/session/request caps, safe errors, and no execution path. | Sensor integration tests and threat model | Any internet service retains residual implementation and denial-of-service risk. |
| PS-005 | Static decoys are easy to fingerprint and make poor demonstrations. | Added validated water, power, and port profiles plus bounded in-memory state changes. | Profile fixtures and tests | State resets on restart and does not model process physics. |
| PS-006 | Mapping every connection to ATT&CK would produce false certainty. | Required protocol evidence and emitted confidence, rationale, and evidence; unsupported events remain unmapped. | Mapper rules, tests, labeled evaluation fixtures | Mapping is still an analyst hypothesis, not proof of intent or compromise. |
| PS-007 | Raw IP addresses and payloads could leak through public reports or STIX. | Separated private evidence from sanitized public artifacts and added a fail-closed validator. | Privacy tests and public-data script | Human legal and contextual review is still required. |
| PS-008 | The project needed a convincing demo before authorized live data existed. | Generated 420 deterministic events and labeled every demonstration artifact as synthetic. | Demo generator and sample data | Synthetic data cannot support real regional threat conclusions. |
| PS-009 | Logs alone do not become operational detections. | Added Sigma, Suricata, and Wazuh packs with positive, negative, and all-negative fixtures. | Detection files, validator, tests | Native destination-engine validation is still required. |
| PS-010 | Project-specific JSON is difficult to exchange with other threat-intelligence tools. | Added deterministic STIX 2.1 public/private export profiles and schema tests. | STIX module, tests, documentation | Custom properties can require consumer mapping. |
| PS-011 | Analysts could not quickly tell which event deserved review. | Added a deterministic score based only on protocol evidence and exposed every factor. | Triage module, tests, dashboard queue | It is a prioritization heuristic, not a predictive risk model. |
| PS-012 | ATT&CK mapping changes could silently regress. | Added human-labeled cases and exact/per-technique confusion metrics. | Evaluation harness and tests | The 12-case fixture set is intentionally small. |
| PS-013 | Optional integrations could block collection or exhaust memory. | Added capped alert queues, deduplication, timeout, retry/backoff, and delivery/drop metrics. | Operations module and tests | Delivery is best effort; the local log remains authoritative. |
| PS-014 | Central ingestion can be spoofed, modified, replayed, or observed in transit. | Combined TLS with HMAC signatures, timestamps, size limits, and replay rejection. | Transport/collector modules and tests | Certificate and secret lifecycle is an operator responsibility. |
| PS-015 | A full ELK/Wazuh runtime would raise memory, setup, and hosting cost. | Used JSONL and Streamlit as the default while shipping optional Wazuh-compatible content. | Default launch path and architecture record | Enterprise SIEM capabilities need an external stack. |
| PS-016 | The first dashboard palette used a turquoise accent that was too bright for comfortable viewing. | Reworked the interface around a muted steel-blue accent and restrained dark surfaces. | `app.py` theme/style rules | Display calibration and personal accessibility needs can vary. |

## Setup and usability problems

### PS-017 — Missing Windows `py` launcher

**Observed problem.** On the initial Windows setup, `py -3.12 -m venv .venv` failed because the Python Launcher for Windows was not installed. The next commands failed because `.venv` had never been created.

**Root cause.** The instructions assumed one executable name (`py`) instead of detecting the available Python installation.

**Solution.** `run_dashboard.ps1` now checks, in order, for `py`, `python`, and the normal per-user Python 3.12 executable. It creates the environment, installs missing dashboard packages, installs the local project package when needed, and starts Streamlit.

**Proof.** `run_dashboard.ps1` and a successful local dashboard health check.

**Residual.** Python must be installed. The first dependency installation requires internet access unless packages are already cached.

### PS-018 — Complex first-run command sequence

**Observed problem.** Asking a new user to create a virtual environment, install dependencies, install the package, and launch Streamlit manually created several failure points.

**Solution.** Consolidated those steps behind `.\run_dashboard.ps1`, while retaining manual commands for users who want full control.

**Proof.** Launcher implementation and simplified README instructions.

**Residual.** PowerShell execution policy may need the documented one-process bypass on a tightly managed computer.

## Release and supply-chain problems

### PS-019 — Test-runner security advisory

**Problem.** An upstream advisory affected the previously allowed pytest version, so a green functional test alone was not adequate release evidence.

**Solution.** Raised the development requirement to a non-affected pytest release and let dependency review verify the graph.

**Proof.** `pyproject.toml`, dependency workflow, passing CI.

**Residual.** Dependency advisories change over time; automated review must remain enabled.

### PS-020 — STIX validator compatibility regression

**Problem.** A newer validator release changed schema-resolution behavior and caused unstable validation unrelated to the exported domain logic.

**Solution.** Pinned the known-compatible `stix2-validator` version and retained independent tests for both public and private bundle profiles.

**Proof.** Development dependency pin and STIX export tests.

**Residual.** The pin should be deliberately reevaluated with its upstream release notes, never updated blindly.

### PS-021 — Vulnerable build tooling in the runtime image

**Problem.** Container scanning found vulnerable package-management/build components that the running service did not actually need.

**Solution.** Used an updated installer only during the image build, installed the application, then removed `pip` and `setuptools` from the final runtime environment. The runtime also uses a non-root user, read-only filesystem, dropped capabilities, and temporary writable mounts.

**Proof.** `Dockerfile`, Compose hardening, Trivy workflow, supply-chain tests.

**Residual.** The base image and operating-system packages still need ongoing scanning and patching.

### PS-022 — Claims without auditable release evidence

**Problem.** A README statement that the project was “secure” or “tested” would be difficult for another person to verify.

**Solution.** Added CI tests, linting, privacy validation, CodeQL, dependency review, secret scanning, container scanning, SBOM generation, checksums, and release provenance.

**Proof.** `.github/workflows/`, release assets, test suite.

**Residual.** Passing automation cannot prove the absence of vulnerabilities or operational mistakes.

## Research-integrity problems

### PS-023 — No authorized live observation period yet

**Problem.** The intended quarterly regional intelligence report requires real observations, but claiming them without an authorized deployment would be misleading.

**Solution.** Kept the public dataset synthetic, wrote a live-collection runbook with stop conditions, and made provenance visible in events, reports, dashboard language, and exports.

**Proof.** [LIVE_COLLECTION_RUNBOOK.md](LIVE_COLLECTION_RUNBOOK.md), sample-data metadata, public validation.

**Residual.** The live report is not complete until a legally approved sensor operates for the stated period and the results pass privacy and methodology review.

### PS-024 — Security engines unavailable in the local development environment

**Problem.** Suricata, Sigma CLI, and `wazuh-logtest` were not installed locally, preventing authoritative native compilation/tests for all three formats.

**Solution.** Added an offline structural/semantic validator and positive/negative fixtures, while documenting the exact destination-native checks and refusing to label offline checks as engine certification.

**Proof.** `scripts/validate_detections.py`, detection tests, [DETECTION_ENGINEERING.md](DETECTION_ENGINEERING.md).

**Residual.** A destination lab must run `suricata -T`, Sigma conversion/validation, and `wazuh-logtest` before production use.

## Problem-solving method used

Across these records, the same method is visible:

1. State the real risk or usability failure without hiding uncertainty.
2. Choose the smallest solution that preserves the safety and zero-cost goals.
3. Make the behavior deterministic where possible.
4. Add automated evidence for the success and failure paths.
5. Document what the solution does not prove.
6. Keep a clear future requirement for residual work instead of presenting it as complete.

This record should be updated whenever a material incident, design constraint, or release blocker changes the implementation.
