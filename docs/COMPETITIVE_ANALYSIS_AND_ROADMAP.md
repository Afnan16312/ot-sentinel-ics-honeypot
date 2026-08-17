# OT Sentinel: Competitive Analysis and Roadmap

Research date: 17 August 2026

This document compares OT Sentinel with established open-source honeypot projects and turns the findings into a practical, zero-cost development roadmap. The aim is not to claim that a small project is more mature than long-running community platforms. The aim is to identify a useful problem that OT Sentinel can solve well and prove with working code and tests.

## Executive conclusion

OT Sentinel should not try to become another large honeypot bundle.

Its strongest direction is:

> A lightweight OT deception and detection-engineering pipeline that converts safe honeypot observations into evidence-qualified ATT&CK mappings, privacy-reviewed intelligence, and tested rules defenders can use.

The current project already has four uncommon strengths:

1. A bounded, inert sensor for three industrial protocol entry points.
2. ATT&CK for ICS labels that include evidence and confidence instead of treating every connection as an attack.
3. A privacy gate between private telemetry and public data.
4. A reproducible local demonstration with tests, infrastructure code, a dashboard and a report.

The most important missing capability is the last mile from **interesting telemetry** to **actionable defense**. The next release should export standard threat intelligence and tested detection content for Sigma, Suricata and Wazuh.

## Current capability baseline

This assessment is based on the repository at commit `66912f2`.

| Area | Present now | Honest limitation |
|---|---|---|
| Sensor | Custom Python listeners for Modbus/TCP, S7/ISO-on-TCP and IEC-104 | Low-interaction parsing, not complete vendor protocol emulation |
| Safety | Small read limit, connection timeout, simulated responses and no link to real equipment | A public sensor still requires network isolation and monitoring |
| Analysis | Normalization, session records and evidence-aware ATT&CK for ICS mapping | Mapping quality is tested by examples, but not yet scored with precision/recall |
| Privacy | Salted source identifiers, raw-field removal and a public-data validator | No formal retention policy or separate private/public STIX profiles yet |
| Visualization | Streamlit observatory, ATT&CK layer, session explorer and methodology | No analyst triage queue or alert workflow |
| Reproducibility | Synthetic dataset, unit/integration tests, Docker, systemd and Azure Bicep | Public results are demonstration data, not a completed live collection study |
| Defender integration | Structured JSONL is easy to ingest | No STIX bundle, Sigma rules, Suricata rules or Wazuh rules yet |

## Similar open-source projects

The comparison uses project repositories as primary sources.

### Comparison matrix

| Project | Main strength | Similarity to OT Sentinel | Important difference | Lesson for OT Sentinel |
|---|---|---|---|---|
| [Conpot](https://github.com/mushorg/conpot) | Mature ICS/SCADA honeypot framework with configurable templates and protocol implementations | Both expose simulated industrial services to collect attacker behavior | Conpot has much greater protocol depth, history and community maturity; OT Sentinel has a purpose-built privacy and ATT&CK evidence pipeline | Integrate with or accept Conpot logs later instead of trying to reimplement all of Conpot |
| [T-Pot](https://github.com/telekom-security/tpotce) | Turnkey, multi-honeypot platform with Elastic-based analysis and many bundled sensors | Both collect and visualize deception telemetry | T-Pot is broad, distributed and resource-heavy; OT Sentinel is small, OT-focused and can run on a laptop | Keep the lightweight local experience and add export adapters rather than an embedded Elastic stack |
| [OpenCanary](https://github.com/thinkst/opencanary) | Very low resource use plus several alert delivery mechanisms | Both use low-interaction network decoys and Python | OpenCanary is aimed mainly at breach detection inside networks and has stronger alerting; OT Sentinel adds ICS-specific behavior analysis | Add selective high-confidence notifications and health checks |
| [HoneyPLC](https://github.com/sefcom/honeyplc) | High-interaction S7 PLC simulation, PLC profiles and ladder-logic capture | Both model PLC-facing behavior and record S7 activity | HoneyPLC prioritizes fidelity and attacker-uploaded program capture; OT Sentinel prioritizes safety, normalization, ATT&CK context and publication | Add fictional, stateful device profiles without accepting executable content |
| [GasPot](https://github.com/sjhilt/GasPot) | Focused and realistic Automatic Tank Gauge emulation with structured logs and write-command warnings | Both distinguish read/probe behavior from higher-value write attempts | GasPot deeply emulates one device family; OT Sentinel covers three protocol entry points with less device fidelity | Add configurable process profiles and preserve the current evidence hierarchy |
| [GridPot](https://github.com/sk4ld/gridpot) | Couples Conpot to a power-system simulation for realistic grid behavior | Both target critical-infrastructure research | GridPot models a physical process; OT Sentinel currently simulates protocol responses only | A stateful fictional process model is valuable, but it belongs after defender integrations |

### What is genuinely different

No single feature is unique by itself. The defensible difference is the combination:

```text
bounded OT decoy
    -> normalized evidence
    -> cautious ATT&CK mapping
    -> privacy-controlled publication
    -> dashboard and reproducible report
```

The project should describe this as its design focus, not as a claim that other honeypots never provide any of these functions.

### Where established projects are stronger

- Protocol completeness and realistic device fingerprints.
- Years of field use, contributors and issue history.
- Distributed sensor management and operational alert delivery.
- Existing SIEM, database and external service integrations.
- Higher-interaction capture such as credentials, files or control programs.

Trying to match all of those areas would make this project larger without making its central idea clearer.

## Defender problems worth solving

### 1. Internet-exposed OT remains easy to find

[CISA's Internet Exposure Reduction Guidance](https://www.cisa.gov/resources-tools/resources/exposure-reduction) says that misconfiguration, default credentials and outdated software remain publicly accessible, including ICS and IIoT assets. It recommends monitoring ingress and egress traffic and regularly reassessing exposed assets.

OT Sentinel's contribution is a safe observation point. It must never be presented as a reason to expose a real control system.

### 2. Logs are useful only when analysts can act on them

[NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final) treats continuous monitoring and risk-informed response as parts of OT security. [CISA's logging guidance](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems) also emphasizes centralized logs, high-risk alerts and enough detail for incident responders.

OT Sentinel currently creates good structured evidence, but an analyst still has to manually convert it into detection rules and cases. This is the highest-value gap.

### 3. ATT&CK mapping can create false certainty

[CISA's ATT&CK mapping guidance](https://www.cisa.gov/news-events/news/best-practices-mitre-attckr-mapping) specifically addresses mapping mistakes and analytical bias, including ICS guidance. OT Sentinel already avoids labeling a connection-only event as exploitation. It should now measure its mapper against labeled fixtures and make disagreements visible.

### 4. Threat intelligence needs portable formats

[OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) provides a machine-readable format for cyber threat intelligence, while MITRE publishes [ATT&CK data as STIX 2.1](https://github.com/mitre-attack/attack-stix-data). A STIX export would let OT Sentinel's output move beyond its own JSON schema.

Privacy must remain explicit: a private bundle may contain observables under a retention policy, while a public bundle should contain only sanitized or aggregated information.

### 5. Detection logic must work in existing tools

[Sigma](https://github.com/SigmaHQ/sigma) exists so log detections can be shared across SIEM products. [Suricata's Modbus rule keywords](https://docs.suricata.io/en/suricata-8.0.0/rules/modbus-keyword.html) can match functions, read/write access, units, addresses and values. [Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html) can decode JSON fields and supports [custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html).

Publishing tested examples for all three would demonstrate that the research can improve a defender's monitoring workflow.

## Recommended roadmap

The priorities below optimize for practical security value, proof quality and zero-cost development.

### Priority 0: Detection Engineering Pack

Build this first.

Deliverables:

- `detections/sigma/`: rules for high-confidence control attempts and exploit-signature evidence.
- `detections/suricata/`: Modbus write and unusual-function examples using native Modbus keywords.
- `detections/wazuh/`: rules that consume OT Sentinel's sanitized JSON fields.
- `tests/fixtures/detections/`: positive and negative example events.
- Automated validation in GitHub Actions.
- A dashboard panel showing which rule would fire and why.

Acceptance criteria:

- Every rule has an ID, description, severity, ATT&CK tag, known false positives and a test fixture.
- Connection-only and ordinary Modbus-read fixtures do not trigger high-severity rules.
- Modbus write, S7 program transfer and exploit-signature fixtures trigger the intended rules.
- CI fails when a rule is invalid or a detection regression occurs.

Why this comes first:

It proves knowledge of telemetry, detection logic, false positives, SIEM/IDS integration and automated testing in one bounded feature.

Estimated cash cost: **AED 0**.

### Priority 0: STIX 2.1 export with privacy profiles

Deliverables:

- `ot-sentinel export-stix --profile private|public`.
- STIX 2.1 bundle validation in tests.
- ATT&CK technique references resolved from MITRE's current ICS collection.
- Private objects for permitted observables and sightings.
- Public objects containing sanitized session references and aggregate behavior only.
- TLP and provenance metadata, including collection window and synthetic/live label.

Acceptance criteria:

- Both profiles pass a STIX 2.1 parser.
- The public bundle passes the existing privacy validator.
- The bundle records exactly which ATT&CK release was used.
- Synthetic observations cannot be confused with live observations.

Estimated cash cost: **AED 0**.

### Priority 0: Analyst triage and mapper evaluation

Deliverables:

- A deterministic session risk score based on action, evidence strength, confidence, repetition and novelty.
- Triage states: `new`, `reviewed`, `expected_scan`, `escalate`.
- A labeled replay set with expected ATT&CK outputs.
- Precision, recall and confusion-matrix metrics for the mapper.
- Dashboard filters for high-risk sessions and mapping disagreements.

Acceptance criteria:

- The scoring formula is documented and unit tested.
- A reviewer can see the raw evidence behind every score and technique.
- Evaluation results are reproducible from one command.
- No model or score is described as proof of attacker intent.

Estimated cash cost: **AED 0**.

### Priority 1: Safe, stateful OT profiles

Deliverables:

- YAML profiles for fictional water, power and port processes.
- Stateful but inert register and point values.
- Consistent banners, device metadata, timing and protocol responses.
- A profile validator that rejects dangerous hooks, shell commands and external connections.

Acceptance criteria:

- Repeated reads return internally consistent values.
- Writes affect simulated memory only and are resettable.
- Profiles contain no real organization names, addresses or credentials.
- The sensor still passes resource, timeout and maximum-input tests.

Estimated cash cost: **AED 0**.

### Priority 1: Operational health and selective alerting

Deliverables:

- Sensor heartbeat and last-event timestamp.
- Queue depth, parser error and dropped-event metrics.
- Optional webhook adapter for high-confidence events only.
- Retry, rate-limit and redaction tests.

Acceptance criteria:

- A routine scan does not send an urgent alert.
- A tested control attempt sends one deduplicated, redacted alert.
- Alert failure never blocks the sensor.

Estimated cash cost: **AED 0** for local testing; an external notification service may have its own limits.

### Priority 1: Software supply-chain evidence

Deliverables:

- Ruff in CI, dependency review and CodeQL where supported.
- Container and dependency vulnerability scan.
- CycloneDX or SPDX software bill of materials in each release.
- Pinned release dependencies and a documented update process.
- A lightweight threat model covering trust boundaries and abuse cases.

Acceptance criteria:

- A tagged release includes checksums, SBOM, test results and privacy-validation results.
- High-severity findings either fail CI or have a written, time-bounded exception.

Estimated cash cost: **AED 0** for a public GitHub repository and open-source tooling, subject to GitHub's current service limits.

### Priority 2: Multi-sensor collection

Deliverables:

- Authenticated, encrypted sensor-to-collector transport.
- Per-sensor identity, heartbeat and configuration version.
- Backpressure and offline queueing.
- Central view that never exposes secrets or raw public identifiers.

This is valuable operational engineering, but it should follow the detection and interoperability work because it adds deployment complexity.

### Priority 2: Authorized live study

Deliverables:

- Written scope, isolation diagram, retention period and shutdown criteria.
- Two-to-four-week authorized collection.
- Privacy review before publication.
- A report that separates observations, interpretations and limitations.

This is the only step that may require paid infrastructure. A local demonstration and all Priority 0/1 development can be completed without Azure. Do not expose a home network or a personal computer merely to obtain live traffic.

## Four-week zero-cost build plan

| Week | Build | Proof produced |
|---|---|---|
| 1 | Sigma, Suricata and Wazuh rules plus fixtures | Valid rules, positive/negative test output and CI evidence |
| 2 | STIX private/public exporters | Standards-compliant bundles and privacy validation |
| 3 | Risk scoring, mapper evaluation and triage dashboard | Precision/recall report and evidence-based session queue |
| 4 | One safe stateful profile, SBOM and tagged release | Reproducible release, security checks and a short recorded demo |

The live collection study is intentionally outside this zero-cost plan. It can be added later when safe, authorized infrastructure is available.

## Skills the completed roadmap demonstrates

- OT protocol analysis rather than generic port logging.
- Secure Python networking and defensive input handling.
- Detection engineering across SIEM and network IDS formats.
- Threat-intelligence standards and ATT&CK data modeling.
- Privacy-aware telemetry handling.
- Test design, CI, infrastructure-as-code and supply-chain hygiene.
- Clear separation between evidence, inference and unsupported attribution.

These are stronger signals than adding more charts because each output can be inspected, executed and tested.

## How to explain the project honestly

Use this short structure:

1. **Problem:** Exposed OT services are probed, but raw honeypot logs are noisy and difficult to use safely.
2. **Build:** I created bounded decoys for three industrial protocol entry points, normalized the sessions and displayed the results.
3. **Security decision:** I required evidence before assigning stronger ATT&CK labels and added a privacy gate before public output.
4. **Proof:** The repository includes repeatable demo data, tests, deployment assets, a dashboard and a report.
5. **Current limit:** The public dataset is synthetic and the sensor is low interaction; I do not claim live UAE attacker findings yet.
6. **Next engineering step:** Convert validated behavior into STIX intelligence and tested Sigma, Suricata and Wazuh detections.

## Decision rule for future features

Add a feature only when it improves at least one of these outcomes:

- safer collection,
- stronger evidence,
- lower analyst workload,
- better interoperability,
- measurable detection quality, or
- more reproducible research.

If a feature only makes the dashboard busier, it is not a priority.

## Sources

- [Conpot](https://github.com/mushorg/conpot)
- [T-Pot](https://github.com/telekom-security/tpotce)
- [OpenCanary](https://github.com/thinkst/opencanary)
- [HoneyPLC](https://github.com/sefcom/honeyplc)
- [GasPot](https://github.com/sjhilt/GasPot)
- [GridPot](https://github.com/sk4ld/gridpot)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data)
- [CISA Internet Exposure Reduction Guidance](https://www.cisa.gov/resources-tools/resources/exposure-reduction)
- [CISA Best Practices for MITRE ATT&CK Mapping](https://www.cisa.gov/news-events/news/best-practices-mitre-attckr-mapping)
- [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [Sigma](https://github.com/SigmaHQ/sigma)
- [Suricata Modbus keyword](https://docs.suricata.io/en/suricata-8.0.0/rules/modbus-keyword.html)
- [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
