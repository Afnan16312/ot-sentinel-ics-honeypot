# OT Sentinel User Research, Pain-Point and Feature Strategy

**Date:** 2026-08-28

**Scope:** public synthetic/sanitized dashboard, local analysis workflow, and possible future private analyst workflow

**Status:** product research and recommendations; proposed features are not shipped unless explicitly marked
**Safety boundary:** this document does not authorize access to the Oracle sensor, publication of private telemetry, automated action against observed sources, or changes to cloud, Docker, Wazuh, Suricata, or network controls

## 1. Executive conclusion

OT Sentinel should not be treated as one product for one generic “cybersecurity user.” It is a small evidence platform serving several different jobs:

1. **Observe** protocol-aware decoy activity.
2. **Understand** what an event, session, source group, control action, confidence value, and ATT&CK hypothesis mean.
3. **Prioritize** evidence without pretending that a score proves malicious intent.
4. **Investigate** a session and the protocol evidence behind it.
5. **Validate** detection content and ATT&CK mappings.
6. **Handoff** a privacy-safe summary to another analyst or tool.
7. **Report** reproducible, carefully bounded findings.
8. **Operate** the sensor and analysis pipeline safely.
9. **Learn or demonstrate** how an OT honeypot, analysis pipeline, and SOC workflow connect.

The strongest current users are a cybersecurity learner/project owner, a SOC or security analyst working with sanitized evidence, a detection engineer, a research/report author, a privacy reviewer, and the operator of the honeypot study. A control engineer, incident responder, security manager, auditor, and MSSP analyst are credible secondary or future users, but their needs should not be represented as fully satisfied by the current public Streamlit application.

The central product problem is:

> Users can see technically rich evidence, but different users need different help deciding what the evidence means, how certain it is, what they should do next, what they may safely share, and what the system cannot prove.

The next product phase should deepen **decision support, evidence traceability, research reproducibility, and safe handoff**. It should not add decorative activity, attacker attribution, automatic blocking, or a multi-user enterprise backend before real user testing proves those needs.

## 2. Research method and confidence

This analysis combines four evidence types:

| Evidence | How it was used | Confidence |
|---|---|---|
| Current repository and dashboard | Establishes what OT Sentinel actually ships and which workflows already exist. | High |
| Existing product documents | Establishes prior decisions, privacy limits, non-goals, and already identified gaps. | High |
| NIST, CISA, MITRE ATT&CK, and UAE official guidance | Establishes real OT constraints, cross-functional roles, monitoring, incident response, detection, asset, reporting, and governance needs. | High for general role/workflow needs |
| Product reasoning | Converts role needs into problem statements and possible features. | Medium until validated with users |

This is **desk research**, not proof from user interviews or production analytics. The personas and pain points are evidence-based hypotheses. Before major implementation, they should be validated with short tests involving representative users. This distinction matters: a plausible feature idea is not the same as demonstrated user demand.

### External evidence shaping the analysis

- [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final) states that OT security must address performance, reliability, and safety, not only conventional IT security.
- The same NIST guide describes OT cybersecurity as cross-functional work involving IT staff, control engineers, control-system operators, security experts, risk management, safety experts, managers, service providers, and vendors.
- NIST describes OT incident response as planning, detection, analysis, containment, reporting, communication, recovery, and lessons learned. This supports workflows that connect observations to evidence, decisions, handoff, and reporting.
- NIST recommends centralized logging, passive monitoring, normal-state baselining, and careful tuning because normal OT behavior can resemble an intrusion and create nuisance alerts.
- [MITRE ATT&CK detections and analytics guidance](https://attack.mitre.org/resources/get-started/detections-and-analytics/) frames ATT&CK as a way to build, test, and refine behavioral analytics. This supports a detection-engineering workflow rather than a decorative ATT&CK heat map.
- The [NIST NICE Framework](https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/about) models cybersecurity around tasks, knowledge, skills, work roles, and teams; it explicitly serves employers, learners, academia, and training providers.
- [CISA’s OT asset-inventory guidance](https://www.cisa.gov/sites/default/files/2025-08/joint-guide-foundations-for-OT-cybersecurity-asset-inventory-guidance_508c.pdf) emphasizes ownership, ports/services, logging, baselines, backups, and other context required for investigation and recovery.
- [CISA’s ICS recommended practices](https://www.cisa.gov/resources-tools/resources/ics-recommended-practices) cover incident response, forensics, defense in depth, patch management, remote access, and mitigations, showing that monitoring is one part of a larger operational workflow.
- [UAE Information Assurance Regulation](https://tdra.gov.ae/-/media/About/regulations-and-ruling/EN/UAE-Information-Assurance-Regulation-v1-1-pdf.ashx) emphasizes risk-based controls, stakeholder responsibilities, monitoring, continuous improvement, compliance, and cross-sector information sharing.
- [Dubai Electronic Security Center’s ICS standard overview](https://www.desc.gov.ae/regulations/standards-policies/) highlights OT/IT convergence, operational continuity, governance, operation, assurance, and cyber-risk management for critical infrastructure.

## 3. Current product baseline

OT Sentinel already includes more than a map. The current baseline must be protected rather than rebuilt:

| Capability group | Current value | Main users | Important limit |
|---|---|---|---|
| Bounded Modbus, S7comm, and IEC-104 decoys | Produces protocol-aware synthetic or authorized observations without executing attacker content. | Operator, learner, researcher | Low-interaction simulation, not a production PLC. |
| Structured event/session evidence | Gives analysts deterministic records and session context. | SOC analyst, researcher | Raw logs are private. |
| Evidence-aware ATT&CK for ICS hypotheses | Connects decoded behavior to techniques with confidence and rationale. | SOC analyst, detection engineer, learner | A mapping is not proof of intent or compromise. |
| Public review scoring | Orders public-safe evidence and explains the factors. | SOC analyst, learner | It excludes private identity and is not a risk probability. |
| Privacy/publication gate | Pseudonymizes and validates public artifacts. | Privacy reviewer, researcher, owner | Technical validation is not legal approval. |
| Observatory and four map modes | Supports overview, filtering, time-window review, map selection, comparison, and accessible table selection. | All dashboard users | Geography is approximate and is not attribution. |
| ATT&CK Analysis | Shows mapped techniques, confidence, and rationale. | Analyst, detection engineer, learner | Counts are mapping matches, not unique intrusions. |
| Detection Preview and native fixtures | Shows offline Sigma/Wazuh/Suricata predictions and separately validated fixture evidence. | Detection engineer, SOC analyst | Offline prediction is not a native SIEM alert. |
| Triage and Session Explorer | Supports prioritization and event-to-session traceability. | SOC analyst, incident responder | The public build is not a case-management system. |
| STIX, Navigator, reports, and aggregate exports | Supports interoperability and repeatable research outputs. | Researcher, threat-intel analyst | Live outputs remain private until reviewed. |
| Health checks, bounded queues, durable storage, delivery spool, and runbooks | Supports safe operation and recovery. | Sensor/platform operator | Not a full observability platform or cloud control plane. |
| Synthetic demo dataset and tests | Makes the project reproducible and explainable. | Learner, reviewer, recruiter | Synthetic evidence cannot support real regional threat claims. |

### Product modes that users must never confuse

| Mode | Intended user | Data | Permitted outcome |
|---|---|---|---|
| Public demonstration | Learner, reviewer, recruiter, general visitor | Synthetic or approved aggregate/sanitized data | Education, demonstration, architecture explanation |
| Local analysis | Analyst, researcher, detection engineer | Sanitized events or synthetic fixtures | Investigation, mapping review, rule validation |
| Private study | Authorized operator and approved analysts | Private telemetry | Internal research and evidence preparation only |
| Public research release | Researcher plus privacy/legal reviewer | Explicitly reviewed aggregate outputs | A bounded report with limitations and methodology |

## 4. User ecosystem and prioritization

### 4.1 Segmentation

| Segment | Representative users | Current fit | Frequency | Product priority |
|---|---|---:|---:|---:|
| Learn and demonstrate | Project owner, student, job seeker, trainer, recruiter, nontechnical reviewer | Strong | Occasional | Primary now |
| Monitor and triage | SOC L1/L2 analyst, threat hunter | Moderate to strong for sanitized evidence | Daily in a future operational workflow | Primary |
| Validate detections | Detection engineer, SIEM/Wazuh/Suricata content engineer | Strong local-lab fit | Weekly | Primary |
| Investigate and respond | Incident responder, forensic analyst, OT IR lead | Partial; lacks private case workflow | Incident-driven | Secondary/future |
| Engineer OT security | OT security engineer, architect, IT/OT security lead | Moderate | Weekly/monthly | Primary advisory user |
| Operate the process | Control engineer, control-system operator, site engineer | Limited direct fit; essential context provider | Shift/daily | Secondary |
| Run the honeypot | Sensor operator, platform engineer, project owner | Strong via CLI/runbooks; dashboard health is partial | Daily/weekly | Primary operational user |
| Produce intelligence | Threat-intel researcher, report author, academic reviewer | Strong for sanitized/reviewed datasets | Weekly/quarterly | Primary |
| Govern and assure | Privacy reviewer, auditor, compliance lead, risk manager | Moderate through documentation and gates | Release/audit driven | Primary approval user |
| Manage security outcomes | OT security manager, SOC manager, CISO/program owner | Partial; lacks executive outcome views | Weekly/monthly | Secondary |
| Deliver managed service | MSSP analyst, multi-site lead, customer success reviewer | Weak; no tenancy/RBAC/case model | Daily in future | Conditional future |

### 4.2 Primary versus future design users

**Design for now:** learner/project owner, sanitized-evidence analyst, detection engineer, researcher/report author, privacy reviewer, and sensor operator.

**Consult now:** OT security engineer, control engineer/operator, incident responder, and security manager. Their domain knowledge should shape terminology, safety, and handoff even when they do not use every screen.

**Do not optimize for yet:** large multi-tenant SOCs, public self-service users, automated response operators, or collaborative case teams. Supporting these properly requires authentication, authorization, audit, retention, tenant isolation, and a different operating model.

## 5. Shared end-to-end user journey

| Stage | User question | Current support | Main friction | Desired outcome |
|---|---|---|---|---|
| Orient | What am I looking at, and is it real? | Dataset banner, provenance, glossary, methodology | New users still need guided sequencing and role-specific language | Correct mental model in under two minutes |
| Observe | What happened in this window? | Metrics, maps, timeline, protocol mix | Volume can be mistaken for incident count or importance | A bounded, correctly labelled summary |
| Narrow | Which activity deserves attention? | Filters, public review score, control-only filtering | Users need reusable views and clearer data-quality context | Small, relevant evidence set |
| Inspect | What exactly did this source/session do? | Map selection, session explorer, decoded evidence | Cross-view navigation and event sequence can still feel fragmented | One coherent evidence timeline |
| Validate | Why is this mapped or ranked, and is a rule present? | Confidence, rationale, detection preview | Rule provenance, gap tracking, and tune/test history are limited | Explainable analytical judgement |
| Decide | What should happen next? | Non-automated next-step copy and local review state | No durable private decision record or severity/impact collaboration | Explicit review outcome with reason |
| Handoff | How do I give this to another person/tool safely? | Aggregate export, STIX, Navigator, Wazuh staging | Public and private handoff have different needs | Reproducible, privacy-scoped package |
| Report | What can I responsibly claim about the period? | Report tooling and provenance controls | Narrative, comparison, methodology, and approval require manual assembly | Defensible report with limitations |
| Improve | Which parser, map, or rule needs work? | Tests, fixtures, detection preview | No consolidated quality/coverage backlog | Evidence-based engineering tasks |
| Operate | Is collection healthy and recoverable? | Health files, monitor script, queues, runbooks | Status is outside the dashboard and does not represent full lifecycle | Safe redacted operational assurance |

## 6. Detailed personas, pain points, and solution hypotheses

### Persona 1 — First-time visitor, recruiter, or nontechnical reviewer

**Context:** Opens the dashboard or GitHub link for five to ten minutes. Has limited OT knowledge and may incorrectly assume every event is an attack, every source is a person, and every map point is an actual victim or attacker location.

**Goals:**

- Understand the project’s purpose quickly.
- See credible evidence that the software works.
- Understand why OT protocols matter.
- Recognize the ethical and privacy boundaries.
- Know what the author personally built and tested.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Cybersecurity terms are unfamiliar | When the visitor sees “420 events,” they cannot tell whether this means 420 attacks, sessions, or messages. | Plain-language metric definitions, examples, and “does not mean” help. |
| Six views look unrelated | When the visitor moves between tabs, they do not know the intended story. | Guided Observe → Investigate → Validate → Explain tour. |
| Synthetic data may feel fake | When the dataset is labelled synthetic without explaining why, the visitor may think the project is only a UI mock-up. | Explain that synthetic fixtures safely prove the end-to-end pipeline, while live data remains private. |
| Technical proof is hidden | When tests, rule validation, and privacy gates are not visible, the visitor judges only visual polish. | Evidence drawer showing safe test counts, validation types, and boundaries. |
| The map can imply global attack coverage | When the visitor sees global points, they may infer worldwide victim/attacker activity. | Persistent “selected dataset only; approximate; no attribution” card. |

**Helpful minor features:** role-based “Explain this screen” button, pronunciation/definition help for Modbus/S7/IEC-104, a one-click demo reset, visible synthetic badge in screenshots, safe example investigation, progress indicator for the walkthrough, and a “What this proves / cannot prove” drawer.

**Helpful major feature:** a deterministic five-minute walkthrough mode that highlights one synthetic source, its session, ATT&CK rationale, detection coverage, privacy gate, and final safe export.

**Success signals:** the visitor can explain the project in two sentences, correctly distinguish events/sessions/sources, and state that the map is approximate and non-attributive.

### Persona 2 — Cybersecurity learner, student, or project owner

**Context:** Runs the application locally, studies the code, demonstrates the project, and learns OT protocols, ATT&CK mapping, Wazuh/Suricata, Docker, privacy, and cloud deployment.

**Goals:**

- Learn how data flows from protocol interaction to dashboard insight.
- Reproduce a safe demonstration without memorizing every command.
- Diagnose setup errors confidently.
- Explain design decisions and limitations during interviews.
- Extend the project without weakening safety.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Many components and commands | When setup fails, the learner does not know whether Python, Docker, Wazuh, the dashboard, or the sensor is responsible. | Component-specific readiness checklist and troubleshooting decision tree. |
| Demo sequence depends on memory | When presenting, the learner may skip the evidence boundary or confuse offline predictions with native alerts. | Presentation mode with a fixed safe script and checkpoints. |
| Code-to-screen relationship is unclear | When a chart changes, the learner cannot identify the file, function, data field, or test behind it. | “How this is built” references in Methodology and documentation links. |
| Fear of damaging live collection | When improving local code, the learner may worry that it changes Oracle. | Persistent separation of local branch, public demo, and live sensor states. |
| Success is difficult to measure | Passing tests does not automatically show what user capability is now better. | Feature acceptance checklist tied to user tasks. |

**Helpful minor features:** copyable commands with platform labels, readiness badges for local components, error-to-runbook links, a command glossary, expected output snippets, “safe to demonstrate” labels, and a local-only tutorial dataset selector.

**Helpful major features:** interactive learning lab with protocol request examples, decoded responses, ATT&CK reasoning, detection rule matches, and small exercises; a safe demo recorder checklist built into the UI.

**Success signals:** first-time local setup completion, fewer wrong commands, correct explanation of component boundaries, and successful completion of the synthetic walkthrough without exposing private data.

### Persona 3 — SOC L1 triage analyst

**Context:** Reviews many alerts or observations, often under time pressure. Needs to decide what is routine, what needs context, and what should move to deeper investigation. May know enterprise security well but have limited Modbus/S7/IEC-104 knowledge.

**Goals:**

- Find high-value control or write behavior quickly.
- Separate repeated scanner noise from meaningful protocol evidence.
- Understand why an observation is ranked.
- Compare related sessions or sources.
- Make a defensible review decision and hand off context.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Event volume dominates attention | When one scanner creates many connections, the analyst may over-prioritize it. | Session grouping, repeat/novelty explanation, and explicit count semantics. |
| OT function codes are unfamiliar | When a Modbus or S7 action is decoded, the analyst needs operational meaning, not only a numeric code. | Human-readable action and potential-process-impact explanation reviewed by OT experts. |
| Score may look authoritative | When a score says 78/100, the analyst may mistake it for probability or severity. | Factor breakdown, data-quality caveat, and comparison to review policy. |
| Context is split across views | When moving from map to ATT&CK, session, and rule, the analyst may lose selection context. | Investigation drawer or context-preserving cross-view navigation. |
| No durable handoff | When escalating, the analyst has no private case summary with evidence and reason. | Privacy-scoped review bundle or future case record. |
| No explicit “benign/unknown” outcome | When evidence is weak, the interface can push the analyst toward alarmist language. | Review states: routine, expected test, needs context, investigate, detection tuning candidate. |

**Helpful minor features:** sticky selection context, one-click “control actions only,” session-first grouping, first/last seen, safe source copy button, filter chips, saved local filter presets, keyboard navigation, reviewed/unreviewed counters, explicit weak-evidence badges, and empty-result recovery suggestions.

**Helpful major features:** a private investigation workspace that combines event sequence, process action, ATT&CK rationale, detection coverage, notes, review decision, and sanitized handoff without exposing raw fields in public mode.

**Success signals:** lower time to first defensible decision, fewer event-count mistakes, fewer unnecessary escalations, and complete rationale in escalated reviews.

### Persona 4 — SOC L2/L3 analyst, threat hunter, or OT incident responder

**Context:** Receives escalated evidence, investigates sequences, validates scope, correlates other sources, communicates with OT personnel, and supports containment or recovery decisions. This is primarily a future private-workflow persona.

**Goals:**

- Reconstruct a reconnaissance → read → write/control sequence.
- Determine evidence scope and uncertainty.
- Correlate related sessions without equating geography with identity.
- Understand detection gaps and supporting logs.
- Coordinate with control engineers before recommending action.
- Preserve an audit trail and report lessons learned.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Session timeline lacks incident narrative | Individual decoded events do not automatically explain sequence or intent. | Deterministic sequence grouping with analyst-confirmed interpretations. |
| Honeypot evidence is incomplete | A decoy sees interactions, not the full enterprise/plant context. | Evidence completeness checklist and external-log correlation fields. |
| OT response can affect safety/availability | An automatic “block source” action could disrupt legitimate or diagnostic traffic. | Human approval, OT-owner consultation, and no automatic response from this application. |
| Cross-tool correlation is manual | Wazuh, Suricata, STIX, and dashboard evidence may use different IDs and scopes. | Stable correlation IDs, evidence manifest, and safe deep links/exports. |
| Case and custody controls are absent | Private evidence needs access control, retention, integrity, and review history. | Conditional future case service with RBAC, append-only audit, checksums, retention, and tenant boundaries. |

**Helpful minor features:** sequence labels, “evidence missing” checklist, investigation hypothesis field, confidence changes over time, cross-tool correlation IDs, and OT-owner consultation status.

**Helpful major features:** private case workflow and evidence graph; multi-source timeline; controlled SIEM/SOAR handoff. These must not be added to the public dashboard as lightweight session state.

**Success signals:** complete evidence chain, transparent uncertainty, documented OT consultation, and no unsafe automated response.

### Persona 5 — Detection engineer or SIEM/IDS content engineer

**Context:** Translates protocol behavior and ATT&CK hypotheses into Sigma, Wazuh, and Suricata content, tests rules, measures false positives, and maintains rule provenance.

**Goals:**

- See which operations and techniques have detection coverage.
- Distinguish offline match logic from native-engine execution.
- Reproduce positive and negative fixtures.
- Understand why a rule fired and what evidence it used.
- Track tuning decisions, versions, and regressions.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Coverage is scattered | When selecting a technique, the engineer cannot immediately see parser support, mapping support, rules, fixtures, and native validation together. | Protocol × operation × technique × rule coverage matrix. |
| “Matched” has several meanings | Offline prediction can be confused with Wazuh or Suricata actually firing. | Explicit evidence states with native validation date/version. |
| Noise cannot be evaluated from counts alone | Repeated matching events may come from one session or fixture. | Unique session/source counts and positive/negative fixture ratios. |
| Rule changes lack visible history | A future reviewer cannot tell why a threshold or condition changed. | Tuning changelog linked to tests and safe fixtures. |
| Uncovered behavior is not an ordered backlog | Gaps do not automatically become actionable engineering work. | Coverage-gap queue prioritized by control action, confidence, prevalence, and fixture availability. |

**Helpful minor features:** copyable native test commands, rule-path links, validation badges, filter by engine, negative-fixture count, parser/mapping/rule distinction, last validated version, rule owner, and reason-for-change field.

**Helpful major features:** detection engineering workbench with a coverage matrix, fixture builder using synthetic records, native validation history, tuning notes, regression status, and safe export to a pull-request template.

**Success signals:** shorter gap-to-tested-rule time, every rule has positive/negative fixtures, native/offline evidence is never confused, and regression failures are visible before release.

### Persona 6 — OT security engineer or IT/OT security architect

**Context:** Designs monitoring and segmentation, works across enterprise and plant teams, interprets OT protocol behavior, reviews exposure, and balances cybersecurity with safety and availability.

**Goals:**

- Understand which exposed services and behaviors the decoy represents.
- Validate that monitoring remains isolated and non-disruptive.
- Compare activity with expected protocols, assets, zones, and conduits.
- Explain residual risk and architectural limitations to management.
- Turn observations into safe monitoring or hardening recommendations.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Public map lacks plant architecture | Internet-source geography says little about zones, conduits, owners, or process criticality. | Optional fictional profile/zone context for demos; private asset-context joins only under approved controls. |
| Activity is not compared with an expected baseline | Without expected service/operation profiles, anomaly language is weak. | Profile-aware expected/unexpected behavior classification with transparent rules. |
| Cyber and operational meaning are separated | A protocol write has different implications depending on target function and process state. | OT-reviewed action glossary and potential-impact category, never automatic consequence claims. |
| Recommendations could disrupt operations | Security action without control-engineer review can create safety/availability risk. | “Consult OT owner” gates and non-automated recommendation templates. |
| Multi-site posture is absent | One sensor view cannot explain architecture-wide coverage. | Conditional multi-sensor inventory and coverage view after secure identity/tenancy design. |

**Helpful minor features:** fictional asset/profile label, expected protocol matrix, zone/conduit teaching diagram, explicit monitoring point, sensor isolation evidence, configuration fingerprint, and architecture limitations card.

**Helpful major features:** profile-aware behavioral baseline and multi-sensor coverage architecture; read-only mapping of approved asset inventory context in a private deployment.

**Success signals:** accurate explanation of monitoring coverage, no safety-impacting recommendations without OT review, and documented gaps between decoy visibility and real architecture.

### Persona 7 — Control engineer, control-system operator, or site engineer

**Context:** Knows the process, equipment, normal maintenance, and real operational consequences. May not use ATT&CK or SIEM terminology daily. NIST treats this role as essential to a cross-functional OT security team.

**Goals:**

- Understand whether a decoded operation is normal, unusual, or potentially unsafe.
- Explain legitimate maintenance or engineering activity.
- See terminology in process language rather than only cyber language.
- Review recommendations before they affect operations.
- Preserve uptime, safety, and process integrity.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Cyber language hides process meaning | “T0843 Program Download” is less useful than a clear description of the observed PLC-related action and evidence. | Side-by-side cyber and OT explanations. |
| Geographic/source context is irrelevant to process impact | A country or source group does not say which process function is affected. | Target profile, function, register/object, and safe process-context labels. |
| False positives can come from maintenance | Expected tests and maintenance may resemble attacks. | Maintenance/context annotations in private mode and baseline comparison. |
| Response recommendations may be unsafe | A security team might suggest blocking or shutdown without operational review. | Mandatory human review wording and OT consultation checklist. |

**Helpful minor features:** OT/cyber terminology toggle, function-code descriptions, profile diagram, maintenance-context label, normal-versus-unexpected rule explanation, and “operational review required” marker.

**Helpful major feature:** collaborative review surface where an OT engineer can add process context without receiving access to unrelated private threat data.

**Success signals:** fewer misunderstood protocol actions, documented operational context, and no security decision represented as safe without process-owner review.

### Persona 8 — Honeypot sensor operator or platform engineer

**Context:** Deploys and maintains the decoy, monitors storage and health, rotates logs, validates isolation, upgrades dependencies, and ensures data can be handed off safely.

**Goals:**

- Know whether listeners, logging, queues, storage, time, and egress controls are healthy.
- Detect stale collection, disk pressure, dropped events, and delivery failures.
- Upgrade or roll back without data loss.
- Preserve the private/public boundary.
- Produce privacy-safe deployment evidence.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Health is distributed across CLI outputs/files | The operator must remember commands and interpret several signals. | Redacted readiness summary with runbook links. |
| Dashboard availability can be confused with sensor health | A working Streamlit page does not prove collection is active. | Separate Dashboard, Dataset, Sensor, Collector, and SOC-lab status. |
| Alert thresholds are not contextual | A stale synthetic dataset is normal; a stale live study may be a problem. | Mode-specific health policy and observation-window metadata. |
| Upgrades risk breaking collection | Container, OS, or dependency changes may affect ports, firewall assumptions, and storage. | Preflight, backup, canary validation, rollback, and configuration fingerprint. |
| Private evidence handling is manual | Copying logs can expose identifiers or create incomplete handoffs. | Deterministic private handoff pipeline already present; add operator-facing checklist/status. |

**Helpful minor features:** redacted status cards, “last healthy event” age, queue/disk bands, config fingerprint, runbook link, log-rotation status, update-check reminder, backup verification date, and expected-listener summary.

**Helpful major feature:** local operator console that reads approved redacted health artifacts and never exposes raw events or cloud identifiers.

**Success signals:** fast detection of stale or failed collection, documented recovery, zero public leakage, and verified restart/rollback.

### Persona 9 — Threat-intelligence researcher, report author, or academic reviewer

**Context:** Defines collection periods, analyzes patterns, evaluates methodology, compares windows, prepares a report, and defends the wording and limitations of every claim.

**Goals:**

- Reproduce an analysis from a specific dataset and revision.
- Distinguish observations from interpretations.
- Compare periods without overlap or provenance mixing.
- Track ATT&CK mapping confidence and rationale.
- Publish only approved aggregate results.
- Explain bias, coverage, and limitations.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Screenshot loses analytical context | Filters, data revision, exclusion counts, and generation time may be absent. | Report snapshot plus machine-readable manifest. |
| Frequency can be overclaimed | Event counts do not equal attackers or incidents, and honeypot exposure is not representative sampling. | Denominator/coverage notes and claim templates. |
| Mapping changes affect results | ATT&CK/rule/parser revisions can change classifications. | Analysis revision, schema, mapper version, and reproducibility manifest. |
| Publication approval is separate from technical validation | A privacy gate cannot approve legal, ethical, or methodological claims. | Explicit human approval workflow and sign-off record. |
| Research bias is hard to see | Cloud region, uptime, exposed ports, profiles, and sensor outages affect what was observed. | Collection coverage calendar and limitation generator. |

**Helpful minor features:** footnote-ready metric definitions, UTC/local time display, collection coverage %, excluded-record breakdown, analysis revision, citation export, chart-caption generator, claim confidence label, and methodology checklist.

**Helpful major features:** reproducible research workspace with dataset manifest, approved aggregate query definitions, period comparison, claim/limitation builder, report template, and publication-review checklist.

**Success signals:** another reviewer can reproduce the aggregate result; every chart states scope/provenance; zero claims confuse frequency with attribution or population prevalence.

### Persona 10 — Privacy, legal, compliance, audit, or risk reviewer

**Context:** Reviews what information is collected, stored, displayed, exported, shared, and retained. Needs evidence that controls work and that limitations are not hidden.

**Goals:**

- Identify data classification and purpose.
- Confirm raw identifiers and payloads do not enter public artifacts.
- Review retention, access, approval, and deletion procedures.
- Verify provenance and integrity.
- Trace each report claim back to a reviewed aggregate.
- Assess alignment with organizational and UAE requirements.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Public/private controls are technical | A reviewer needs a plain control narrative and evidence, not only tests. | Control-to-evidence matrix and data-flow diagram. |
| “Sanitized” can be vague | Without field-level transformations and residual-risk notes, approval is difficult. | Public schema, transformation table, canary tests, residual-risk checklist. |
| Retention is operationally separate | A valid export may still violate policy if private evidence is retained incorrectly. | Retention/deletion workflow and approval record. |
| Audit evidence is fragmented | Tests, checksums, commits, reports, and approvals are separate. | Release assurance bundle with immutable references. |
| Regional/compliance claims can become overconfident | A portfolio project cannot claim certification or legal compliance from technical controls alone. | “Supports review; does not certify compliance” wording everywhere. |

**Helpful minor features:** classification badge, privacy preflight result, export field list, retention reminder, human approval checkbox, checksum copy, policy reference field, and redaction summary.

**Helpful major feature:** publication review workspace that assembles a candidate artifact, validator evidence, field manifest, methodology, approvals, and release checksum without automatically publishing.

**Success signals:** complete evidence package, zero forbidden fields, documented residual risk, and clear human ownership of publication approval.

### Persona 11 — OT security manager, SOC manager, CISO, or program owner

**Context:** Allocates resources, reviews exposure and capability maturity, approves risk, and communicates with executives or regulators. Needs trends and limitations, not raw event detail.

**Goals:**

- Understand whether monitoring and analysis capabilities are operating.
- See coverage, gaps, trends, and data quality.
- Allocate work to rules, protocols, or operational improvements.
- Communicate risk without false precision.
- Verify that safety and privacy constraints are respected.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Technical counts do not answer management questions | Event volume alone does not show capability, exposure, or risk reduction. | Outcome-oriented capability and coverage summary. |
| Score implies false precision | A single number can hide evidence quality and operational context. | Score distribution plus factors, gaps, and decision status. |
| No workload picture | Managers cannot see unreviewed observations, detection gaps, or validation debt. | Work queue and aging metrics in a future private workflow. |
| No clear resource trade-offs | The system does not show which improvement produces the most analyst or assurance value. | Prioritized backlog using user value, safety, effort, evidence, and dependency. |

**Helpful minor features:** weekly summary, “known/unknown/not measured” states, coverage trend, backlog aging, validation freshness, and executive glossary.

**Helpful major feature:** management assurance view showing capability health, detection coverage, research quality, and open decisions—without raw telemetry or misleading “attack risk” scores.

**Success signals:** decisions are tied to evidence and owner; no management metric equates map prominence with risk; investment priorities are explainable.

### Persona 12 — MSSP analyst or multi-site service lead

**Context:** Would monitor several sensors, customers, or sites with different permissions, baselines, contacts, and retention rules. This is a conditional future persona, not a current target.

**Goals:**

- Maintain tenant and site separation.
- Compare sensor health and evidence across sites.
- Route cases to the correct customer contact.
- Apply shared detection content while respecting local exceptions.
- Report service quality and outcomes.

**Pain points and problem statements:**

| Pain point | Problem statement | Solution direction |
|---|---|---|
| Current app is single-user and local | Streamlit session state cannot provide tenancy, RBAC, durable audit, or collaborative cases. | Only build after a formal multi-user architecture decision. |
| One baseline does not fit every site | Expected protocol activity and maintenance differ. | Per-site profiles, rule exceptions, owners, and maintenance windows. |
| Cross-site comparison risks leakage | Shared views may reveal another tenant’s identifiers or trends. | Tenant-isolated storage, authorization tests, and aggregate policies. |
| Escalation ownership varies | The correct OT contact and response procedure differ by site. | Site-specific routing and runbook metadata. |

**Helpful major features:** multi-tenant case service, RBAC, site/sensor inventory, per-site baselines, routing/SLA workflow, audit log, retention policies, and customer-safe reporting. These requirements are migration triggers for a framework and database architecture beyond the current dashboard.

**Success signals:** provable tenant isolation, correct routing, complete audit history, and no cross-customer leakage.

## 7. Cross-persona root problems

The personas differ, but their pain points come from a smaller set of root causes:

| Root cause | Who feels it | Product consequence |
|---|---|---|
| Evidence concepts are easy to misread | Visitors, learners, analysts, managers | Counts become “attacks,” sources become “attackers,” and maps become attribution. |
| OT meaning and cyber meaning are separated | SOC analysts, control engineers, managers | Function codes, ATT&CK techniques, and process impact are interpreted inconsistently. |
| Volume, urgency, confidence, novelty, and operational impact are different dimensions | Analysts, researchers, managers | One score or one chart can dominate judgement incorrectly. |
| The system spans several tools | Learners, analysts, detection engineers, operators | Users lose context moving between map, sessions, ATT&CK, Wazuh, Suricata, reports, and runbooks. |
| Public and private workflows have different data needs | Analysts, researchers, privacy reviewers | A safe public export is too weak for a case; a rich private export is unsafe publicly. |
| A honeypot has narrow visibility and sampling bias | Researchers, responders, managers | Observed activity can be overgeneralized to a region or sector. |
| OT response carries safety and availability consequences | OT engineers, responders, managers | Automatic containment or alarmist recommendations can cause harm. |
| Evidence quality changes across parser, mapper, rule, and geolocation stages | Analysts, engineers, researchers | A clean visualization can conceal uncertainty or missing coverage. |
| Operational status is separate from analytical status | Operators, learners, managers | A running dashboard is mistaken for healthy collection or complete data. |
| Collaboration requires governance | Responders, privacy reviewers, managers, MSSPs | Notes, cases, approvals, and tenancy cannot safely live in casual session state. |

## 8. Minor feature opportunities

“Minor” means a bounded improvement that can usually be delivered without changing the data architecture or adding a new service. Minor does not mean unimportant. Many of these changes prevent serious misunderstanding.

Status vocabulary:

- **Enhance:** a related capability is shipped, but this specific improvement remains.
- **Net-new:** no equivalent is currently visible.
- **Conditional:** build only when the stated workflow/data mode exists.

### 8.1 Orientation, language, and first-use help

| ID | Feature | Users/problem solved | Status | Priority / effort | Acceptance and safety |
|---|---|---|---|---|---|
| MIN-001 | Role-based start cards: “I am learning,” “I am investigating,” “I am validating rules,” “I am preparing a report” | Helps users enter the correct workflow instead of scanning six views. | Net-new | P0 / S | Selection changes help/navigation only, never data or permissions. |
| MIN-002 | Persistent `Synthetic demo`, `Sanitized`, or `Private` dataset badge | Prevents screenshots or exports from losing data-status context. | Enhance | P0 / XS | Badge appears in every view and export preview. |
| MIN-003 | Metric info icons beside events, sessions, source groups, and control actions | Prevents counts from being interpreted as intrusions or people. | Enhance | P0 / XS | Tooltip includes “means” and “does not mean.” |
| MIN-004 | “What this screen can prove / cannot prove” drawer on every tab | Prevents overclaiming map, ATT&CK, detection, or score results. | Net-new | P0 / S | Copy is view-specific and tested for banned attribution language. |
| MIN-005 | OT protocol mini-glossary with Modbus, S7comm, IEC-104, PLC, HMI, SCADA | Helps non-OT analysts and visitors. | Enhance | P1 / S | Plain language plus link to methodology; no vendor claims. |
| MIN-006 | Side-by-side cyber and OT terminology | Helps control engineers and SOC analysts communicate. | Net-new | P1 / M | Terms reviewed by an OT practitioner before release. |
| MIN-007 | “Why synthetic data?” explanation | Shows that fixtures validate the pipeline safely rather than pretending to be captured attacks. | Enhance | P0 / XS | Includes a link to ethics and reproducibility evidence. |
| MIN-008 | First-use guided path with Skip and Restart | Reduces discovery time for visitors and learners. | Net-new | P1 / M | Fully keyboard accessible; no forced modal. |
| MIN-009 | Screen title subtitle describing the decision supported | Makes each view’s purpose obvious. | Enhance | P0 / XS | One sentence, no marketing claims. |
| MIN-010 | Example question chips such as “Show control activity” or “Which evidence has high confidence?” | Converts features into user tasks. | Net-new | P1 / S | Chips apply visible reversible filters. |

### 8.2 Filters, navigation, and workspace control

| ID | Feature | Users/problem solved | Status | Priority / effort | Acceptance and safety |
|---|---|---|---|---|---|
| MIN-011 | One Reset Workspace action | Clears confusing combinations of filters, focus, playback, selections, and local notes. | Net-new | P0 / S | Confirmation preserves notes unless explicitly selected; reset is testable. |
| MIN-012 | Unified active-filter chip row | Shows global and map-local state in one place. | Enhance | P0 / S | Each chip clears one scope only. |
| MIN-013 | Filter-result explanation | Tells users how many records were excluded by protocol, time, priority, confidence, control-only, and missing geography. | Net-new | P0 / M | Counts only; no raw values. |
| MIN-014 | No-result recovery actions | Prevents empty views from becoming dead ends. | Enhance | P0 / XS | Offers clear time, protocol, or all-filter reset based on actual state. |
| MIN-015 | Session-local saved filter presets | Helps analysts repeat common views without an account system. | Net-new | P1 / M | Allowlisted values only; no source IDs, notes, or raw fields. |
| MIN-016 | Safe URL state for public filters | Lets a reviewer reopen a non-sensitive view. | Conditional | P2 / M | Protocol, country, mode, and bounded time only; privacy test parses URL. |
| MIN-017 | Sticky context strip during scrolling | Prevents users from forgetting dataset, time window, and filters. | Enhance | P0 / S | Does not cover content at 200% zoom or narrow viewports. |
| MIN-018 | Back to previous map/filter state | Makes geographic focus and exploration reversible. | Enhance | P1 / S | Restores an allowlisted in-session state. |
| MIN-019 | Search within safe source/session tables | Reduces scrolling in larger approved datasets. | Net-new | P1 / S | Searches pseudonymous/public fields only. |
| MIN-020 | Column chooser with sensible role presets | Lets analysts, researchers, and learners see relevant fields without overcrowding. | Net-new | P2 / M | Private fields never become selectable in public mode. |

### 8.3 Investigation and triage microfeatures

| ID | Feature | Users/problem solved | Status | Priority / effort | Acceptance and safety |
|---|---|---|---|---|---|
| MIN-021 | Session-first/event-first toggle | Prevents repeated messages from dominating triage. | Net-new | P0 / M | Counts reconcile exactly between modes. |
| MIN-022 | First seen, last seen, duration, and request count in every session summary | Speeds basic investigation. | Enhance | P0 / S | Uses sanitized timestamps and counts. |
| MIN-023 | Human-readable operation names beside raw protocol terms | Helps analysts interpret function codes. | Enhance | P0 / S | Decoder evidence remains visible; label never invents process impact. |
| MIN-024 | Evidence-strength badge with tooltip | Clarifies high/medium/low ATT&CK confidence. | Enhance | P0 / XS | Tooltip states that confidence concerns mapping evidence, not actor identity. |
| MIN-025 | Public review-score factor chips | Makes the score scannable without hiding detail. | Enhance | P1 / S | Sum/factors match deterministic scoring tests. |
| MIN-026 | “Why this outranks that” comparison | Helps analysts compare two observations instead of trusting one score. | Net-new | P1 / M | Compares factors, not probability or risk. |
| MIN-027 | Explicit “insufficient evidence” state | Prevents forced escalation from weak observations. | Net-new | P0 / S | Available independently of severity. |
| MIN-028 | Review states: unreviewed, routine, expected test, needs context, investigate, tuning candidate | Represents real analyst outcomes. | Enhance | P0 / S | Local/private only; public exports exclude state and notes. |
| MIN-029 | Review-state reason presets plus free-text note | Improves consistency while preserving analyst judgement. | Net-new | P1 / M | Notes never enter public browser exports. |
| MIN-030 | Selected-observation counter and clear-selection button | Makes investigation state obvious. | Enhance | P0 / XS | Keyboard accessible and reversible. |
| MIN-031 | Related-observations panel by protocol, technique, operation, and session | Helps analysts find context without using geography as identity. | Net-new | P1 / M | Bounded results; relation logic is displayed. |
| MIN-032 | Safe correlation ID copy button | Improves Wazuh/Suricata/report handoff. | Net-new | P1 / S | Copies pseudonymous/event correlation IDs only. |
| MIN-033 | Deterministic sequence labels: reconnaissance, read, write/control, malformed/error | Makes sessions easier to scan. | Net-new | P1 / M | Label states observed sequence, not attacker intent. |
| MIN-034 | Sequence completeness indicator | Reminds responders that the honeypot may see only part of a broader activity chain. | Net-new | P1 / S | Uses “observed/not observed,” never “did not occur.” |
| MIN-035 | “Recommended next step” with owner role | Turns findings into safe, non-automated work. | Enhance | P0 / S | Uses verbs such as review, compare, validate, consult; never block/retaliate. |
| MIN-036 | OT consultation flag | Helps responders record that operational review is required. | Conditional | P1 / S | Private workflow only; no effect on sensor/network. |
| MIN-037 | Selection comparison tray with one-click remove/reorder | Improves the shipped aggregate comparison flow. | Enhance | P1 / S | Remains capped at three safe aggregate observations. |
| MIN-038 | Highlight the exact event fields supporting each ATT&CK mapping | Improves explainability. | Net-new | P0 / M | Show decoded allowlisted fields, never raw payload bytes. |
| MIN-039 | Score/data-quality separation | Prevents a weakly located or partially decoded record from appearing highly trustworthy. | Net-new | P0 / M | Two distinct labels: review priority and evidence/data quality. |
| MIN-040 | Analyst action history for the current session | Helps users undo and understand filter/selection changes. | Net-new | P2 / M | In-memory only until private audit architecture exists. |

### 8.4 Map and time-analysis microfeatures

| ID | Feature | Users/problem solved | Status | Priority / effort | Acceptance and safety |
|---|---|---|---|---|---|
| MIN-041 | Permanent “map represents” card | Prevents the map from becoming a global threat or attribution claim. | Enhance | P0 / XS | Visible in all map modes and snapshots. |
| MIN-042 | Shape/pattern encoding in addition to protocol colour | Improves accessibility and print use. | Net-new | P1 / M | Works in grayscale and high-contrast mode. |
| MIN-043 | Data-quality coverage beside map | Shows mapped, unmapped, invalid, and filtered counts. | Net-new | P0 / M | Aggregate counts only. |
| MIN-044 | “Replay of recorded dataset” label | Prevents playback from being mistaken for a live feed. | Enhance | P0 / XS | Persistent while playback controls are visible. |
| MIN-045 | UTC/local-time toggle with timezone label | Helps operators and report authors without losing canonical UTC. | Net-new | P1 / S | Exports always include UTC and optional display timezone. |
| MIN-046 | Adjacent-window overlap warning | Prevents invalid trend interpretation. | Enhance | P0 / XS | Comparison helper/test proves non-overlap. |
| MIN-047 | Window-coverage percentage | Shows whether downtime or partial collection affects comparison. | Net-new | P1 / M | Requires safe collection metadata, not inferred from event count alone. |
| MIN-048 | “No meaningful change” threshold explanation | Prevents tiny deltas from being overemphasized. | Enhance | P1 / S | Threshold is visible and deterministic. |
| MIN-049 | First-seen-in-window marker | Helps find novel observations. | Net-new | P1 / M | Baseline definition displayed; empty baseline handled explicitly. |
| MIN-050 | Technique-focused map highlight | Connects map evidence to ATT&CK. | Net-new | P1 / M | Does not imply geographic causality. |

### 8.5 Detection-engineering microfeatures

| ID | Feature | Users/problem solved | Status | Priority / effort | Acceptance and safety |
|---|---|---|---|---|---|
| MIN-051 | Rule state badge: offline prediction, native fixture validated, not validated | Prevents evidence-state confusion. | Enhance | P0 / S | State derives from checked evidence, not label text alone. |
| MIN-052 | Rule version and engine version | Shows whether validation is current. | Net-new | P0 / S | Values come from repository evidence manifest. |
| MIN-053 | Last native-validation date | Makes stale validation visible. | Net-new | P0 / S | Never use dashboard wall clock as validation proof. |
| MIN-054 | Positive and negative fixture counts | Shows basic rule-test breadth. | Net-new | P1 / S | Counts link to fixture paths. |
| MIN-055 | Unique sessions matched per rule | Prevents repeated events from overstating coverage. | Net-new | P1 / M | Uses sanitized/session identifiers. |
| MIN-056 | Copyable local test command | Reduces rule-validation friction. | Net-new | P0 / XS | Command uses synthetic fixture path only. |
| MIN-057 | Parser → mapper → rule evidence chain | Shows where coverage succeeds or stops. | Net-new | P1 / M | Every stage has explicit pass/gap/not-applicable state. |
| MIN-058 | “Create gap note” local action | Converts uncovered behavior into a documented task. | Net-new | P1 / S | Produces no automatic GitHub issue or external write. |
| MIN-059 | Rule tuning reason and safe fixture link | Preserves engineering history. | Net-new | P1 / M | Stored in code/docs, not private telemetry. |
| MIN-060 | Engine filter and coverage summary | Lets engineers compare Sigma/Wazuh/Suricata scope. | Enhance | P0 / S | Does not claim semantic equivalence across engines. |

### 8.6 Research, reporting, and export microfeatures

| ID | Feature | Users/problem solved | Status | Priority / effort | Acceptance and safety |
|---|---|---|---|---|---|
| MIN-061 | Export manifest containing dataset status, schema, revision, window, filters, and generation time | Makes results reproducible. | Enhance | P0 / M | Manifest passes publication validation. |
| MIN-062 | Report-ready snapshot layout | Avoids inconsistent manual screenshots. | Net-new | P1 / M | Includes provenance and approximate-geography caveat. |
| MIN-063 | Auto-generated chart caption | Helps authors explain metric, scope, and limitation. | Net-new | P1 / S | Uses deterministic template, not unsourced causal language. |
| MIN-064 | Claim builder: observation, interpretation, limitation | Separates evidence from inference. | Net-new | P1 / M | User must approve final wording. |
| MIN-065 | Collection coverage calendar | Shows uptime/gaps affecting research claims. | Conditional | P1 / M | Uses approved aggregate health metadata only. |
| MIN-066 | Excluded-record reason table | Explains mapping/data-quality limits. | Net-new | P0 / M | Counts only; no rejected raw values. |
| MIN-067 | Citation-ready ATT&CK technique links | Improves report traceability. | Enhance | P1 / S | Version/permalink recorded. |
| MIN-068 | Analysis revision and commit ID in exports | Makes mapper/parser/rule state reproducible. | Net-new | P0 / S | Public Git commit only; no host/cloud IDs. |
| MIN-069 | Approved wording templates for frequency and uncertainty | Reduces “top attackers” or “global attacks” overclaims. | Net-new | P0 / S | Reviewed by methodology/privacy owner. |
| MIN-070 | Human publication checklist beside export | Makes legal/ethical approval visible. | Net-new | P0 / S | Technical pass cannot auto-check human approvals. |

### 8.7 Privacy, governance, and assurance microfeatures

| ID | Feature | Users/problem solved | Status | Priority / effort | Acceptance and safety |
|---|---|---|---|---|---|
| MIN-071 | Public/private mode indicator beside every download | Prevents wrong-intent exports. | Enhance | P0 / XS | Public download always executes the fail-closed gate. |
| MIN-072 | Privacy preflight summary | Gives reviewers visible evidence before export. | Net-new | P0 / M | Shows pass/fail and field categories, not sensitive values. |
| MIN-073 | Export field manifest | Makes “sanitized” concrete. | Net-new | P0 / S | Exact allowlisted fields shown. |
| MIN-074 | Redaction/transformation summary | Explains pseudonymization and removed categories. | Net-new | P1 / M | Does not reveal salt, originals, or canary values. |
| MIN-075 | Retention reminder on private workflow | Connects export/analysis to policy. | Conditional | P1 / S | Policy-configurable; no automatic deletion without explicit design. |
| MIN-076 | Human approval record for publication candidate | Separates technical and human decisions. | Conditional | P1 / M | Identity/audit storage requires private workflow controls. |
| MIN-077 | Checksums with copy/verify action | Supports integrity and handoff. | Enhance | P1 / S | Uses released/candidate artifact only. |
| MIN-078 | “Supports review; does not certify compliance” banner | Prevents unsupported NESA/UAE IA/DESC compliance claims. | Net-new | P0 / XS | Appears near compliance references and reports. |
| MIN-079 | Privacy-boundary regression matrix | Helps contributors see which UI/export surfaces are tested. | Net-new | P1 / M | Links tests to fields and outputs. |
| MIN-080 | Sensitive-language linter for UI/report copy | Finds “attacker,” “victim,” “breach,” or attribution claims without evidence. | Net-new | P1 / M | Reviewed allowlist for legitimate methodology text. |

### 8.8 Operations, accessibility, and quality-of-life microfeatures

| ID | Feature | Users/problem solved | Status | Priority / effort | Acceptance and safety |
|---|---|---|---|---|---|
| MIN-081 | Separate status cards for Dashboard, Dataset, Sensor, Collector, and SOC lab | Prevents one component’s status from standing in for the whole system. | Net-new | P0 / M | Unknown is shown as unknown; no invented green status. |
| MIN-082 | Redacted status snapshot import | Lets the local dashboard explain health without connecting to Oracle. | Conditional | P1 / M | File contains only approved aggregate health metadata. |
| MIN-083 | Runbook link on each status warning | Converts operator alarms into exact safe steps. | Net-new | P0 / S | Link target is versioned and local. |
| MIN-084 | Disk, queue, drop, stale, delivery, and clock-skew bands | Improves operator triage. | Enhance | P1 / M | Threshold/mode displayed; no secrets or paths. |
| MIN-085 | Configuration fingerprint | Proves which safe configuration class was used without showing OCIDs, addresses, or keys. | Net-new | P1 / M | Fingerprint input fields are explicitly allowlisted. |
| MIN-086 | Reduced-motion option and no autoplay | Supports accessibility and avoids misleading “live” activity. | Net-new | P0 / S | Respects user preference and persists locally. |
| MIN-087 | Full keyboard route through filters, table selection, evidence, and export | Supports non-pointer users. | Enhance | P0 / M | Task-completion test covers the full path. |
| MIN-088 | Screen-reader summary of charts/maps | Provides equivalent evidence when visuals are inaccessible. | Net-new | P1 / M | Summary uses same filtered data and caveats. |
| MIN-089 | High-contrast and grayscale verification | Prevents colour-only meaning. | Net-new | P0 / S | Visual checklist or automated contrast test passes. |
| MIN-090 | Loading, partial-data, tile-failure, and parser-error states | Makes failure modes understandable. | Enhance | P0 / M | Every state distinguishes missing visualization from missing evidence. |
| MIN-091 | Narrow-screen investigation drawer | Improves touch/small-screen usability. | Net-new | P2 / M | Verify at 390 px and 200% zoom on real devices. |
| MIN-092 | Export filename with dataset type, UTC window, and revision | Prevents ambiguous downloaded files. | Net-new | P0 / XS | Contains no source ID or private metadata. |
| MIN-093 | Copy feedback and error messages in plain language | Reduces uncertainty after actions. | Enhance | P0 / XS | Messages explain outcome and recovery action. |
| MIN-094 | User-visible changelog for dashboard interactions | Helps demos and audits track what changed. | Net-new | P1 / S | Links feature to verification evidence. |
| MIN-095 | Feedback button that stores no telemetry by default | Creates a path for user research without adding analytics tracking. | Conditional | P2 / M | Opens local template or user-controlled issue draft; no automatic submission. |

## 9. Major feature opportunities

Major features alter a workflow, introduce durable data, integrate tools, or require architecture/security decisions.

| ID | Major feature | Primary users | Problem solved | Prerequisites and safety | Recommended timing |
|---|---|---|---|---|---|
| MAJ-01 | Guided investigation workspace | SOC analysts, learners | Combines selected observation, session sequence, decoded evidence, ATT&CK rationale, score factors, detection coverage, and next step in one coherent flow. | Public mode uses sanitized data only; no automatic response. | P0/P1 |
| MAJ-02 | Session-centric correlation engine | SOC L2/L3, researchers | Groups reconnaissance → read → write/control patterns and related observations. | Deterministic rules, visible relation logic, bounded windows, no intent claim. | P1 |
| MAJ-03 | Detection engineering workbench | Detection engineers | Unifies parser/mapping/rule coverage, fixtures, native validation, gaps, and tuning history. | Synthetic fixtures first; engine states kept distinct. | P1 |
| MAJ-04 | Reproducible research workspace | Researchers/report authors | Packages dataset manifest, queries, comparisons, captions, claims, limitations, and publication review. | Aggregate/privacy gate plus human approval; no automatic publication. | P1 |
| MAJ-05 | Publication assurance workspace | Privacy/audit/research | Makes field transforms, validator results, methodology, approvals, and checksums reviewable together. | Private approval storage and access design if identities are recorded. | P1/P2 |
| MAJ-06 | OT profile and expected-behavior model | OT security/control engineers | Compares observations with expected protocols, operations, roles, and fictional/approved process context. | Profiles must remain fictional in public mode; private asset data requires strict access. | P1 |
| MAJ-07 | Read-only operator assurance console | Sensor operator, owner | Consolidates redacted health, freshness, queue, disk, delivery, rotation, backup, and validation state. | Reads approved local status artifacts; no direct cloud control or secrets. | P1 |
| MAJ-08 | Safe private investigation bundle | SOC/IR analysts | Preserves evidence, filters, rationale, notes, rule IDs, provenance, and checksum for handoff. | Separate public/private workflows; encrypted/private storage; retention policy. | P1/P2 |
| MAJ-09 | Evidence graph | IR, threat hunters, researchers | Shows relationships among sessions, operations, techniques, rules, reports, and decisions. | Relationship types explicit; geography not identity; bounded rendering. | P2 |
| MAJ-10 | Collection-quality and research-bias module | Researchers, managers | Quantifies uptime, exposure/config changes, mapping coverage, excluded records, and study limitations. | Uses safe metadata; avoids claiming representativeness. | P1 |
| MAJ-11 | Protocol learning lab | Learners, SOC analysts, control engineers | Teaches request/response structure, decoded action, ATT&CK hypothesis, and rule result with safe exercises. | Synthetic traffic only; no arbitrary payload execution. | P1 |
| MAJ-12 | Report composer | Researchers, project owner | Produces repeatable Markdown/PDF sections from reviewed aggregate evidence. | Templates preserve provenance/limitations and require human review. | P1 |
| MAJ-13 | Detection replay and fixture builder | Detection engineers | Creates sanitized/synthetic positive and negative cases and runs local engine validation. | No live PCAP publication; resource limits; disposable lab. | P2 |
| MAJ-14 | Controlled Wazuh/Suricata investigation handoff | SOC/detection engineers | Moves validated sanitized evidence and stable correlation IDs into tools without manual copying. | One-way, privacy-gated, retry-safe; engine version validation. | P2 |
| MAJ-15 | Multi-sensor coverage view | OT architects, managers | Shows sensor identity, protocol/profile coverage, health, and approved aggregate differences across sites. | Authenticated sensors, secure identities, clock policy, site isolation; no public raw data. | P2 |
| MAJ-16 | Private collaborative case service | IR teams, MSSP | Adds durable cases, RBAC, notes, decisions, audit, retention, and assignment. | Formal architecture migration, identity provider, database, authorization tests, backup/restore. | Conditional P3 |
| MAJ-17 | Multi-tenant MSSP platform | MSSP/service lead | Supports tenants, SLAs, per-site profiles, routing, and customer reporting. | Tenant isolation, RBAC/ABAC, audit, legal agreements, scaling evidence. | Conditional P3 |
| MAJ-18 | Approved asset-context integration | OT engineer, responder | Adds owner, zone, asset class, expected services, logging, backup, and process criticality. | Private deployment only; minimal fields; access/retention controls; read-only join. | Conditional P2/P3 |
| MAJ-19 | Safe saved investigations | Analysts/reviewers | Restores filter/selection/comparison context without losing provenance. | Public saved views exclude IDs/notes; private saved work requires identity and storage controls. | P1 public / P3 private |
| MAJ-20 | Management assurance and work-priority view | Managers | Shows capability coverage, quality, review backlog, validation freshness, and open decisions. | No fake risk KPI; metrics linked to evidence and limitations. | P2 |
| MAJ-21 | Structured OT consultation workflow | Responders/control engineers | Records operational context and approval before response recommendations. | Private workflow, role controls, audit, no automatic control action. | P2/P3 |
| MAJ-22 | Privacy-safe project demonstration mode | Learner/recruiter | Runs a predictable five-minute evidence story with screenshots and validation results. | Synthetic dataset locked; every screen carries provenance. | P1 |

## 10. Highest-value problem-to-solution matrix

This matrix identifies the problems worth solving first. It is intentionally more selective than the complete feature inventory.

| Rank | Problem statement | Affected users | Recommended solution | Why now | Proof of value |
|---:|---|---|---|---|---|
| 1 | Users mistake events, sessions, sources, map points, or ATT&CK matches for attacks or attackers. | Visitors, learners, analysts, managers | MIN-003, MIN-004, MIN-041, approved wording templates | Misinterpretation undermines the project’s credibility and can create unsafe claims. | 90% of test users correctly define all four counts and map limitation. |
| 2 | Analysts still move between several views to reconstruct one investigation. | SOC L1/L2, learner | MAJ-01 guided investigation workspace | Existing evidence is strong; workflow cohesion creates more value than another chart. | Median selection-to-explanation time decreases without more errors. |
| 3 | Event volume can dominate triage even when it is repeated scanner noise. | SOC analysts, researchers | MIN-021, MIN-022, MIN-026, MIN-033 | Current session data can support better grouping without new private fields. | Analysts choose the same priority as reviewed fixture labels more consistently. |
| 4 | OT operation names and process implications are difficult for non-OT analysts. | SOC, control engineers, learners | MIN-006, MIN-023 and OT-reviewed glossary | Cross-functional language is a documented OT requirement. | Users explain the observed operation accurately without inventing impact. |
| 5 | Public review score can appear more certain than its inputs. | Analysts, visitors, managers | MIN-025, MIN-026, MIN-039 | Explainability is already present and can be made comparative. | Users cite factors and uncertainty rather than only the number. |
| 6 | Detection coverage is not one connected engineering workflow. | Detection engineers | MAJ-03 plus MIN-051–060 | The repository already has rules, fixtures, previews, and native validation evidence. | A user identifies an uncovered behavior and runs the correct fixture test quickly. |
| 7 | Public and private export needs are fundamentally different. | Analysts, researchers, privacy reviewers | MIN-071–077 and MAJ-08 | Current public safety must remain fail-closed as richer handoff develops. | Zero forbidden public fields and successful private handoff review. |
| 8 | A report screenshot can lose filters, revision, coverage, and provenance. | Researchers, reviewers | MIN-061–070, MAJ-04/12 | Current export/report tooling makes this an incremental step. | Independent reviewer reproduces every aggregate in the report. |
| 9 | A healthy dashboard can be mistaken for a healthy sensor or complete dataset. | Operators, learners, managers | MIN-081–085, MAJ-07 | This confusion has already appeared during setup and demonstration. | Users correctly identify which component is healthy, unknown, or stale. |
| 10 | Normal OT behavior, maintenance, and errors can resemble malicious activity. | SOC, OT engineers, detection engineers | MAJ-06 plus maintenance/context labels | NIST recommends normal-state baselining and alert tuning. | Reduced nuisance classifications without hiding control behavior. |
| 11 | Recommendations can ignore operational safety and availability. | Responders, OT engineers, managers | MIN-035/036 and MAJ-21 | OT response must remain human and cross-functional. | Every response recommendation records OT consultation or explains why not applicable. |
| 12 | Honeypot observations can be overgeneralized as UAE/global threat prevalence. | Researchers, managers, visitors | MIN-064/065/069 and MAJ-10 | The research-grade claim depends on honest sampling limitations. | Reports state exposure, uptime, coverage, and non-representativeness. |
| 13 | Rule prediction and native-engine validation can be confused. | Analysts, detection engineers, visitors | MIN-051–053 | A small lab label error can become a large credibility error. | Users correctly distinguish every rule state. |
| 14 | Users cannot preserve a defensible review reason. | SOC/IR, researchers | MIN-028/029, MAJ-08 | Decision rationale is part of handoff and later tuning. | Escalated reviews include evidence, state, reason, and provenance. |
| 15 | Data quality is hidden behind clean visualizations. | Analysts, researchers, managers | MIN-039/043/047/066 and MAJ-10 | Missing coordinates/parser coverage change interpretation. | Users can explain coverage and excluded records before making a claim. |
| 16 | Learners cannot quickly diagnose which component failed. | Learner/operator | MIN-081/083/090 and component-specific quick start | Existing runbooks are deep but not task-local. | Reduced wrong-directory/port/tool troubleshooting steps. |
| 17 | A control engineer lacks a useful, low-jargon review surface. | OT operator/control engineer | MIN-006/023 and MAJ-21 | OT expertise is required for credible interpretation. | OT reviewers complete a scenario without needing ATT&CK expertise. |
| 18 | Saved work and collaboration tempt unsafe ad hoc persistence. | Analysts, IR, MSSP | MAJ-08/16/19 with explicit architecture gates | Session state is not a case system. | No private note/source ID enters public state; private audit tests pass before launch. |
| 19 | Larger datasets can degrade map usability and browser reliability. | Analysts, researchers | Pre-aggregation, clustering, bounded traces, load tests | Scale should be measured before a frontend rewrite. | Documented supported rows/traces and render-time budget. |
| 20 | Managers receive technical volume instead of decision-oriented assurance. | Security leadership | MAJ-20 | Management needs coverage, quality, ownership, and open decisions. | Managers identify top capability gap without interpreting raw event counts. |

## 11. Recommended roadmap

### Phase 0 — validate users before more architecture

**Objective:** verify that the assumed personas and task priorities are correct.

1. Run moderated tests with a learner, SOC analyst, detection engineer, OT/control engineer, researcher, operator, and privacy reviewer.
2. Record misunderstandings, completion time, dead ends, confidence, and unsafe claims.
3. Use only the synthetic dataset and local/native fixture evidence.
4. Rank failures by frequency, severity, and cross-persona impact.

No large architecture change should precede this phase.

### Phase 1 — clarity and investigation cohesion

Recommended next release:

1. MIN-003/004/009: metric and view-specific explainability.
2. MIN-011–014/017: workspace reset, unified filters, exclusion counts, recovery, sticky context.
3. MIN-021–024/027/033/038/039: session-first triage, evidence fields, insufficient-evidence state, sequence and data-quality separation.
4. MIN-041/043/044/046: permanent map semantics, map coverage, replay label, comparison integrity.
5. MIN-051–053/056/060: precise detection evidence state, versions, date, command, and engine summary.
6. MIN-061/066/068–073/078: reproducible export, excluded reasons, revision, wording, checklist, mode, preflight, manifest, compliance caveat.
7. MIN-081/083/086/087/089/090/092: component status, runbook link, accessibility, failure states, and safe filenames.
8. Begin MAJ-01 as a composition of existing public-safe components, not a new service.

**Definition of done:**

- A first-time visitor can explain the evidence boundary.
- A SOC analyst can move from summary to session evidence and a next step without losing context.
- A detection engineer can distinguish prediction from native validation.
- A researcher can reproduce an exported aggregate.
- A keyboard user can complete the same core task.
- No new surface exposes a forbidden field or implies attribution.

### Phase 2 — detection, research, and operational assurance

Build only after Phase 0 research confirms demand:

1. MAJ-03 detection engineering workbench.
2. MAJ-04/10/12 reproducible research, collection-quality, and report composition.
3. MAJ-06 expected-behavior/profile model using fictional public profiles first.
4. MAJ-07 read-only redacted operator assurance.
5. MAJ-11 protocol learning lab.
6. MAJ-19 public-safe saved views.

**Definition of done:** each feature has a named user, observed task failure, deterministic data source, privacy assessment, acceptance test, and rollback plan.

### Phase 3 — private handoff and collaboration

Only after governance and storage requirements are defined:

1. MAJ-08 private investigation bundle.
2. MAJ-09 evidence graph.
3. MAJ-13/14 detection replay and controlled SOC handoff.
4. MAJ-18 approved private asset context.
5. MAJ-21 structured OT consultation.

**Definition of done:** private/public separation, encryption, access, retention, audit, backup, restore, and deletion are verified—not merely documented.

### Phase 4 — multi-user or multi-tenant product

Build only if real users require sustained collaboration:

1. MAJ-15 multi-sensor coverage.
2. MAJ-16 private case service.
3. MAJ-17 MSSP tenancy.
4. MAJ-20 management assurance.

This is the point at which the current framework-free collector and Streamlit presentation may need a separate authenticated application layer. It should be triggered by proven requirements, not by a desire to add Flask, Django, or React.

## 12. Prioritization model

Score proposed features from 1–5 on each factor:

| Factor | Question | Weight |
|---|---|---:|
| User value | Does this remove a frequent or severe task failure? | 25% |
| Safety and trust | Does it reduce overclaiming, privacy risk, or unsafe OT action? | 25% |
| Evidence readiness | Do approved fields, fixtures, and tests already support it? | 15% |
| Cross-persona benefit | Does it help more than one priority user? | 10% |
| Reproducibility | Can another person verify the result? | 10% |
| Effort | Can it be built and maintained simply? Higher score means lower effort. | 10% |
| Architectural reversibility | Can it be removed or changed without migrating private state? | 5% |

Calculate:

`priority = value×0.25 + safety×0.25 + readiness×0.15 + cross_persona×0.10 + reproducibility×0.10 + effort×0.10 + reversibility×0.05`

This score prioritizes development work; it is unrelated to the dashboard’s public review score.

### Initial priority judgement

| Feature | User value | Safety/trust | Readiness | Overall recommendation |
|---|---:|---:|---:|---|
| MAJ-01 Guided investigation workspace | 5 | 5 | 5 | Build next through composition of shipped components. |
| MIN-003/004 Metric and proof boundaries | 5 | 5 | 5 | Immediate. |
| MIN-021 Session-first triage | 5 | 4 | 4 | Immediate/next. |
| MIN-039/043 Data-quality separation | 5 | 5 | 4 | Immediate/next. |
| MAJ-03 Detection workbench | 5 | 4 | 4 | High-value Phase 2. |
| MAJ-04 Research workspace | 5 | 5 | 4 | High-value Phase 2. |
| MAJ-07 Operator assurance | 4 | 5 | 3 | Validate operator workflow, then build read-only. |
| MAJ-06 Expected-behavior model | 5 | 4 | 3 | Start with fictional profiles and expert review. |
| MAJ-16 Multi-user case service | 4 | 3 | 1 | Defer until collaboration is proven. |
| MAJ-17 Multi-tenant MSSP platform | 3 | 2 | 1 | Explicitly defer. |

## 13. Product metrics by user outcome

### 13.1 First-time comprehension

| Metric | Desired direction | Failure it detects |
|---|---|---|
| Time to correctly explain what OT Sentinel does | Down | Weak orientation |
| Percentage distinguishing events, sessions, sources, and intrusions | Up | Metric ambiguity |
| Percentage stating map geography is approximate/non-attributive | Up | Unsafe map inference |
| Percentage recognizing synthetic data as pipeline evidence | Up | “Fake dashboard” misunderstanding |

### 13.2 Analyst effectiveness

| Metric | Desired direction | Failure it detects |
|---|---|---|
| Time from overview to selected evidence | Down | Navigation friction |
| Time from selection to defensible review state | Down | Weak decision support |
| Percentage of escalations with rationale/evidence | Up | Unsupported escalation |
| Event-count versus session-count errors | Down | Noise inflation |
| Reviews using “insufficient evidence/needs context” correctly | Up | Forced alarmism |

### 13.3 Detection engineering

| Metric | Desired direction | Failure it detects |
|---|---|---|
| Behaviors with parser + mapping + rule + positive/negative fixture coverage | Up | Coverage gaps |
| Rules with current native validation evidence | Up | Stale/unproven rules |
| Offline/native evidence-state mistakes in testing | Zero | Misleading rule claims |
| Median gap-to-tested-rule time | Down | Engineering friction |

### 13.4 Research and publication

| Metric | Desired direction | Failure it detects |
|---|---|---|
| Reproducible report aggregates | 100% | Missing manifests/revisions |
| Public candidates rejected by privacy gate before publication | Visible and resolved | Unsafe fields/process |
| Published artifacts with provenance, scope, and limitations | 100% | Overclaiming |
| Claims using attribution or population prevalence without evidence | Zero | Research integrity failure |

### 13.5 Operations

| Metric | Desired direction | Failure it detects |
|---|---|---|
| Time to detect stale collection or delivery failure | Down | Weak monitoring |
| Time to reach the correct runbook step | Down | Troubleshooting friction |
| Successful restart/rollback/backup verification | Up | Operational fragility |
| Public leakage incidents | Zero | Boundary failure |

### 13.6 Metrics not to optimize

Do not treat these as success metrics without context:

- More events, sources, countries, or map paths.
- Higher public review scores.
- More ATT&CK techniques mapped.
- More alerts generated.
- More visual animation or real-time appearance.
- More external integrations.
- More users before privacy, identity, and support models exist.

These can increase while the product becomes less trustworthy.

## 14. User-research validation plan

### 14.1 Participants

Minimum first round: 12 participants.

| User type | Participants | Why |
|---|---:|---|
| Nontechnical visitor/recruiter | 2 | Tests first-use comprehension and project credibility. |
| Cybersecurity learner | 2 | Tests setup, explanation, and learning workflow. |
| SOC analyst | 2 | Tests triage, investigation, and handoff. |
| Detection engineer | 1 | Tests rule evidence and coverage workflow. |
| OT/control engineer or operator | 2 | Tests protocol/process language and safety. |
| Research/report reviewer | 1 | Tests reproducibility and claims. |
| Privacy/audit reviewer | 1 | Tests publication and field controls. |
| Sensor/platform operator | 1 | Tests health and recovery workflow. |

If these exact roles are unavailable, record the substitution and do not treat a student proxy as an OT operator or experienced SOC analyst.

### 14.2 Standard synthetic-only tasks

1. Explain what the dashboard is and whether the data is real.
2. Define event, session, pseudonymous source, control action, and ATT&CK hypothesis.
3. Find the most review-worthy control behavior without using only event volume.
4. Select an observation and explain the decoded evidence.
5. State why its public review score is higher or lower than another.
6. Decide whether the evidence is routine, needs context, or deserves deeper investigation.
7. Open the relevant session and ATT&CK rationale.
8. Determine whether a detection is an offline prediction or native fixture validation.
9. Produce a safe aggregate export and explain its provenance.
10. State at least four things the application cannot prove.
11. Diagnose a simulated stale-dataset or tile-failure state.
12. Explain which role must be consulted before an OT response recommendation.

### 14.3 Interview questions

- What did you expect this screen to show before using it?
- Which number or label did you trust first, and why?
- What did you think a source bubble represented?
- Which evidence changed your decision?
- What information was missing for you to act confidently?
- Which view or term felt unnecessary?
- What would you need to share this with a colleague?
- What would make you refuse to use or approve this system?
- Which action could be unsafe in a real OT environment?
- If you could add only one capability, what decision would it help you make?

### 14.4 Observation sheet

For each task record:

- completed / completed with help / failed;
- time to completion;
- wrong assumption;
- navigation dead end;
- evidence used;
- confidence before and after;
- unsafe claim or action;
- feature request in the participant’s own words;
- whether the request is a root need or a proposed solution.

Do not record private telemetry, credentials, personal data beyond agreed research notes, or any live Oracle content.

### 14.5 Decision rule after research

- Fix any misunderstanding that could cause privacy leakage, attribution, or unsafe OT action even if only one credible participant encounters it.
- Prioritize a workflow feature when at least three relevant users share the same task failure or when one expert identifies a severe OT safety issue.
- Do not build a multi-user backend because participants casually ask for “sharing.” First determine whether a privacy-safe bundle or saved public view solves the actual need.
- Retest the same tasks after implementation; a positive opinion is weaker evidence than successful task completion.

## 15. Features and claims to defer or reject

| Proposal | Decision | Reason |
|---|---|---|
| Raw IP reveal in the public dashboard | Reject | Violates privacy boundary and adds little defensible user value. |
| Threat-actor, organization, or victim attribution | Reject | Honeypot evidence and coarse geography cannot prove identity. |
| Automatic retaliation, scanning back, blocking, or OT control action | Reject | Ethical, legal, and OT safety risk; outside honeypot purpose. |
| “Live attacks” animation for recorded/synthetic data | Reject | Misleading product behavior. |
| Decorative 3D globe | Defer/reject | Adds visual complexity without a user decision. |
| AI-generated incident conclusions without evidence citations | Reject | Encourages confident unsupported interpretation. |
| Automatic public release of live telemetry/reports | Reject | Publication requires human privacy, legal, and methodology review. |
| Public user uploads | Defer | Creates malware, privacy, storage, and moderation requirements. |
| Public accounts/comments | Defer | Requires identity, abuse, retention, and moderation design. |
| Flask/Django/React migration for appearance alone | Defer | Architecture should follow proven workflow/scale requirements. |
| Multi-tenancy without isolation tests and governance | Reject until prerequisites exist | Cross-customer exposure would be severe. |
| One universal “risk” score | Reject | Hides confidence, evidence quality, operational impact, and context. |
| Country leaderboards or “top attacker countries” | Reject | Encourages attribution and prevalence claims unsupported by the study. |

## 16. Architecture and governance triggers

Retain the current minimal collector and Streamlit public dashboard while the application has a small number of read-only analytical views and local/session review state.

Reconsider a separate authenticated application layer only when one or more are proven:

- multiple analysts need durable shared investigations;
- role-based permissions and approvals are required;
- private case-management data must be stored;
- multi-tenant or multi-site isolation is required;
- external SIEM/SOAR consumers need a stable service API;
- workload, query, or rendering measurements exceed the safe current design;
- audit, retention, backup, and restore requirements cannot be satisfied locally.

Any migration should preserve collector security controls, run in parallel first, replay sanitized fixtures through both paths, prove black-box parity, and retain rollback.

## 17. Final product recommendation

The best next product is not “a bigger dashboard.” It is a **guided, evidence-first OT investigation and learning workspace** with three carefully separated outcomes:

1. **Public demonstration:** understandable, reproducible, synthetic/sanitized, and impossible to mistake for attribution.
2. **Local engineering:** strong mapping, detection, privacy, research, and operational validation using fixtures and approved data.
3. **Future private investigation:** richer handoff, context, and collaboration only after identity, authorization, retention, audit, and safety governance exist.

The most valuable immediate work is to make evidence concepts unmistakable, group triage around sessions and sequences, connect the existing views into one investigation flow, expose data quality and rule-validation state, and make every export reproducible. These changes help nearly every priority user while keeping the current architecture, cost model, and safety boundary intact.

## 18. Repository evidence consulted

- `docs/FEATURE_CATALOG.md`
- `docs/PRODUCT_GAP_ANALYSIS.md`
- `docs/PRODUCT_REQUIREMENTS_AND_TRACEABILITY.md`
- `docs/UX_PRODUCT_ROADMAP_2026.md`
- `docs/ARCHITECTURE.md`
- `docs/ETHICS.md`
- `docs/DATA_DICTIONARY.md`
- `docs/TRIAGE_AND_EVALUATION.md`
- `app.py`
- `src/ot_sentinel/dashboard_map.py`
- `src/ot_sentinel/triage.py`
- `src/ot_sentinel/mapper.py`
- `src/ot_sentinel/privacy.py`
- `src/ot_sentinel/publication.py`
- dashboard, privacy, mapping, detection, operations, and supply-chain tests
