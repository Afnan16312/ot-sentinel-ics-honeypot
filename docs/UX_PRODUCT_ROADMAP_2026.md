# OT Sentinel UX and Product Roadmap (2026)

## Purpose and scope

This is a decision document, not a claim that the listed ideas are already built. It reconciles the original product-gap work with the dashboard that is actually present today, then identifies the next improvements that would make OT Sentinel clearer, more useful and more credible in a portfolio demonstration.

This roadmap applies only to the **public, synthetic/local dashboard workflow**. It does not authorize access to the private Oracle collection, publication of live telemetry, automatic attribution, or a change to cloud networking, Docker, Wazuh, Suricata, or the collector.

The key design principle is simple: the map should help a person make a safe next decision, not merely look impressive. NIST notes that OT security must account for performance, reliability and safety requirements alongside security; that is why explanations, limits and safe handoffs matter as much as visualization. [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final)

## Delivered roadmap update: investigation workflow

The following P0 items are now implemented in the public dashboard branch:

- A bounded comparison tray compares up to three **pseudonymous, aggregate-only** map observations.
- The prior-window summary uses adjacent, non-overlapping windows and gives a cautious plain-language delta statement.
- Selected observations show a **Public review score**, the public-safe factors behind it, and a non-automated next step.
- A persistent data-and-privacy strip and a short in-app glossary explain synthetic/sanitized data, approximate geography, sessions, sources, control actions, and evidence confidence.
- Local review notes are scoped to the selected source/country/protocol observation so a note cannot appear on a different selection.

These changes do not connect the dashboard to the Oracle sensor, do not expose individual private events, and do not turn a score, location, or map point into attribution.

## Evidence reviewed

| Source | What it establishes |
|---|---|
| `app.py` | The current Streamlit workspace, six analysis views, global filters, dashboard copy and map-to-analysis navigation. |
| `src/ot_sentinel/dashboard_map.py` | Privacy-safe map aggregation, four map modes, selection, bounded exports and coordinate controls. |
| `docs/INTERACTIVE_MAP_REDESIGN.md` | The intended map semantics, shipped interaction model, safety controls and known limitations. |
| `docs/PRODUCT_GAP_ANALYSIS.md` | The original MAP-01 to MAP-50 backlog and broader product opportunities. |
| `docs/PRODUCT_REQUIREMENTS_AND_TRACEABILITY.md` | Requirements that must remain future work until evidence exists. |
| MITRE ATT&CK resources | ATT&CK visualisations should carry their scoring, notes and context rather than imply that a colour alone proves meaning. [Working with ATT&CK](https://attack.mitre.org/resources/working-with-attack/) |

## Current capability status

The first roadmap is not obsolete: most of its high-value map work is now already in the product. Rebuilding these features would add cost without solving a new user problem.

| Area | Current state | What a user can do now | Remaining boundary |
|---|---|---|---|
| Map orientation | Shipped | Read the legend, map semantics and synthetic/sanitized status. | The first-use explanation is still passive rather than guided. |
| Exploration | Shipped | Switch among Flow, Source Bubbles, Density and Time Playback; filter protocol, time, confidence, priority and control actions; compare up to three aggregate map observations. | There is no saved-view workflow. |
| Investigation | Shipped | Select a pseudonymous source, inspect a safe timeline and evidence badges, then prepare Session Explorer or ATT&CK Analysis. | Investigation context is not packaged as a durable private case. |
| Comparison | Shipped baseline | Compare the selected time window with an adjacent, equal, non-overlapping window; read a bounded plain-language change summary and inspect aggregate sources side by side. | It does not establish a causal trend, rate, or attribution. |
| Detection workflow | Shipped baseline | Inspect Detection Preview, rules, coverage and local Wazuh/Suricata validation context. | There is no prioritized coverage-gap worklist or tuning history. |
| Exports | Shipped baseline | Download reviewed aggregate-only data and a view manifest. | There is no report-ready snapshot, safe permalink or private review bundle. |
| Accessibility | Shipped baseline | Use an accessible source table, labels, tooltips and a tile-free fallback. | Mobile investigation and keyboard discovery need deliberate user testing. |
| Trust and safety | Shipped baseline | See synthetic data disclosure, approximate geography context and public/private controls. | A provenance timeline and data-quality explanation would make limitations easier to understand. |
| Operations | Shipped locally | Use health checks, bounded collection and local assurance documentation. | The dashboard does not yet surface a redacted operational-health summary. |

## Users, jobs and present friction

### 1. First-time visitor or recruiter

**Job:** Understand what OT Sentinel does in under two minutes and see that it is a careful cybersecurity project, not a decorative map.

| Pain point | Why it matters | Best response |
|---|---|---|
| Six views can look like six unrelated tools. | A viewer may not discover the intended workflow. | Add a dismissible `Observe → Validate → Explain` guide above the first dashboard view. |
| Terms such as *session*, *source*, *control attempt* and *confidence* are unfamiliar. | Counts can be mistaken for attacks or attackers. | Add a one-line glossary tooltip at every high-level metric and a short glossary page. |
| The map looks global, which can imply global coverage. | A viewer may overread the synthetic locations. | Add a compact `What this map represents` card: selected dataset only, coarse geography, no attribution, not a world census. |
| The synthetic-data notice can be skimmed. | Credibility falls if the demo looks like a claim about real victims. | Keep the notice, but add a small persistent `Synthetic demo` badge to export and screenshot states. |
| The strongest evidence is hidden behind interaction. | The project can feel like a static UI mock-up. | Include a single guided example source with three visible steps: select, inspect evidence, open ATT&CK rationale. |

### 2. SOC analyst

**Job:** Decide whether a cluster of protocol activity deserves more investigation and hand off a defensible summary.

| Pain point | Why it matters | Best response |
|---|---|---|
| Activity volume, urgency and evidence strength are separate concepts. | Large counts can incorrectly dominate attention. | Add a plain-language `Why this is ranked` card: control action, confidence, repeat activity and novelty contributions. |
| Only one selected source is easy to inspect at a time. | Analysts compare candidates constantly. | Add a session-only comparison tray for up to three pseudonymous sources. |
| Window comparison is tabular. | Analysts must manually infer what changed. | Add a `What changed?` summary that says, for example, “Modbus control activity increased by X records; evidence confidence unchanged.” |
| Local notes are useful but ephemeral. | A handoff can lose reasoning. | Add an explicitly private, downloadable review bundle with selected source IDs, filters, notes, rationale and generation time; route it through the publication gate. |
| No clear recommended next action appears after selection. | New analysts can stall after finding a source. | Add non-automated next steps: inspect timeline, review ATT&CK rationale, inspect detection coverage, mark as needs context. |
| A geographic point can look like identity evidence. | This risks unsafe attribution. | Keep country and source wording neutral; add an always-visible note in the selected-source panel. |

### 3. Detection engineer

**Job:** Understand which protocol behavior is covered by a rule and which behavior needs detection work.

| Pain point | Why it matters | Best response |
|---|---|---|
| Coverage exists but does not become an ordered backlog. | Gaps are visible but not actionable. | Add a coverage-gap queue grouped by protocol, ATT&CK technique and observed operation. |
| Predicted matches and native-engine validation may be confused. | Offline logic can be mistaken for a Wazuh or Suricata alert. | Use three explicit states: `offline prediction`, `native fixture validated`, `not validated`. |
| Rule version/freshness is not visible near the investigation. | An analyst cannot judge if a rule is current. | Add rule ID, repository revision, fixture-validation date and known scope. |
| Repeated low-severity events are difficult to evaluate. | Noise reduction is a core SOC task. | Show a deterministic repeat/novelty explanation with a bounded sample of safe decoded fields. |
| No feedback loop exists from review to tuning. | The project demonstrates detection but not detection engineering. | Add local labels such as `expected`, `needs tuning`, `investigate`; export only a sanitized tuning summary. |

### 4. Researcher or report author

**Job:** Produce a repeatable, privacy-safe statement about a defined observation window.

| Pain point | Why it matters | Best response |
|---|---|---|
| A screenshot can lose filters and provenance. | Results cannot be reproduced. | Add a report snapshot with a visible dataset label, filter summary, date window and generation timestamp. |
| Changes between periods require manual interpretation. | Trend claims become fragile. | Add a bounded comparison narrative and a CSV/JSON sidecar with aggregate deltas. |
| Map concentration can imply importance. | Geographic prominence is not risk. | Put the caveat directly beside concentration/heat views and in exports. |
| Audience members may ask what is real. | This project must distinguish demo, synthetic, sanitized and reviewed observations. | Add a concise provenance panel with those four terms defined. |

### 5. Project owner and learner

**Job:** Run a reliable demonstration, understand every component and explain its limits without exposing private data.

| Pain point | Why it matters | Best response |
|---|---|---|
| A fresh demo can be hard to narrate. | Good engineering is missed if the walkthrough is improvised. | Add a five-minute walkthrough mode that resets safely and highlights one path through the app. |
| Dashboard status and sensor status are conceptually different. | A local UI running does not prove a sensor is healthy. | Add a read-only, redacted status card that clearly labels dashboard, dataset and sensor health separately. |
| User-visible copy can drift from the code. | The public story can become inaccurate. | Add screenshot/visual-regression checks for the top dashboard states and a documentation review checklist. |
| The number of optional integrations is growing. | Overbuilding makes the project hard to run. | Retain the minimal Streamlit/collector architecture unless measured scale or workflow needs exceed it. |

## Net-new map interaction backlog

These proposals deliberately exclude the map capabilities already shipped: mode selection, playback, confidence/priority/control filters, one-source selection, accessible source table, ATT&CK/session preparation, local notes, tile-free fallback, country focus, coverage audit and aggregate export.

| ID | Proposal | User problem solved | Safety/implementation guardrail | Priority |
|---|---|---|---|---|
| MAP-N01 | **Comparison tray** for 2–3 selected sources | Analysts cannot compare a busy source with a high-priority source. | Session-only; use pseudonymous IDs and aggregate fields only. | P0 |
| MAP-N02 | **Why this matters** ranking card | A numeric threat/review score feels opaque. | Display deterministic factors and weights; never call it a probability or attribution score. | P0 |
| MAP-N03 | **What changed?** window summary | Tables make trend interpretation slow. | Only describe measured deltas; say `no meaningful change` when thresholds are not met. | P0 |
| MAP-N04 | **Investigation next-step panel** | New analysts do not know what to do after selecting a point. | Suggest actions; never auto-escalate or label a source malicious. | P0 |
| MAP-N05 | **Safe saved views** | A reviewer cannot return to a useful filter state. | Encode only allowlisted protocol, country, time and mode values; never IDs, notes or payloads. | P1 |
| MAP-N06 | **Report-ready safe snapshot** | Screenshots lose context. | Render provenance, filters and approximation caveat into the image/sidecar. | P1 |
| MAP-N07 | **Source clustering with drill-down** | Dense bubble views become visually noisy with larger approved datasets. | Aggregate before rendering; cap cluster members and preserve accessible table equivalent. | P1 |
| MAP-N08 | **Protocol/technique camera presets** | Viewers spend time finding meaningful views. | Presets are filters/camera positions, not claims of geographic relevance. | P1 |
| MAP-N09 | **Map-to-detection trail** | Selecting a map point does not immediately show whether it has a validated rule. | Show coverage state and evidence type, not raw event transport data. | P1 |
| MAP-N10 | **Data-quality strip** | Users cannot distinguish a risky observation from a low-quality location record. | Label it `mapping/data quality`, never `risk`; show only aggregate excluded reasons. | P1 |
| MAP-N11 | **First-seen/repeated markers** | Repeat activity is present but does not stand out visually. | Define the comparison baseline in UI; handle an empty baseline explicitly. | P1 |
| MAP-N12 | **Synchronized timeline brush** | Changing time requires indirect controls. | Limit buckets and use deliberate Apply action for large data. | P2 |
| MAP-N13 | **Story checkpoints** | Playback is useful but a person can miss the important moment. | Curate only synthetic or reviewed aggregate moments; clearly label replay, not live stream. | P2 |
| MAP-N14 | **Keyboard map command palette** | Power users need faster movement; pointer users are already supported. | Discoverable, fully labelled, no browser-shortcut conflicts. | P2 |
| MAP-N15 | **Mobile investigation drawer** | Small displays can bury filters and selection details. | Test at 390px and with 200% zoom; preserve a non-map table route. | P2 |
| MAP-N16 | **Visual regression screenshots** | A styling fix can silently break dense dashboard layout. | Run local/CI screenshots for the default, selected-source, empty and narrow viewport states. | P1 |

## Broader product opportunities

### Workflow and clarity

1. Add a guided first-run experience with a visible Skip button.
2. Add a glossary with precise, non-alarmist definitions.
3. Add a single Reset Workspace action that clears global filters, map selection, playback and local review state.
4. Add a breadcrumb/status strip: dataset type, selected time window, active filters and current view.
5. Add a `Can prove / cannot prove` card to Observatory, ATT&CK Analysis, Detection Preview and Triage.
6. Add a short, synthetic walkthrough script that works even when map tiles are unavailable.
7. Add a side-by-side distinction between **event**, **session**, **pseudonymous source** and **control attempt**.
8. Add contextual help next to every metric whose count can be mistaken for a count of intrusions.

### Triage and case quality

1. Group the triage queue by session as well as event.
2. Show first seen, last seen, repeat count and selected evidence rationale in every queue row.
3. Make `reviewed`, `needs context`, `expected` and `needs tuning` explicit non-incident states.
4. Keep local review state outside public exports by default.
5. Create a sanitized private review bundle only after its privacy boundary and storage location are defined.
6. Add a `related observations` view based on protocol, session and technique; do not use country as the relationship signal.
7. Put a copyable safe rule-test command beside native fixture-validated detections.
8. Let a user explain score changes in notes, instead of treating the score as the final answer.

### Detection engineering

1. Turn coverage into a matrix: protocol × operation × technique × rule state.
2. Create an ordered `coverage gap` list with test-fixture references.
3. Display rule provenance: local rule path, revision, validation date and fixture set; hide credentials and infrastructure IDs.
4. Separate parser confidence from ATT&CK confidence and from triage priority.
5. Maintain a simple tuning changelog explaining why a rule changed and which safe fixture tests it.
6. Add a regression badge only when the complete local fixture suite passed.
7. Do not promote synthetic matches as production detection-rate evidence.

### Data trust, privacy and research integrity

1. Attach schema version, dataset status, filter state and generation time to every export.
2. Give map geography a persistent `approximate` label in every mode and report snapshot.
3. Display aggregate exclusion reasons: no coordinate, invalid coordinate, filtered by time, filtered by public-data gate.
4. Add a privacy preflight result before public exports.
5. Add export tests that inspect serialised figure data as well as visible tables.
6. Define a private-data retention and deletion workflow before any data handoff.
7. Preserve the rule that raw IPs, payloads, credentials, OCIDs and cloud identifiers never reach browser state or public artifacts.
8. Make observation vs inference visually distinct in every report chart and caption.

### Reliability and operability

1. Add a dashboard status card that distinguishes `dashboard available`, `dataset loaded` and `sensor health known`.
2. Present redacted health signals only: last successful ingestion metadata, queue status, disk headroom band and last validation status.
3. Add a stale-data threshold appropriate to the dataset mode; never use the browser clock alone as proof of freshness.
4. Link status warnings to exact safe runbook steps.
5. Publish expected resource needs for local Streamlit, Wazuh lab and sensor components separately.
6. Keep map rendering bounded: aggregate first, cap paths/clusters and test filter changes with a larger synthetic fixture.
7. Add a safe fallback when tiles fail, including a clear explanation that data still exists even if the basemap does not.
8. Add a rollback checklist for every future public dashboard deployment.

### Learning and portfolio quality

1. Write an architecture one-pager with a single end-to-end diagram.
2. Write a two-minute nontechnical explanation and a five-minute technical walkthrough.
3. Record a demo only from synthetic/reviewed public data and review every frame for privacy.
4. Include one annotated investigation story that goes map → selected source → evidence → rule coverage → safe conclusion.
5. Maintain a changelog of user-visible changes and their reason.
6. Put the project limits near the project achievements; this signals responsible OT practice.
7. Add a demo-mode reset so every recording begins from the same state.
8. Use user testing with a nontechnical viewer, a cyber learner, an analyst and a privacy-minded reviewer before major UI expansion.

## Recommended delivery order

### P0: make the current product easier to trust and use

| Item | Outcome | Estimated scope | Definition of done |
|---|---|---|---|
| MAP-N02 score explanation | Scores become explainable rather than decorative. | Small | Every score displays its factors and a limitation statement. |
| MAP-N03 change summary | A viewer can explain the difference between two windows. | Small/medium | Summary matches aggregate calculation and carries a non-attribution caveat. |
| MAP-N04 next steps | A selected source leads to a clear human decision path. | Small | Suggestions use only already available safe views and actions. |
| Glossary + metric help | Fewer misunderstandings about counts. | Small | Key terms have concise hover/help content and a static glossary. |
| Status/provenance strip | Viewers know whether they see synthetic, reviewed, local or live-sanitized data. | Small | Strip is visible in every analytical view and export. |

### P1: make analysis repeatable and detection-oriented

| Item | Outcome | Estimated scope | Definition of done |
|---|---|---|---|
| MAP-N01 comparison tray | Analysts compare candidates without mental arithmetic. | Medium | Up to three safe selected sources, keyboard path and reset action. |
| MAP-N05 safe saved views | A reviewer can reproduce a filter state. | Medium | URL/view state contains only allowlisted safe values. |
| MAP-N06 safe snapshot | Reports preserve the question and context. | Medium | Snapshot/sidecar passes the publication validator. |
| MAP-N09 detection trail | Map selection reaches rule coverage efficiently. | Medium | Coverage states distinguish prediction from native validation. |
| MAP-N10 data-quality strip | Geography confidence is not confused with risk. | Small | Quality fields are aggregate-only and clearly labelled. |
| MAP-N16 visual regression tests | Future UI fixes do not introduce layout regressions. | Medium | Baselines cover default, empty, selected and narrow states. |

### P2: add only after user testing or larger approved datasets justify it

| Item | Why wait | Evidence to start |
|---|---|---|
| Source clustering | It adds complexity that small data may not need. | Measured point-overlap or slow rendering in an approved synthetic load test. |
| Timeline brushing/checkpoints | Current bounded controls already work. | Users repeatedly fail to find a time segment in five short tests. |
| Mobile drawer/command palette | Accessibility baseline should be tested before adding new interaction paradigms. | User testing shows a real discovery or access problem. |
| Durable private cases | Storage and role boundaries matter more than the UI. | Defined private storage, retention, authorization and export policy. |
| External SOC/SOAR case sync | Integration failures can create operational risk. | A documented consumer, schema, failure path and rollback owner. |

### Explicitly do not build now

- 3D globes, animated attacker travel or decorative network routes.
- Threat-actor, organisation or individual attribution from coarse network geography.
- A public live feed, public comments, arbitrary uploads or open user accounts.
- A React/MapLibre rewrite before Streamlit limits are measured.
- Any feature that reads the live Oracle sensor directly into a browser or public export.
- Automatic escalation or blocking based only on a review/threat score.

## Validation plan before implementation

For every proposed interaction, test the same synthetic fixture with five people: a nontechnical viewer, cybersecurity learner, SOC analyst/detection engineer, research/report reviewer and privacy-minded reviewer. Ask them to:

1. Say what the data status is.
2. Identify the difference between an event, session and pseudonymous source.
3. Find a high-priority selected source and explain why it is ranked.
4. Determine what changed between two windows without making an attribution claim.
5. Find the associated ATT&CK rationale and detection coverage state.
6. Export or save a safe reproduction of the view.
7. Explain one thing the dashboard cannot prove.

Measure completion time, wrong assumptions, privacy questions, abandoned paths and whether the user can recover without help. Do not show private live telemetry during these sessions.

## Acceptance guardrails for future work

A feature is only ready to ship when it meets all relevant conditions:

- It solves a named user decision, not only a visual preference.
- It reuses an allowlisted public/synthetic field or is rejected by the publication gate.
- It can be reset or undone.
- It does not claim identity, maliciousness, location certainty or real-time status beyond the evidence.
- It works with keyboard and non-map fallback paths where applicable.
- It has an automated test for its calculation and a privacy test for its serialised output.
- It does not alter Oracle, the live sensor, Wazuh, Suricata, Docker or collector configuration unless a separate approved task says so.
- Its documentation, screenshot/demo copy and code agree.

## Bottom line

OT Sentinel is no longer missing basic map interaction. The best next improvements are **interpretation features**: explain why something is ranked, explain what changed, compare a small number of sources, tie a selected source to coverage, and preserve a safe record of the investigation. These additions build on the existing safety-first architecture and make the project feel like an analyst workstation rather than a visual dashboard.
