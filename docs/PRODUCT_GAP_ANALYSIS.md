# OT Sentinel Product Gap Analysis and Map Roadmap

**Scope:** local dashboard and authorized research workflow at release `v0.2.0`  
**Status:** recommendations only; no live Oracle configuration or private telemetry is changed by this document.  
**Audience:** project owner, analyst, reviewer, and future contributors.

## 1. Executive summary

OT Sentinel already has a strong technical foundation: three bounded OT protocol listeners, privacy-safe public data preparation, evidence-aware ATT&CK mapping, triage scoring, detection previews, session exploration, Wazuh/Suricata fixtures, and a four-mode geographic workspace.

The biggest product problem is not a missing chart. It is the gap between **seeing activity** and **deciding what to do next**. A first-time viewer needs orientation, a security analyst needs confidence and drill-down, and a researcher needs reproducible evidence. The roadmap below makes those jobs explicit.

The highest-value next release should improve the map in five directions:

1. **Explain the map before asking users to explore it.**
2. **Make every visual selection reversible and shareable.**
3. **Connect map observations to sessions, ATT&CK evidence, triage and detections.**
4. **Show uncertainty, coverage and provenance beside every conclusion.**
5. **Stay fast, privacy-safe and honest when the dataset grows.**

Do not add decorative 3D globes, fake real-time animations, raw IP reveal, attacker attribution, or a framework migration merely to make the screen feel busier.

## 2. Current product baseline

The following is present in the repository today. It is the baseline against which gaps are identified.

| Area | Current capability | Evidence |
|---|---|---|
| Collection | Bounded Modbus/TCP, S7comm and IEC-104 listeners | `src/ot_sentinel/sensor.py`, `protocols.py` |
| Evidence | Structured JSONL events with session and protocol fields | `src/ot_sentinel/model.py` |
| Analysis | Conservative ATT&CK for ICS hypotheses with confidence and rationale | `src/ot_sentinel/mapper.py` |
| Triage | Deterministic evidence-based score and queue | `src/ot_sentinel/triage.py` |
| Privacy | Pseudonymization, field allowlists and fail-closed public validation | `src/ot_sentinel/privacy.py`, `publication.py` |
| Map modes | Flow, source bubbles, density and finite UTC playback | `dashboard_map.py` |
| Map controls | Time window, labels, paths, reset camera, point selection and fullscreen | `app.py` |
| Map drill-down | Privacy-safe investigation summary and country focus | `app.py` |
| Export | Aggregate CSV and PNG controls | `app.py`, `dashboard_map.py` |
| Related views | ATT&CK, Detection Preview, Triage, Session Explorer and Methodology | `app.py` |
| Interoperability | Sigma, Suricata, Wazuh, STIX and Navigator outputs | `detections/`, `src/ot_sentinel/` |
| Reproducibility | Seeded synthetic dataset and validators | `data/`, `scripts/`, tests |

The current map is therefore an **investigation surface**, not a production SOC console. It is intentionally read-only and uses coarse public geography.

## 3. Users, jobs and pain points

### 3.1 First-time visitor

**Job:** understand what the application is showing in under one minute.

Pain points:

- The distinction between synthetic, sanitized and authorized live data is easy to miss when scanning quickly.
- “Source,” “session,” “event,” “control action,” and “technique hypothesis” are not obvious to a non-specialist.
- The map does not immediately state what a click will reveal.
- A visitor cannot tell whether a line is a network route, physical travel, or an analytical relationship until reading the caption.
- There is no guided first-run tour or sample investigation.
- Empty states explain that data is absent, but not what action will restore a useful view.

### 3.2 SOC analyst

**Job:** find the most important evidence, validate it, and move it into a response workflow.

Pain points:

- A map point does not immediately expose a compact event timeline for that source.
- Analysts must switch tabs to connect a source to ATT&CK, triage, sessions and detections.
- There is no “why is this important?” explanation beside a selected point.
- There is no visual distinction between repeated observations and one-off observations.
- The map cannot show only high-confidence or high-severity evidence without using the global filter panel.
- There is no saved investigation state, permalink, case note, or analyst handoff package.
- Export is aggregate-only, which is correct for public data but insufficient for a private analyst case workflow.
- There is no acknowledgement or review state for a finding.

### 3.3 Detection engineer

**Job:** determine whether an observed behavior is covered by a rule and whether the rule is noisy.

Pain points:

- The map does not show detection coverage for a selected protocol or technique.
- Rule predictions, native Wazuh alerts and Suricata results are not presented as one comparison.
- There is no “uncovered behavior” view.
- There is no count of unique sessions per rule, so repeated alerts can dominate attention.
- There is no easy export of a rule-validation slice with provenance.

### 3.4 Researcher or report author

**Job:** make a defensible claim about a collection window and reproduce it later.

Pain points:

- Date range, timezone and dataset provenance are visible but not packaged with every export.
- The map does not show confidence intervals or coordinate coverage percentages in the primary view.
- There is no compare-two-periods mode.
- A user cannot annotate why a technique interpretation was accepted, rejected or deferred.
- A report author must manually explain that country concentration is not attribution.

### 3.5 Project owner or learner

**Job:** demo the project clearly and learn from the system.

Pain points:

- The dashboard has many powerful tabs but no recommended sequence.
- It is not obvious which values are safe to show publicly.
- There is no built-in “demo scenario” that reliably demonstrates map selection, filtering and export.
- There is no small glossary connected to the UI labels.
- A recruiter or friend can see the screen but may not understand the evidence boundary.

## 4. Map interaction opportunities

Each item below states the user problem, proposed solution, and proof needed before calling it shipped.

### 4.1 Orientation and map literacy

| ID | Problem | Recommendation | Acceptance evidence |
|---|---|---|---|
| MAP-01 | Users cannot tell what the endpoint means | Add a compact legend: approximate sensor region, source group, path, density, and selected point | Legend is visible in every mode and uses the same symbols/colors |
| MAP-02 | Line semantics are misunderstood | Add a one-sentence “lines show observation relationships, not routes or attribution” callout beside the legend | Copy is present in screenshot and accessibility tree |
| MAP-03 | First action is unclear | Add a short empty-selection prompt: “Select a bubble to inspect its evidence summary” with a keyboard hint | Prompt disappears after selection and returns after reset |
| MAP-04 | New users miss the time filter | Add a “Start here” hint that points to Filters and Observation window | Hint can be dismissed and does not cover the map |
| MAP-05 | Users do not know whether data is live | Keep the dataset status pinned near the map and show a “not live” badge for playback | Synthetic build never presents playback as streaming |
| MAP-06 | Colors are memorized poorly | Keep protocol colors identical across map, distribution cards, charts and ATT&CK context | A visual token test or snapshot checks the shared palette |
| MAP-07 | Map controls are discoverable only by trial | Group camera, layer and playback actions into labelled control clusters | Every control has an accessible name and help text |

### 4.2 Filtering and exploration

| ID | Problem | Recommendation | Acceptance evidence |
|---|---|---|---|
| MAP-08 | Global filters and map filters feel separate | Display active global and map-local filters in one chip row with clear-all actions | Clearing one chip changes only its intended scope |
| MAP-09 | Users cannot filter by evidence strength | Add optional confidence and triage queue filters | Counts and map traces update without exposing private fields |
| MAP-10 | Users cannot focus on control behavior | Add a “control activity only” toggle that uses the existing allowlisted operation set | Toggle count matches the triage control count |
| MAP-11 | A selected source is hard to find again | Add “pin source” for the current session only | Pinned state is cleared on reload and never persisted with raw identity |
| MAP-12 | The map can become visually dense | Add a cluster/aggregate mode for overlapping bubbles with a count and zoom-to-cluster action | Cluster mode remains bounded and selectable |
| MAP-13 | Users do not know why records are absent | Add a filter result summary: visible, excluded by time, excluded by geography, excluded by invalid coordinates | Summary contains counts only |
| MAP-14 | Country focus is one-way | Add “back to previous view” and “clear country focus” actions | Browser/app state returns to the prior filter state |
| MAP-15 | Time windows are preset-only | Add a bounded custom UTC start/end selector with validation | Invalid or reversed windows fail safely |
| MAP-16 | Playback has no event context | Show the active UTC bucket, events, sources and protocol mix while playing | Bucket metrics match the filtered frame |
| MAP-17 | Users cannot compare modes | Add a synchronized split preview only for small datasets, otherwise provide a mode comparison summary | Rendering has a documented row/trace limit |

### 4.3 Selection and investigation

| ID | Problem | Recommendation | Acceptance evidence |
|---|---|---|---|
| MAP-18 | A point summary is too static | Add a compact selected-source timeline with event count, first/last seen, protocols and control count | Timeline uses aggregate or sanitized fields only |
| MAP-19 | Selection does not show evidence quality | Add confidence badges and a tooltip explaining that mappings are hypotheses | Badge values come directly from mapped evidence |
| MAP-20 | Analysts cannot move from map to session | Add “Open in Session Explorer” with a safe source/session filter | Navigation passes only allowlisted pseudonymous keys |
| MAP-21 | Analysts cannot move from map to ATT&CK | Add “View technique evidence” linking to the selected technique list | Link state matches the selected protocol/source |
| MAP-22 | The most active source is not necessarily most urgent | Add a toggle between rank by events, control actions, severity and triage score | Ranking is explicit and testable |
| MAP-23 | One source can represent shared infrastructure | Add a disclaimer next to source-group labels and avoid person/organization language | Disclaimer is present wherever source groups appear |
| MAP-24 | Analysts cannot record a review decision | Add private local review states: unreviewed, reviewed, needs context, false positive | State is local-only and never enters public exports |
| MAP-25 | No case handoff exists | Add a sanitized investigation bundle containing filters, aggregate counts, selected technique IDs and notes | Bundle has provenance, checksum and no raw address/payload |
| MAP-26 | Users lose context after switching tabs | Preserve selected filter context across tabs and show a compact context bar | Tab switching does not change underlying evidence |

### 4.4 Comparison, trend and intelligence views

| ID | Problem | Recommendation | Acceptance evidence |
|---|---|---|---|
| MAP-27 | A single period hides change | Add “compare windows” for two bounded periods with delta counts and direction arrows | Periods cannot overlap accidentally without clear labeling |
| MAP-28 | Repeated activity is not obvious | Add repeat count and unique-session count to bubble hover and tables | Counts derive from the durable observation index when available |
| MAP-29 | Protocol mix changes are hard to see | Add a stacked protocol trend below the map | Chart and selected time window use the same filtered frame |
| MAP-30 | ATT&CK heat is disconnected from geography | Add a technique selector that highlights only map observations carrying that technique | Selection never implies geographic causality |
| MAP-31 | Analysts cannot spot first-seen behavior | Add a “new in selected window” marker using the comparison baseline | Baseline is explicit and empty-baseline behavior is tested |
| MAP-32 | Data quality can change over time | Add coverage trend: mapped, unmapped and invalid-coordinate counts per window | No coordinate or IP detail is displayed |
| MAP-33 | Time playback looks real-time | Add a static label such as “replay of recorded dataset” in the playback control | Label is present in all synthetic demos |

### 4.5 Export and collaboration

| ID | Problem | Recommendation | Acceptance evidence |
|---|---|---|---|
| MAP-34 | CSV lacks the investigation context | Add a manifest row or sidecar containing dataset status, filters, window, schema version and generation time | Sidecar is validated and privacy-safe |
| MAP-35 | PNG exports do not explain the view | Add an export caption with mode, time window and synthetic/sanitized status | Image metadata or companion text carries provenance |
| MAP-36 | Reviewers cannot reproduce a view | Add a local share link encoded only with safe filter values | Link contains no raw addresses, credentials or cloud identifiers |
| MAP-37 | Public and private export intent is easy to confuse | Separate “Public aggregate export” and “Private review package” labels | Public action always runs the publication gate |
| MAP-38 | Reports require manual screenshots | Add a report-ready map snapshot with a fixed safe layout | Snapshot is deterministic for a fixture dataset |

### 4.6 Accessibility and responsive behavior

| ID | Problem | Recommendation | Acceptance evidence |
|---|---|---|---|
| MAP-39 | Color alone communicates protocol | Add text labels and patterns/shape differences in the legend | Protocol remains distinguishable in grayscale |
| MAP-40 | Keyboard users cannot select map points reliably | Provide a synchronized accessible source table with select buttons | Keyboard selection updates the same investigation panel |
| MAP-41 | Hover-only context disappears on touch | Mirror key hover fields in the selected summary | Touch and keyboard paths expose the same evidence |
| MAP-42 | Mobile users lose map controls | Provide a collapsible control drawer and keep reset/filters visible | 390px viewport has no overlap or horizontal scroll |
| MAP-43 | Small text is hard to scan | Set minimum readable sizes for legends, labels and captions | Automated or manual contrast/size checklist passes |
| MAP-44 | Motion can distract or trigger discomfort | Add reduced-motion behavior and disable autoplay by default | `prefers-reduced-motion` is honored |

### 4.7 Performance and reliability

| ID | Problem | Recommendation | Acceptance evidence |
|---|---|---|---|
| MAP-45 | Large datasets can make Plotly heavy | Pre-aggregate once per filter/window key and cap traces by documented policy | Load test records render time and trace count |
| MAP-46 | Rapid filter changes cause rerender churn | Debounce or submit filter changes as a deliberate action for large data | Small synthetic data remains instant |
| MAP-47 | Tile network failures look like app failures | Add an offline map fallback with points/table and clear tile-status copy | Dashboard remains useful without CARTO tiles |
| MAP-48 | Playback can drift from filters | Reset playback frame and selection whenever the filter key changes | Regression test covers changing protocols during playback |
| MAP-49 | Browser errors are discovered late | Add a smoke test for every map mode, filter state and export control | CI captures console errors and failed render states |
| MAP-50 | Users mistake stale data for current data | Add last-ingest health and stale thresholds when live/sanitized data is used | Status is derived from metadata, not the wall clock alone |

## 5. Broader product gaps beyond the map

### 5.1 Onboarding and information architecture

- Add a three-step “Observe → Validate → Explain” landing panel.
- Add a glossary for event, session, source group, control action, confidence, and hypothesis.
- Add a “What can this prove?” / “What can this not prove?” card on every analytical tab.
- Add a persistent breadcrumb showing dataset, date window and active filters.
- Add a single “Reset workspace” action that clears filters, selection, playback and local review state.
- Add a demo checklist button that walks through one safe investigation using synthetic data.
- Add keyboard shortcuts only if they are discoverable and do not conflict with browser behavior.

### 5.2 Analyst workflow

- Add a queue view that groups by session rather than only by event.
- Add deduplication visibility: first seen, repeat count, last seen and source-group count.
- Add evidence cards that show the exact decoded field supporting a mapping without exposing raw payload bytes.
- Add analyst notes stored outside public data and clearly marked private.
- Add a review decision audit trail with timestamp and analyst-provided reason.
- Add a bounded “related observations” panel based on protocol, session and technique—not geography alone.
- Add a safe escalation package for Wazuh/Suricata handoff with rule IDs and sanitized context.
- Add explicit “no action required” and “needs more evidence” states to avoid forcing every observation into an incident.

### 5.3 Detection engineering

- Show detection coverage by protocol, operation and ATT&CK technique.
- Show predicted/offline matches separately from native Wazuh and Suricata evidence.
- Add a false-positive review slice using synthetic fixtures.
- Add a rule freshness/version card and native validation date.
- Add a copyable rule test command for each selected rule.
- Add a “coverage gap” report listing mapped behaviors with no rule match.

### 5.4 Data trust and provenance

- Put dataset provenance in every view, download and report.
- Show the observation window and generation revision, not only the current UTC clock.
- Show coverage percentages and excluded-record reasons as aggregate counts.
- Distinguish event count, session count and unique source-group count everywhere.
- Add a visible “approximate geography” marker to all map exports.
- Add a schema version to exports and a migration note when fields change.
- Add a data-quality score that is descriptive, not a security score.

### 5.5 Privacy and safety

- Keep raw IPs, payloads, credentials, OCIDs and cloud identifiers out of browser state and exports.
- Add tests that inspect serialized Plotly figures, not only DataFrames.
- Add a public/private mode indicator before any download.
- Add a privacy preflight result beside export buttons.
- Ensure local analyst notes cannot be included accidentally in public bundles.
- Add retention reminders for private data and a documented deletion procedure.
- Keep attribution language out of labels, rankings and tooltips.

### 5.6 Operations and deployment

- Add a read-only deployment status panel: sensor health, last event, queue depth, disk headroom and last successful validation.
- Add operator alerts for stale ingestion, disk pressure, delivery failures and clock skew.
- Add a runbook button linking to the exact recovery procedure.
- Add a read-only “configuration fingerprint” rather than displaying secrets or OCIDs.
- Add a dashboard banner when the UI is disconnected from the live sensor.
- Add a controlled export handoff command instead of copying live files manually.

### 5.7 Documentation and learning

- Add one-page architecture and one-page analyst quick start.
- Add screenshots for every tab with synthetic data labels visible.
- Add a “how to explain this project” script for nontechnical viewers.
- Add a troubleshooting decision tree for empty map, stale data, missing tiles and Wazuh login.
- Add a changelog entry for every user-visible interaction change.
- Add short screen-reader labels and keyboard instructions to the walkthrough.

## 6. Priority matrix

Priority is based on analyst value, safety, implementation cost and evidence quality.

### P0 — do next

1. **MAP-01/02/03:** legend, semantics and selection prompt.
2. **MAP-08/13/14:** unified filter state, exclusion counts and reversible country focus.
3. **MAP-18/19/20/21:** selected-source timeline and links to session/ATT&CK evidence.
4. **MAP-28:** repeat count versus unique-session count.
5. **MAP-34/35/37:** provenance-aware export packaging and explicit public/private actions.
6. **MAP-40/41:** accessible source table and non-hover selection path.
7. **MAP-47:** offline tile fallback.

### P1 — high-value follow-up

1. **MAP-09/10/22:** confidence, control-only and triage ranking filters.
2. **MAP-27/30/31:** period comparison, technique highlighting and first-seen markers.
3. **MAP-24/25:** private review states and sanitized handoff bundle.
4. Detection coverage and uncovered-behavior views.
5. Onboarding tour, glossary and reset workspace.
6. Performance pre-aggregation and large-dataset load tests.

### P2 — valuable when evidence supports it

1. **MAP-12/17:** clustering and split-mode comparison for larger datasets.
2. **MAP-36:** safe local share links.
3. Persistent private cases and analyst collaboration.
4. Multi-sensor comparison and facility/profile overlays.
5. External SIEM/SOAR case synchronization.

### Explicitly defer

- 3D globe or decorative animated routes.
- Real-time “attacker travel” animations.
- Identity resolution, organization attribution or threat-actor labels.
- Public login, comments or arbitrary file upload.
- React/MapLibre migration before Streamlit performance is measured.
- Automatic publication of authorized live data.

## 7. Suggested release plan

### Release 0.3 — explain and investigate

Ship the P0 set. Keep the existing map engine and data contract. Add no new runtime service.

Definition of done:

- A new user can understand the map semantics without opening documentation.
- A selected source can be traced to a safe timeline, session view and ATT&CK evidence.
- Every export records filters, date window and provenance.
- Keyboard and mobile paths reach the same investigation result.
- Existing privacy and map tests remain green.

### Release 0.4 — compare and validate

Ship period comparison, confidence/triage filters, detection coverage, private review states and performance tests.

Definition of done:

- An analyst can explain why one observation is higher priority than another.
- A detection engineer can identify covered and uncovered behaviors.
- A researcher can compare two periods without mixing provenance.
- Load tests document the maximum supported dataset and trace policy.

### Release 0.5 — handoff and scale

Only after measured need: private case packages, multi-sensor views, local share links and external SOC workflow integration.

Definition of done:

- Private and public workflows are visibly separate.
- Case packages are checksum-verifiable and privacy-gated.
- Scaling decisions are based on measurements, not assumptions.
- Every external integration has a failure and rollback path.

## 8. Product metrics

Track these with synthetic fixtures first, then with authorized sanitized data:

| Metric | Why it matters | Target direction |
|---|---|---|
| Time to first meaningful map action | Measures onboarding clarity | Down |
| Time from selected point to evidence summary | Measures investigation friction | Down |
| Percentage of sessions reaching a safe export | Measures end-to-end usefulness | Up, without forcing export |
| Unmapped behavior rate | Finds analysis/detection gaps | Understand and explain |
| Detection coverage by protocol/technique | Measures defender utility | Up with bounded false positives |
| Repeat observations per unique session | Separates noise from persistence | Visible, not inherently good/bad |
| Invalid/excluded coordinate rate | Measures map trust | Explain, then improve source quality |
| Map render time and browser error rate | Protects usability at scale | Down |
| Public export privacy-gate failures | Finds unsafe release attempts | Zero published failures |
| Accessibility task completion | Ensures non-pointer access | Up |

Never use country concentration, source count or map prominence as a proxy for attacker importance without protocol evidence and an explicit caveat.

## 9. Research and validation plan

Before implementing a large feature, run five short sessions with:

1. a nontechnical friend;
2. a cybersecurity learner;
3. a SOC analyst or detection engineer;
4. a researcher/report reviewer;
5. a privacy-minded reviewer.

Give each person the same synthetic dataset and ask them to:

- explain what the map shows;
- find the most concerning control behavior;
- select one source and explain the evidence;
- move from the map to a session and technique;
- export a safe summary;
- state what the dashboard cannot prove.

Record completion time, wrong assumptions, dead ends and questions. Do not collect personal data or show private live telemetry during this exercise.

## 10. Implementation guidance

Keep the current separation of responsibilities:

- `src/ot_sentinel/dashboard_map.py`: aggregation, privacy-safe fields, figure traces and map limits;
- `app.py`: controls, navigation, session state, accessible fallback tables and copy;
- `src/ot_sentinel/triage.py` and `mapper.py`: evidence and confidence semantics;
- `src/ot_sentinel/publication.py`: public export gates;
- `tests/test_dashboard_map.py` and `tests/test_dashboard_app.py`: interaction, privacy, empty state and rendering checks;
- `docs/INTERACTIVE_MAP_REDESIGN.md`: map-specific design contract;
- `docs/FEATURE_CATALOG.md`: update only after a feature is actually shipped and verified.

Every new interaction should answer four questions in code review:

1. What user decision does this make easier?
2. Which existing safe field powers it?
3. How can the user undo it?
4. What test proves it cannot leak private data or imply attribution?

## 11. Final recommendation

The best next build is a **Map Investigation Mode**: a unified legend and filter state, a selected-source timeline, evidence/confidence badges, direct links to sessions and ATT&CK, repeat-versus-unique counts, reversible focus, accessible table selection, and provenance-aware exports. It makes the existing capabilities feel like one coherent analyst workflow and can be shipped without changing the collector, Oracle deployment, Wazuh lab or public data contract.

The project should only move to multi-user cases, external SOC actions or a different frontend after user testing demonstrates that the current workflow—not visual novelty—is the limiting factor.
