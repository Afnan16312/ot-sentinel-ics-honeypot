# Phase 1 User-Centered Workflow Record

## Outcome

This phase turns the approved user research into a small, testable dashboard improvement. It changes only the local/public Streamlit analysis experience and supporting pure-Python helpers. It does not access, restart, redeploy or reconfigure the Oracle sensor, Docker lab, Wazuh, Suricata or cloud networking.

## Features shipped

| Feature | User problem solved | Implementation | Honest boundary |
|---|---|---|---|
| View claim boundaries | Users could overstate what a map, mapping, score or rule result proves. | Every dashboard tab has a view-specific “can show / cannot establish” panel. | Copy cannot prevent misuse outside the product. |
| Major-metric explanations | Non-specialists could confuse events, sessions and sources with attacks or people. | Keyboard-focusable information markers explain the four main counters and the map counters. | Tooltips explain meaning; they do not validate data. |
| Reset workspace | Combined filters, map state and prepared drill-downs were difficult to unwind. | One action clears filters, map state, focus and local display controls. Notes are preserved unless deletion is explicitly selected. | It resets one browser session, not shared or server-side state. |
| Session-first triage | Event-first rows made one connection look like many separate investigations. | Triage groups by bounded `session_id` by default and can switch back to event rows. | A session is not a person, intrusion or campaign. |
| Evidence completeness | Review priority could be mistaken for evidence quality. | Each event reports complete, partial or limited field availability and an ATT&CK mapping state, independently of its review score. | Completeness is structural and does not prove truth or accuracy. |
| Precise detection state | Offline predictions could be confused with native SIEM/IDS alerts. | Detection Preview separates current offline matching from dated Wazuh and Suricata synthetic-fixture evidence with pinned versions. | Historical fixture evidence is not current engine health or production tuning proof. |

## Evidence completeness model

The model checks four reviewed public field groups:

1. a non-empty decoded request not marked invalid;
2. a bounded session identifier;
3. finite coarse public coordinates with a non-unknown country code;
4. at least one mapping with both confidence and rationale.

Four checks produce **complete fields**, two or three produce **partial fields**, and zero or one produce **limited fields**. The result never changes the public review score.

## Detection states

| State | Meaning |
|---|---|
| Offline prediction | The dashboard evaluated committed rule conditions against the current sanitized records during this run. |
| Native fixture passed | A pinned engine previously passed committed synthetic positive and negative fixtures on the displayed date. |
| Not recorded | The committed native evidence record is missing or cannot be parsed safely. |

The authoritative reproduction commands remain in `tests/soc/README.md`. Any rule, image or isolation change invalidates the historical assurance until the native sequence is repeated.

## Problems intentionally not solved

- no attacker attribution or raw source display;
- no automated blocking or response;
- no shared analyst accounts, RBAC or case database;
- no direct Oracle-to-dashboard or Oracle-to-Wazuh connection;
- no framework migration;
- no claim that synthetic fixtures measure production accuracy.

## Files and verification

- `app.py` — interface, state reset, session grouping and evidence-state display;
- `src/ot_sentinel/triage.py` — deterministic evidence completeness;
- `src/ot_sentinel/detection_preview.py` — committed native-evidence summary parser;
- `tests/test_dashboard_app.py`, `tests/test_triage.py`, `tests/test_detection_preview.py` — synthetic regression coverage;
- `docs/ADR_024_USER_CENTERED_EVIDENCE_WORKFLOW.md` — architectural decision and rollback.

Release verification must include the complete pytest suite, Ruff, public-data validation, detection validation and the existing supply-chain checks. No live telemetry is used by these checks.
