# ADR-024 — Separate evidence meaning, review priority and validation state

## Status

Accepted on the `feature/user-centered-workflow-phase-1` branch.

## Context

OT Sentinel serves learners, analysts, detection engineers, researchers and privacy reviewers. The same number can mean different things to each user. A high review score can be mistaken for threat probability, a complete record can be mistaken for true evidence, and an offline rule match can be mistaken for a native Wazuh or Suricata alert.

## Decision

Keep the existing Streamlit and standard-library architecture and make three concepts visibly separate:

1. **Review priority** ranks recorded behavior for human attention.
2. **Evidence completeness** reports whether four reviewed public field groups are present: decoded request, session identifier, coarse public location and evidence-qualified mapping.
3. **Detection evidence state** distinguishes a match calculated offline now from a dated, versioned native synthetic-fixture result recorded in the repository.

The dashboard also starts triage at the bounded-session level, provides event rows as a reversible alternative, adds view-specific claim boundaries and supplies one workspace reset. Reset preserves browser-session review notes unless the user explicitly selects note deletion.

## Alternatives considered

- **One combined risk or confidence score:** rejected because it would mix behavior, data availability and detection evidence into a number users could overinterpret.
- **A new case-management service or frontend framework:** deferred because the public application has no analyst accounts, shared cases or complex API resources.
- **Reading current Wazuh/Suricata runtime status:** rejected because the public dashboard must not depend on a disposable local lab or the live Oracle sensor.
- **Clearing all local state automatically:** rejected because it could destroy analyst notes without explicit intent.

## Consequences

- Users receive clearer evidence boundaries and a session-first review path.
- No dependency, cloud resource, listener, firewall rule or live-collection process changes.
- Evidence completeness is structural only. It does not prove accuracy, intent, compromise or business impact.
- Native fixture results become stale after rule, image or isolation changes and must be re-run using `tests/soc/README.md`.
- Review notes remain local and non-durable; shared case management remains a future migration trigger.

## Verification

Synthetic tests cover completeness classification, native-evidence parsing, session/event triage switching, workspace reset and note preservation. The full project suite, Ruff and existing privacy/detection validators remain release gates.

## Rollback

Revert the feature commit. No data or schema migration is required, and the live Oracle sensor is unaffected.
