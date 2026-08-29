# ADR-023 — Immutable Offline Handoff and Sanitized-Only Wazuh Staging

Status: **Accepted and implemented locally**

## Context

The Oracle sensor records authoritative private JSONL. Finishing the study requires integrity checks, sanitization, analysis, SOC ingestion and candidate generation, but none of those steps should modify the evidence, connect a local SOC to Oracle or turn a technical validation into publication approval.

Wazuh needs a stable file to collect and index historical JSON events. A simple file copy is not safely repeatable: a retry could duplicate alerts, and an interrupted append could leave partial JSON. Suricata is not an alternative historical JSON consumer because it analyzes packets or PCAP.

## Decision

1. Keep the original JSONL immutable and identify it by SHA-256.
2. Fail closed before processing malformed, incomplete, duplicate, oversized, mixed or unexpected records.
3. Name private run directories from the input digest and candidate-approval state.
4. Import only privacy-validated sanitized records into the historical SQLite index and local Wazuh staging path.
5. Make SQLite import one transaction with a unique event-ID ledger.
6. Append Wazuh inputs through a two-phase private SQLite ledger to one ignored file monitored through a read-only bind mount.
7. Keep every Wazuh host port on loopback and never deploy an agent or integration to Oracle.
8. Generate public-profile STIX and Streamlit summary candidates only after an explicit human flag; keep `publication: false` in the manifest.
9. Treat Suricata rules as separate packet-level detection evidence rather than pretending that JSONL was inspected as traffic.

## Consequences

- Re-running the same handoff verifies outputs rather than duplicating analysis.
- Interrupted SQLite or Wazuh staging can be retried without changing the original evidence.
- Output collisions stop processing instead of overwriting a different artifact.
- Wazuh can store and index reviewed sanitized events, but loses raw address/payload detail by design.
- The processing manifest provides hashes and provenance without containing private values or unnecessary absolute paths.
- Shutdown, encrypted backup, contextual review and publication remain human decisions.

## Rejected alternatives

- **Connect Wazuh directly to Oracle:** increases live-sensor resource, network and secret exposure during collection.
- **Import raw JSONL into local Wazuh:** copies more private evidence than the selected rules need.
- **Use `wazuh-logtest` as historical ingestion:** proves rule matching but does not persist dashboard-searchable alerts.
- **Send JSONL to Suricata:** misrepresents a packet IDS as a log ingestion engine.
- **Automatically replace Streamlit data:** bypasses contextual and small-count publication review.

## Verification

The handoff tests cover valid synthetic and observed-shaped fixtures, raw/private-field rejection, malformed and incomplete JSONL, duplicates, mixed classification, weak secrets, storage rollback, interrupted/repeated operations, output collisions, manifest privacy and Git tracking boundaries. Native local Wazuh evidence confirms a synthetic write is stored and indexed under rule `110001`, negative fixtures stay quiet and the alert remains available after manager restart.
