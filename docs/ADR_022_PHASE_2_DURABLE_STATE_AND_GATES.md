# ADR-022: Durable Auxiliary State and Shared Safety Gates

**Status:** Accepted for the Phase 2 feature branch

**Date:** 2026-08-25

## Context

The original design correctly kept append-only JSONL as private authoritative evidence, but process-memory replay and delivery queues did not survive restarts. Publication checks also existed in more than one place, creating drift risk. The project needs persistence and stronger validation without adding a framework, ORM or runtime dependency.

## Decision

Use Python's standard-library `sqlite3` only for three separate auxiliary responsibilities:

1. collector replay reservations with expiry and atomic insert;
2. privacy-reduced, HMAC-fingerprint observation deduplication;
3. an optional bounded pending-delivery spool.

Keep these databases separate because their secrets, retention and failure semantics differ. JSONL remains authoritative private evidence. The spool stores event JSON but never a collector secret or signature; HMAC is generated only at transmission.

Create one `ot_sentinel.publication` gate used by command-line validation, aggregate generation, Streamlit input and public STIX. Strict sanitization removes `source_network`, payloads and recursive credential-like fields. Raw-address pseudonymization requires a private salt of at least 32 characters. Public datasets cannot mix synthetic and observed provenance.

Keep Detection Preview offline and clearly labeled. Native Wazuh and Suricata evidence remains a separate validation layer.

## Alternatives considered

- **Continue with memory-only caches and queues:** simpler, but loses replay and pending-delivery state on restart.
- **Replace JSONL with SQLite:** would weaken the existing portable authoritative-evidence contract and couple sensing to an analysis database.
- **Add Redis, a broker or SQLAlchemy:** improves some scaling options but adds services and dependencies inappropriate for this small zero-cost project.
- **Let each output implement privacy independently:** creates inconsistent failure behavior and a higher leak risk.
- **Treat offline matchers as native proof:** misleading because destination-engine parsing and runtime behavior can differ.

## Consequences

SQLite transactions provide restart persistence and local concurrency with no new runtime package. Operators must protect and bound private database files. A corrupt auxiliary database can reduce analysis or forwarding availability but must not erase JSONL. Shared publication failures stop display/download instead of degrading to partial output. The native SOC task and final recording remain incomplete until authoritative engine output and human review exist.

## Migration and rollback

All new stores are optional. Disabling their command-line/environment options returns to the previous in-memory forwarding path while JSONL continues unchanged. A migration must never point at an Oracle/live database during this branch. Rollback consists of stopping the local test process, preserving any authorized private spool if needed, removing the option and restarting the previous local configuration; no public data is generated from the private files automatically.
