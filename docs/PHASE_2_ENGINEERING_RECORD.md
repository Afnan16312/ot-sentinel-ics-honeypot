# Phase 2 Engineering Record

This record explains the local-only Phase 2 work on `feature/phase-2-enhancements`. Every fixture is synthetic. No Oracle service, network rule, port, process or private event was accessed or changed.

## Delivery matrix

| Task | What was built | Why | Verification | Limitation / intentionally not deployed |
|---|---|---|---|---|
| Persistent replay and scanner deduplication | SQLite replay reservations plus a separate HMAC-fingerprint observation index with 30-minute repeat counts | Replays must remain rejected across collector restarts while repeated scans should be counted without duplicating analysis rows | restart, expiry, concurrency, retry-release, fingerprint, repeat-count and privacy tests | Optional local/private stores only; JSONL remains authoritative; not enabled on Oracle |
| ATT&CK Navigator exporter | Deterministic Layer 4.5 `ics-attack` JSON from SQLite repeat counts | Make technique frequency inspectable in an established analyst tool | score, ordering, malformed-ID and privacy tests plus layer validator | Committed layer is synthetic; observed layers default to ignored private storage |
| Weekly intelligence brief | Reproducible seven-day Markdown generator with protocol, session, pseudonym and confidence summaries | Turn private analysis indexes into a reviewable report draft | empty, mixed-classification, ties, repeats and privacy tests | Committed report is synthetic; no observed report is published automatically |
| Native SOC lab | Disposable, loopback-only Wazuh 4.14.7 and Suricata 8.0.4 harness, deterministic PCAP and positive/negative injectors | Provide an authoritative destination-engine path rather than relying only on static checks | native `wazuh-logtest`, `suricata -T`, deterministic PCAP verification and harness tests | Pinned local versions only; never deployed to Oracle and must be re-run after content/engine changes |
| Shared publication gate | One package validator used by scripts, Streamlit and public STIX; recursive credential removal; 32-character salt minimum; 512-byte sensor ceiling | Prevent privacy behavior from drifting between publication paths | end-to-end raw-address, prefix, payload, nested-credential, unsafe-ID, mixed-provenance and STIX tests | Not connected to Oracle or observed telemetry |
| Local health checker | Privacy-safe JSON/text readiness checker with warning and critical exit codes | Make stale process, event, disk, queue, delivery and storage conditions machine visible | healthy, stale, low-disk, queue-drop, process and storage-failure tests | Local command only; no cloud monitor or scheduler was installed |
| Detection Preview | Streamlit panel predicting Sigma, Wazuh and Suricata matches using the existing fixture matchers | Explain why a sanitized event would match defender content | positive cross-engine and negative connection/read tests | Explicitly offline prediction; not native-engine proof |
| Durable delivery spool | Optional bounded SQLite queue with restart persistence, retry backoff and health metrics | Prevent temporary collector outages or sensor restarts from losing pending delivery | restart, retry, corruption, bounds, drain, metadata, secret-exclusion and JSONL-preservation tests | Optional and disabled by default; not deployed to the live sensor |
| OpenAPI assurance | Pinned development-only OpenAPI 3.1 validator and CI command | JSON parsing cannot prove standards compliance | external validator plus semantic collector contract tests | Adds no sensor runtime dependency |
| Walkthrough deliverable | Exact 6:15 synthetic-only storyboard and frame-by-frame privacy review | Make the remaining human recording reproducible and safe | checklist content test | The actual reviewed video and public URL remain human actions |

## Cross-cutting security invariants

- The framework-free sensor and collector keep an empty runtime dependency list.
- `POST /v1/events` and `GET /health` remain compatible.
- Received sensor payloads cannot be configured above 512 bytes.
- Raw JSONL remains private authoritative evidence even when indexing or forwarding fails.
- SQLite replay, observation and spool files are private and ignored by Git.
- Transport signatures are created only when a request is transmitted; secrets are never written to the spool.
- Public records and STIX contain no raw address, network prefix, raw payload or credential-like field.
- ATT&CK relationships and Detection Preview results are hypotheses, not proof of exploitation, intent or compromise.

## Deferred evidence

Native Wazuh and Suricata validation is complete and recorded in [the SOC evidence](../tests/soc/NATIVE_VALIDATION.md). The final video still needs the reviewed native results plus a green feature-branch GitHub Actions run. That human recording requirement does not authorize a cloud deployment or publication of private telemetry.

## Local verification on 2026-08-25

- Complete pytest suite: **151 passed, 10 subtests passed**.
- Ruff: passed.
- `pip check`: no broken requirements.
- `pip-audit`: no known vulnerabilities.
- Public-data validator: 420 synthetic records passed.
- Detection pack: 4 Sigma, 4 Wazuh alert and 4 Suricata rules; 10 fixtures including 3 all-negative cases passed offline validation.
- External OpenAPI 3.1 validator: passed.
- STIX 2.1 validator and independent public-STIX privacy gate: passed.
- Navigator Layer 4.5 validator: passed; the layer and weekly report reproduced byte-for-byte.
- Streamlit: local health endpoint returned 200 and AppTest completed with no application exceptions.
- Git diff and staged privacy/key/cloud-identifier scans: passed.
- Native Wazuh/Suricata: **passed**. Wazuh rule `110001` fired only for the synthetic write; Suricata loaded 4/4 rules and produced one SID `4200501` write alert with zero harmless-read alerts.
