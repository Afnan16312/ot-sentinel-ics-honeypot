# Final Handoff Engineering Record

Branch: `feature/final-data-handoff-readiness`

This record documents the final offline data-processing and SOC-ingestion preparation. Only committed synthetic fixtures were used. No Oracle service, telemetry, configuration, network rule, port or cloud resource was accessed or changed.

## Features shipped

| Feature | Implementation | Why it shipped | Evidence |
|---|---|---|---|
| Privacy-safe historical preflight | `handoff.py`, `preflight_events.py` | Stop damaged, mixed or unexpected JSONL before analysis without displaying values | schema, malformed, incomplete, size, timestamp, duplicate and safe-error tests |
| Transactional sanitized import | `SQLiteObservationStore.import_sanitized`, `import_observations.py` | Make historical analysis idempotent, private and restart-safe | whole-batch rollback, repeated import and cross-file event-ID conflict tests |
| Persistent Wazuh staging | `wazuh_ingest.py`, fixed localfile mount, staging ledger | Turn validated JSONL into stored/indexed native alerts without connecting Wazuh to Oracle | native manager/indexer verification and post-restart check |
| Final processor | `finalize.py`, `finalize_collection.py` | Put integrity, privacy, analysis and candidate stages in one fail-closed order | dry-run, private-only, explicit-candidate and repeated checksum verification tests |
| Processing manifest | private `processing-manifest.json` | Make input/output lineage and approval status machine-readable | manifest privacy, relative-path and checksum tests |
| Operator documentation | final runbook, ADR, SOC/publication/operations updates | Make the workflow understandable and repeatable in PowerShell | documentation links, traceability and harness tests |

## Problems solved

| Problem | Solution | Residual boundary |
|---|---|---|
| A partially transferred final line could be accepted by ordinary JSONL readers. | Preflight requires newline completion and validates every bounded record. | The operator must still verify the transfer checksum against the original. |
| Re-running a historical import could inflate counts. | A unique event-ID/content digest ledger skips identical records and rejects conflicts inside one SQLite transaction. | Intentional schema/event-ID changes need a new reviewed input. |
| A Wazuh file append could be interrupted or repeated. | A two-phase private SQLite staging ledger records offsets, repairs a partial append and blocks later datasets behind unresolved work. | The staging directory and local Wazuh volumes remain private operator state. |
| `wazuh-logtest` did not prove dashboard-searchable persistence. | Wazuh logcollector reads a validated mounted file; verification checks manager storage and indexer search. | Evidence applies to pinned Wazuh 4.14.7 and must be repeated after upgrades. |
| Different commands could accidentally publish or overwrite artifacts. | Digest-named private runs, atomic output writes, output collision rejection and an explicit candidate flag keep publication separate. | Contextual, legal and small-count review remains human. |
| Suricata could be incorrectly described as a JSONL consumer. | Documentation keeps Suricata packet/PCAP validation separate from Wazuh JSON ingestion. | Historical packet analysis requires an authorized PCAP source that this study does not collect. |
| Repeated Suricata validation counted prior EVE alerts. | The PCAP generator archives the previous ignored EVE file before each run without deleting evidence. | Archives remain local, ignored operator state. |

## Security and privacy properties

- Original evidence is read-only input and is never overwritten or deleted.
- Preflight errors contain record numbers and codes, not field values.
- Sanitized imports reject raw addresses, payloads, credential-like keys, tokens and mixed provenance.
- Private secrets are environment-only and are not stored in SQLite or manifests.
- In-repository output paths must be ignored by Git.
- The analysis database stores salted source IDs and decoded evidence, not raw addresses or payload bytes.
- Wazuh input is validated sanitized JSONL and all host ports remain on loopback.
- Public candidate creation requires an explicit flag; manifests always record publication as false.
- Streamlit demonstration data is never replaced automatically.
- No automatic GitHub upload, Oracle connection or cloud deployment exists in the workflow.

## Verification on 2026-08-25

- Complete pytest suite: **175 passed, 10 subtests passed**.
- Ruff: **passed**.
- Public-data validator: **420 sanitized synthetic events passed**.
- Detection validation: **4 Sigma, 4 Suricata and 4 Wazuh alert rules; 10 fixtures including 3 all-negative passed**.
- OpenAPI 3.1 validator: **passed**.
- Targeted STIX, Navigator, OpenAPI and supply-chain verification: **18 passed, 2 subtests passed**.
- `pip check`: **no broken requirements**.
- `pip-audit` after updating the ignored virtual-environment `pip` to 26.2.1: **no known vulnerabilities**; the local project itself is correctly reported as not published on PyPI.
- Synthetic final processor: **420 events completed across sanitized JSONL, SQLite, Wazuh JSONL, report, Navigator, aggregate summary, public-profile STIX and manifest**.
- Repeated final processor: **all existing output checksums verified; no duplicate import**.
- Native Wazuh rule test: **rule 110001 fired only for the synthetic write**.
- Native Wazuh historical ingestion: **write stored and indexed; connection/read custom alerts remained quiet; result survived manager restart**.
- Native Suricata 8.0.4: **4/4 rules loaded; one SID 4200501 write alert; zero harmless-read alerts**.

## Human work that intentionally remains

1. Decide the authorized collection end time.
2. Stop and retire cloud resources under the live runbook.
3. Make and verify the encrypted evidence backup.
4. Transfer the private JSONL to the approved offline system.
5. Run the prepared commands using private environment secrets.
6. Review Wazuh findings, report wording, STIX, Navigator and aggregate disclosure risk.
7. Approve or reject publication separately.
8. Record, review and upload the project walkthrough if desired.

None of these remaining human decisions are silently treated as completed by the software.
