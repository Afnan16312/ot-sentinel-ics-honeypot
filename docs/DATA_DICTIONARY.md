# Public event data dictionary

| Field | Description |
|---|---|
| `event_id` | Unique event identifier |
| `session_id` | Correlation identifier for one TCP session |
| `sensor_id` | Non-secret decoy identifier |
| `observed_at` | UTC ISO-8601 timestamp |
| `protocol` | `modbus`, `s7`, or `iec104` |
| `source_id` | Salted, truncated SHA-256 pseudonym |
| `source_country` | Approximate GeoIP country, not verified physical location |
| `source_asn` | Approximate autonomous-system label |
| `event_type` | Connection, request, or bounded sensor error |
| `decoded` | Allow-listed protocol metadata and optional fictional profile state |
| `techniques` | Evidence-qualified ATT&CK hypotheses with confidence and rationale |
| `severity` | Analytical priority, not proof of compromise |
| `is_demo` | `true` for synthetic portfolio data |
| `sanitized` | Indicates that publication processing was applied |

The public dashboard derives `triage_score`, `triage_priority` and public score factors from the fields above. These are deterministic analyst-priority aids, not assertions about a person's identity or intent. Private repeat and novelty evidence may inform the private collector score, but they are intentionally not displayed in public views.

Private sensor events may also contain `source_ip`, `source_network` and `raw_payload_hex`. Strict public sanitization removes all three, recursively removes credential-like keys and requires `sanitized: true`. Public datasets and public STIX bundles contain no literal address or network prefix. Remote collector transport adds authentication headers but does not add secrets to the event body.
