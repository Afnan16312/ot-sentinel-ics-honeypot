# Public event data dictionary

| Field | Description |
|---|---|
| `event_id` | Unique event identifier |
| `session_id` | Correlation identifier for one TCP session |
| `sensor_id` | Non-secret decoy identifier |
| `observed_at` | UTC ISO-8601 timestamp |
| `protocol` | `modbus`, `s7`, or `iec104` |
| `source_id` | Salted, truncated SHA-256 pseudonym |
| `source_network` | Coarse source prefix; may be removed in stricter releases |
| `source_country` | Approximate GeoIP country, not verified physical location |
| `source_asn` | Approximate autonomous-system label |
| `event_type` | Connection, request, or bounded sensor error |
| `decoded` | Allow-listed protocol metadata |
| `techniques` | Evidence-qualified ATT&CK hypotheses with confidence and rationale |
| `severity` | Analytical priority, not proof of compromise |
| `is_demo` | `true` for synthetic portfolio data |
| `sanitized` | Indicates that publication processing was applied |

Public datasets never include `source_ip` or `raw_payload_hex`.

