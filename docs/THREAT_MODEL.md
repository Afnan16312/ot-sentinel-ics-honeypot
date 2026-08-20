# Threat Model

## Scope

This threat model covers the low-interaction sensor, optional profile runtime, private JSONL storage, central collector, alert webhook, privacy pipeline and public dashboard. It does not claim to cover a real industrial process or production safety system.

## Security objectives

- Untrusted traffic cannot execute code or operate real equipment.
- A request cannot consume unbounded memory, storage or connection time.
- Public artifacts do not contain raw source IPs, payloads or credentials.
- Central collector traffic is authenticated and encrypted outside a loopback lab.
- Notifications contain only the minimum data needed for triage.
- Synthetic evidence cannot be mistaken for live observations.

## Trust boundaries

| Boundary | Untrusted input | Main controls |
|---|---|---|
| Internet to sensor | Arbitrary TCP bytes | Three explicit listeners, 4 KiB hard maximum, timeouts, no execution |
| Sensor container to Internet | Attempted new outbound connection | Dedicated edge subnet, host `DOCKER-USER` new-connection drop and boot-time fail-closed helper |
| Profile loader | Local profile document | 64 KiB limit, JSON-only YAML subset, schema allowlist, active-content key rejection |
| Sensor to raw log | Parsed and raw evidence | Bounded payload, append-only JSONL, private ignored directory |
| Sensor to collector | Signed event envelope | HTTPS requirement, per-sensor HMAC, timestamp window, replay rejection, bounded queue |
| Sensor to alert service | High-confidence event | Selective policy, deduplication, redaction, HMAC, bounded retries |
| Private to public data | Sensitive telemetry | Salted pseudonyms, raw-field deletion, automated privacy validation |

## Abuse cases and mitigations

### Resource exhaustion

An attacker opens many connections or sends oversized data. The sensor limits stream buffers, payload size and idle time. Docker drops capabilities, limits processes, CPU and memory, uses a read-only filesystem, and removes Python package installers from the finished image.

### Container outbound pivot

A parser or runtime flaw attempts to initiate an Internet connection. The Oracle deployment creates a dedicated edge bridge only for published ports, installs a host `DOCKER-USER` rule that drops new connections originating from that subnet, and refuses systemd startup when the expected firewall chain is unavailable. Established response traffic remains possible so the decoy can answer inbound sessions.

### Parser confusion

Malformed frames attempt to trigger exceptions or inconsistent mappings. Parsers return bounded error records, test fixtures cover truncation, and the sensor never passes payloads to a shell, interpreter or PLC library.

### Profile weaponization

A profile attempts to introduce a command, plugin, URL or executable hook. The loader accepts only a dependency-free JSON subset of YAML, rejects unknown top-level fields and recursively rejects active-content keys.

### Collector impersonation or replay

An unauthorised sensor submits fabricated evidence. Each sensor uses a different secret, signs the timestamp and exact body with HMAC-SHA256, and the collector rejects unknown identities, stale timestamps, invalid signatures and duplicate event IDs. TLS remains mandatory outside explicit loopback testing.

### Alert leakage and fatigue

A notification leaks source data or every scan creates an alert. The policy requires high severity plus a high-confidence ATT&CK match, removes raw source/payload material, deduplicates sessions and uses a bounded queue.

### Misleading analysis

A dashboard viewer treats a scan, score or mapped technique as proof of compromise or identity. The mapper preserves rationale and confidence, the triage score uses behavior only, and the dashboard repeatedly states that scores support review rather than attribution.

## Residual risks

- A low-interaction implementation can be fingerprinted.
- HMAC secrets must be generated, stored and rotated securely by the operator.
- JSONL storage is not a tamper-evident database.
- A public IP creates continuing patching and monitoring obligations.
- Engine-specific Sigma, Suricata and Wazuh validation must be repeated in the destination environment.
- The Oracle egress helper assumes Docker's iptables backend and must be redesigned before an nftables-backend migration.

## Deployment rule

Never place the sensor on the same network as production OT, personal devices or sensitive data. Use an isolated host or subscription, deny unnecessary outbound traffic, retain raw evidence privately and maintain a tested shutdown procedure.
