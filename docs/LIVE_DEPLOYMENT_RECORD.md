# Live Deployment Record

This document records privacy-safe operational evidence for the current study. It is not a threat-intelligence report and contains no public IP addresses, source addresses, payloads, keys or cloud identifiers.

## Deployment decision

| Item | Recorded state |
|---|---|
| Collection start | 2026-08-19 20:41 UTC |
| Sensor region | UAE East (Dubai) |
| Host | Oracle Cloud Always Free-eligible Ampere A1 shape |
| Isolation | Dedicated VCN and container networks; no production, corporate or home-network route |
| Public decoys | Modbus/TCP 502, S7/ISO-on-TCP 102, IEC-104 2404 |
| Administration | SSH key authentication restricted to the operator's current `/32` |
| Public dashboard data | Synthetic only |
| Private live evidence | Excluded from Git and public Streamlit deployment |

## Deployment verification

The following checks were completed on 2026-08-19 and 2026-08-20:

- all three public TCP ports were reachable from an authorized external test machine;
- a harmless Modbus read received the expected simulated reply;
- the sensor health state reported `ok`;
- the systemd unit was enabled and active after restart;
- the Docker container restarted and the three host ports remained published;
- new outbound connections from the container timed out as intended;
- the `DOCKER-USER` isolation rules remained present;
- log rotation was accepted and the filesystem had 41 GB free.

## First privacy-safe snapshot

From 2026-08-19 20:47 UTC through 2026-08-20 09:53 UTC, the private log contained:

| Measure | Count |
|---|---:|
| Records | 238 |
| Bounded sessions | 123 |
| Distinct observed source addresses | 34 |
| Connection records | 123 |
| Protocol request records | 110 |
| Session error records | 5 |
| Modbus-associated records | 97 |
| S7-associated records | 88 |
| IEC-104-associated records | 53 |
| Informational records | 234 |
| Medium-severity records | 4 |

These counts include authorized self-tests and automated Internet activity. A source address is not a person, organization or confirmed attacker. A connection, session, protocol request, severity label or ATT&CK hypothesis is not proof of exploitation, intent, attribution or compromise.

## Publication decision

No live record is approved for public release yet. The GitHub dataset, hosted dashboard and demonstration PDF remain synthetic. Publication requires the full collection window, pseudonymization with a private salt, automated public-data validation and manual methodology/privacy review.

## Remaining study milestones

1. Continue the authorized collection for the chosen two-to-four-week window.
2. Record daily health, storage and cost status without copying source identifiers into notes.
3. End collection and preserve the raw evidence privately.
4. Sanitize and validate a separate candidate public dataset.
5. Review ATT&CK hypotheses and distinguish scanning, protocol interaction and stronger evidence.
6. Publish a dated report only after the privacy and methodology gates pass.

See [Oracle Cloud Runbook](ORACLE_CLOUD_RUNBOOK.md), [Live Collection Runbook](LIVE_COLLECTION_RUNBOOK.md), [Ethics](ETHICS.md) and [Data Dictionary](DATA_DICTIONARY.md).
