# Monitoring Plan

This is a design for future monitoring. It does not alter the live Oracle instance.

## Signals to monitor

| Signal | Healthy condition | Action when unhealthy |
|---|---|---|
| Sensor service | Process and container remain running | Investigate logs; use the documented rollback before restart |
| Health snapshot | `status` is `ok` and timestamp advances after events | Check listener, storage and queue counters |
| Disk capacity | Free space remains comfortably above the retention requirement | Rotate/archive private logs; never delete evidence blindly |
| Delivery failures | Counter remains stable when a collector is configured | Keep local JSONL authoritative and repair forwarding separately |
| Queue drops | Zero during normal operation | Reduce load or increase reviewed capacity limits |
| Certificate expiry | Rotation completes before expiry | Replace through a tested overlapping-certificate procedure |
| Public-data validation | All release gates pass | Stop publication and review the candidate manually |

## Alerting principles

- Operational alerts must contain health metadata only, not raw telemetry.
- A traffic spike is an investigation signal, not proof of an attack.
- Liveness and readiness are separate: a running process may still be unable to store events.
- Monitoring must not introduce a new public administrative endpoint on the sensor.
- Every automated recovery action requires a tested rollback and evidence-preservation rule.

The current daily manual checks remain documented in [Operations](OPERATIONS.md). Automated monitoring should first be tested against a disposable clone, not the active research sensor.
