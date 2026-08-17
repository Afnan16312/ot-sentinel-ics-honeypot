# Operations Guide

This guide covers the optional state profile, health, alert and multi-sensor features. The basic local dashboard remains available through `run_dashboard.ps1`.

## Safe stateful profiles

Three fictional profiles are included:

| Profile | Sector | Purpose |
|---|---|---|
| `profiles/water-treatment.yaml` | Water | Simulated treatment measurements and writable training setpoints |
| `profiles/power-substation.yaml` | Power | Simulated distribution measurements and control registers |
| `profiles/port-crane.yaml` | Ports | Simulated crane measurements and training command registers |

The documents use the JSON subset of YAML 1.2. This keeps the sensor dependency-free and prevents unsafe YAML constructors. The loader requires `fictional: true`, rejects unknown top-level fields, caps the document at 64 KiB and rejects command, shell, script, plugin, URL and hook fields.

Start a local sensor with a profile:

```powershell
.\.venv\Scripts\python.exe -m ot_sentinel.sensor `
  --host 127.0.0.1 `
  --profile profiles\water-treatment.yaml `
  --health-file logs\health.json
```

Modbus writes affect only the runtime's in-memory registers. They cannot reach a PLC and disappear when the process restarts. Writable address ranges are explicit. Attempts outside those ranges are logged but not applied.

## Health snapshot

Set `OT_HEALTH_PATH=logs/health.json` or pass `--health-file`. After each event the sensor atomically records:

- start time and last-event time,
- total and per-protocol event counts,
- event-type counts,
- alert and collector queue depth/drop counters,
- delivery failures.

The file contains operational health only. It is not an availability guarantee.

## Selective webhook alerts

Alerts are disabled by default. To enable them:

```powershell
$env:OT_ALERT_WEBHOOK = "https://alerts.example/v1/ot-sentinel"
$env:OT_ALERT_SECRET = "a-private-random-secret-of-at-least-16-characters"
.\.venv\Scripts\python.exe -m ot_sentinel.sensor
```

Only events with both high severity and a high-confidence ATT&CK match are eligible. The alert excludes source IPs and raw payloads, is deduplicated by session and technique, is HMAC-SHA256 signed, and uses a bounded background queue. HTTPS is required except for loopback testing.

The receiver should verify the `X-OT-Sentinel-Signature` header against the exact request body before processing it.

## Central multi-sensor collector

The collector is a small authenticated ingestion foundation, not a replacement for a production message broker.

1. Copy `config/collector_sensors.example.json` to a private location outside Git.
2. Give every sensor a different random secret of at least 16 characters.
3. Obtain a TLS certificate for the collector endpoint.
4. Start the collector:

```powershell
.\.venv\Scripts\python.exe -m ot_sentinel.collector `
  --host 0.0.0.0 `
  --port 9443 `
  --credentials C:\private\collector-sensors.json `
  --output logs\collector-events.jsonl `
  --tls-cert C:\private\collector.crt `
  --tls-key C:\private\collector.key
```

5. Configure a sensor:

```powershell
$env:OT_COLLECTOR_URL = "https://collector.example:9443/v1/events"
$env:OT_COLLECTOR_SECRET = "the-secret-for-this-sensor-only"
$env:OT_SENSOR_ID = "remote-sensor-02"
.\.venv\Scripts\python.exe -m ot_sentinel.sensor
```

The transport signs the timestamp and exact JSON body. The collector rejects unknown sensors, invalid signatures, stale timestamps, oversized requests, identity mismatches and duplicate event IDs. It writes `transport_authenticated: true` only after those checks pass.

For a same-machine demonstration only, the collector accepts `--allow-insecure-loopback` while bound to `127.0.0.1`. Plain HTTP is deliberately refused for remote addresses.

## Shutdown and failure behavior

- `Ctrl+C` closes the sensor or collector cleanly.
- Alert and collector delivery never blocks protocol handling; bounded queues absorb short interruptions.
- After three failed deliveries the health counter increases and the sensor continues locally.
- Local JSONL remains the evidence source when a remote integration is unavailable.

## Production limits

- Store HMAC secrets in a real secret manager and rotate them.
- Put a reverse proxy, rate limiter and durable queue in front of a production collector.
- Monitor disk space and ship private logs to approved storage.
- Do not expose the collector or sensor from a personal network.
- Do not place any component on the same network as production OT.
