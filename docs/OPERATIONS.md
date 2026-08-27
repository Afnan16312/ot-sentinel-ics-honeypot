# Operations Guide

This guide covers the optional state profile, health, alert and multi-sensor features. The basic local dashboard remains available through `run_dashboard.ps1`.

The verified Oracle Cloud operating procedure, including systemd, Docker networking, outbound blocking and log rotation, is in [ORACLE_CLOUD_RUNBOOK.md](ORACLE_CLOUD_RUNBOOK.md). The current privacy-safe study status is in [LIVE_DEPLOYMENT_RECORD.md](LIVE_DEPLOYMENT_RECORD.md).

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
- delivery failures,
- oldest collector-queue age and optional spool storage readiness.

The file contains operational health only. It is not an availability guarantee.

## Selective webhook alerts

Alerts are disabled by default. To enable them:

```powershell
$env:OT_ALERT_WEBHOOK = "https://alerts.example/v1/ot-sentinel"
$env:OT_ALERT_SECRET = "a-private-random-secret-of-at-least-16-characters"
.\.venv\Scripts\python.exe -m ot_sentinel.sensor
```

Only high-severity events are eligible. The alert excludes source IPs and raw payloads, is deduplicated by session and technique, is HMAC-SHA256 signed, and uses a bounded background queue. HTTPS is required except for loopback testing.

The receiver should verify the `X-OT-Sentinel-Signature` header against the exact request body before processing it.

### File-based alert configuration

For a private indexed deployment, copy and edit [`config/alerts.yaml`](../config/alerts.yaml). It intentionally uses the JSON subset of YAML so the sensor does not need a YAML parser. Keep `enabled` as `false` until the endpoint and secret are ready; do not put secrets in this file.

```powershell
$env:OT_ALERT_SECRET = "a-private-random-secret-of-at-least-16-characters"
.\.venv\Scripts\python.exe -m ot_sentinel.sensor `
  --observation-db logs\observations.sqlite3 `
  --alerts-config config\alerts.yaml
```

When enabled through this file, an event is enqueued only after its private SQLite observation has been recorded. Delivery remains asynchronous with a bounded queue: a slow, unavailable or failing webhook increments health counters but never blocks an ICS listener. The JSON sent to Slack, Discord or a SOAR endpoint contains only `observed_at`, `protocol`, `severity`, `mitre_attack_ids` and an HMAC-derived `source_hash`; it excludes raw addresses, payloads, credentials, sensor identifiers and session identifiers.

### Explainable private threat score

Each private observation stores `threat_score` (0–100), `threat_priority` and `threat_factors_json`. The factors are protocol action, strongest ATT&CK evidence confidence, repeat pseudonymous-source activity and payload-fingerprint novelty. Existing Streamlit **Triage** cards show the same explainable review model for sanitized dashboard records. If the private index is connected to an analyst-only dashboard later, display these three stored fields directly; do not copy the private database into the public Streamlit build.

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

Collector replay reservations default to a private SQLite file, so an accepted sensor/event pair remains rejected through a local collector restart until expiry. This database stores replay keys and expiry only; collector event JSONL remains the private evidence output.

### Optional local durable delivery spool

For a local controlled test, set a private ignored spool path before starting the sensor:

```powershell
$env:OT_COLLECTOR_SPOOL = "logs/collector-delivery.sqlite3"
$env:OT_COLLECTOR_SPOOL_MAX_ROWS = "5000"
$env:OT_COLLECTOR_SPOOL_MAX_BYTES = "33554432"
$env:OT_CONFIGURATION_VERSION = "local-synthetic-v1"
$env:OT_COLLECTOR_HEARTBEAT = "true"
```

The spool persists pending event JSON across restarts, rejects the newest enqueue when its row or byte bound is full and retries due rows with bounded exponential backoff. It never stores `OT_COLLECTOR_SECRET` or a request signature; both are used only when transmitting. Disable the feature by leaving `OT_COLLECTOR_SPOOL` unset. This option was tested locally and was not deployed to Oracle.

### Local health checker

Use [Local Health Monitoring Runbook](HEALTH_MONITORING_RUNBOOK.md) for synthetic/local snapshots. The checker reports warning (`1`) and critical (`2`) states without echoing event data, addresses, payloads or paths. No monitor or scheduler was installed in cloud infrastructure.

The machine-readable request and response contract is [OpenAPI 3.1](api/collector.openapi.json). The [collector threat model](COLLECTOR_THREAT_MODEL.md) explains what the controls do and do not protect. The [operational hardening guide](COLLECTOR_HARDENING.md) covers TLS termination, gateways, rate limits, supervision, rotation, monitoring, backup, migration and rollback without treating those deployment activities as already completed.

For a same-machine demonstration only, the collector accepts `--allow-insecure-loopback` while bound to `127.0.0.1`. Plain HTTP is deliberately refused for remote addresses.

## Shutdown and failure behavior

- `Ctrl+C` closes the sensor or collector cleanly.
- Alert and collector delivery never blocks protocol handling; bounded queues absorb short interruptions.
- In-memory delivery makes three bounded attempts; the optional durable spool reschedules failed rows with capped exponential backoff.
- Local JSONL remains the evidence source when a remote integration is unavailable.

## Final offline handoff

The post-collection preflight, sanitized SQLite import, persistent local Wazuh staging, reports, STIX, Navigator and manifest are documented in [Final Data Handoff Runbook](FINAL_DATA_HANDOFF.md). These commands operate only on a separately transferred local file. They do not connect to Oracle, publish automatically or replace the Streamlit demonstration dataset.

## Oracle host daily check

Run these commands only from the private SSH session:

```bash
cd /opt/ot-sentinel
sudo systemctl is-active ot-sentinel.service
sudo docker compose -f docker-compose.yml \
  -f infra/oracle/docker-compose.oracle.yml ps
sudo cat logs/health.json
df -h /
sudo du -sh logs
```

The service should be `active`, the container should be `Up`, health should be `ok`, and disk growth should remain bounded. Do not paste or publish `logs/events.jsonl`.

## Production limits

- Store HMAC secrets in a real secret manager and rotate them.
- Put a reverse proxy, rate limiter and durable queue in front of a production collector.
- Monitor disk space and ship private logs to approved storage.
- Do not expose the collector or sensor from a personal network.
- Do not place any component on the same network as production OT.
- Treat `GET /health` as process liveness only; monitor successful storage and disk state separately.
- Preserve the exact request bytes through any gateway because HMAC verification covers the exact body.
- Use the tested 64 KiB application limit even if an upstream proxy permits larger generic requests.
