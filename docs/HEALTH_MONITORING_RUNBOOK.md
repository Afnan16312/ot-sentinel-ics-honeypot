# Local Health Monitoring Runbook

This checker is for local development and synthetic test snapshots. It is not installed on the Oracle sensor and does not read live telemetry.

## What it checks

`scripts/check_health.py` evaluates process status, health-snapshot freshness, last-event freshness when traffic is expected, free disk space, queue drops, delivery failures and collector-storage writability. Its output contains only check names, severity and generic remediation messages—never event rows, addresses, payloads or paths.

Exit codes are stable for automation:

- `0`: all configured checks passed;
- `1`: warning, such as stale expected traffic, queue drops, a delivery failure or low disk;
- `2`: critical, such as a stopped process, stale health snapshot, critically low disk or unwritable collector storage.

## Local usage

Run a human-readable check:

```powershell
python scripts/check_health.py tests/fixtures/local-health.json --expect-traffic
```

Use JSON for a local scheduled test or CI fixture:

```powershell
python scripts/check_health.py tests/fixtures/local-health.json --json
```

If a local collector output directory exists, add `--collector-storage <local-directory>`. If a local PID is supervised separately, add `--pid <local-pid>`. Omitting either check is reported honestly; the checker does not discover or contact remote hosts.

## Response

For a warning, inspect local queue and delivery counters and confirm whether traffic was expected. For a critical state, keep public publication disabled, verify local process and disk state, and confirm storage writability before resuming synthetic tests. Do not copy private logs into tickets or chat messages.

## Boundaries

This task intentionally does not install a service, scheduler, monitoring agent, webhook or cloud alert. Any future production monitoring design requires separate approval, redaction review and deployment testing.
